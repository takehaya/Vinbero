package main

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"go.uber.org/zap"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/config"
	"github.com/takehaya/vinbero/pkg/locator"
	"github.com/takehaya/vinbero/pkg/netresource"
	"github.com/takehaya/vinbero/pkg/server"
)

// locatorNode is the part of a daemon a locator lives in, booted the way run
// does: decode the saved locators, restore the SID reservations, register
// the config's locators (with BGP), then the saved ones.
type locatorNode struct {
	res *netresource.ResourceManager
	mgr *locator.Manager
	srv *server.LocatorServer
}

type locatorBoot struct {
	configLocators []config.LocatorConfig
	bgp            bool
	reservations   []locator.SIDReservation
}

func bootLocators(path string, b locatorBoot) (*locatorNode, error) {
	res, err := netresource.NewResourceManager(path, zap.NewNop())
	if err != nil {
		return nil, err
	}
	saved, err := savedLocators(res)
	if err != nil {
		return nil, err
	}
	mgr := locator.NewManager()
	if err := mgr.RestoreSIDReservations(b.reservations); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(b.configLocators))
	for _, lc := range b.configLocators {
		names = append(names, lc.Name)
		if !b.bgp {
			continue
		}
		loc, err := configToLocator(lc)
		if err != nil {
			return nil, err
		}
		if err := mgr.Add(loc); err != nil {
			return nil, err
		}
	}
	if err := restoreLocators(mgr, saved, names, res, zap.NewNop()); err != nil {
		return nil, err
	}
	sids := server.NewSidFunctionServer(nil, nil, mgr, nil)
	sids.SetLocatorStore(locatorStateStore{res: res, configNames: names})
	return &locatorNode{res: res, mgr: mgr, srv: server.NewLocatorServer(mgr, sids.AddLocatorAndClaim, sids.DeleteLocatorGuarded)}, nil
}

func mustBootLocators(t *testing.T, path string, b locatorBoot) *locatorNode {
	t.Helper()
	n, err := bootLocators(path, b)
	if err != nil {
		t.Fatalf("boot: %v", err)
	}
	return n
}

func classicLocator(name, prefix string) *v1.Locator {
	return &v1.Locator{Name: name, Prefix: prefix, BlockLen: 32, NodeLen: 16, FunctionLen: 16, ArgumentLen: 64,
		Behavior: v1.LocatorBehaviorMode_LOCATOR_BEHAVIOR_MODE_CLASSIC, FunctionAutoStart: 1, FunctionAutoEnd: 0xffff}
}

// create returns the per-locator error, "" on success.
func (n *locatorNode) create(t *testing.T, l *v1.Locator) string {
	t.Helper()
	resp, err := n.srv.LocatorCreate(context.Background(), connect.NewRequest(&v1.LocatorCreateRequest{Locators: []*v1.Locator{l}}))
	if err != nil {
		t.Fatal(err)
	}
	if errs := resp.Msg.GetErrors(); len(errs) > 0 {
		return errs[0].GetReason()
	}
	return ""
}

func (n *locatorNode) delete(t *testing.T, name string, force bool) string {
	t.Helper()
	resp, err := n.srv.LocatorDelete(context.Background(), connect.NewRequest(&v1.LocatorDeleteRequest{Names: []string{name}, Force: force}))
	if err != nil {
		t.Fatal(err)
	}
	if errs := resp.Msg.GetErrors(); len(errs) > 0 {
		return errs[0].GetReason()
	}
	return ""
}

func (n *locatorNode) names() []string {
	var out []string
	for _, l := range n.mgr.List() {
		out = append(out, l.Name)
	}
	sort.Strings(out)
	return out
}

func sameNames(got []string, want ...string) bool {
	return strings.Join(got, ",") == strings.Join(want, ",")
}

// A locator made over the API comes back after a restart as it was
// registered, with or without BGP; one deleted over the API does not.
func TestLocatorRestart_RoundTripAndDelete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	n := mustBootLocators(t, path, locatorBoot{bgp: true})
	if reason := n.create(t, classicLocator("LOC1", "fd00:200::1/48")); reason != "" {
		t.Fatal(reason)
	}
	usid := &v1.Locator{Name: "U1", Prefix: "fc00:0:2::/48", BlockLen: 32, NodeLen: 16, FunctionLen: 16,
		Behavior: v1.LocatorBehaviorMode_LOCATOR_BEHAVIOR_MODE_USID, FunctionAutoStart: 0xe000, FunctionAutoEnd: 0xefff}
	if reason := n.create(t, usid); reason != "" {
		t.Fatal(reason)
	}
	for _, bgp := range []bool{false, true} {
		n2 := mustBootLocators(t, path, locatorBoot{bgp: bgp})
		got, ok := n2.mgr.Get("LOC1")
		if !ok || got.Prefix.String() != "fd00:200::/48" || got.ArgumentLen != 64 || got.FunctionAutoEnd != 0xffff || got.Behavior != locator.BehaviorClassic {
			t.Errorf("bgp=%v: LOC1 after restart = %+v (found %v)", bgp, got, ok)
		}
		u, ok := n2.mgr.Get("U1")
		if !ok || u.Behavior != locator.BehaviorUSID || u.FunctionAutoStart != 0xe000 {
			t.Errorf("bgp=%v: U1 after restart = %+v (found %v)", bgp, u, ok)
		}
		// A binding naming it can mint its service SIDs from the start.
		if _, _, err := n2.mgr.AllocateSID("LOC1", nil); err != nil {
			t.Errorf("bgp=%v: allocate from the restored locator: %v", bgp, err)
		}
	}
	if recs := n.res.RuntimeLocators(); len(recs) != 2 || recs[0].Name != "LOC1" || recs[1].Name != "U1" {
		t.Errorf("records not in registration order: %+v", recs)
	}

	if reason := n.delete(t, "LOC1", false); reason != "" {
		t.Fatal(reason)
	}
	n3 := mustBootLocators(t, path, locatorBoot{bgp: true})
	if !sameNames(n3.names(), "U1") {
		t.Errorf("after delete and restart: %v", n3.names())
	}
	if reason := n3.delete(t, "U1", true); reason != "" {
		t.Fatal(reason)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "runtime_locators") {
		t.Errorf("the last delete left the field: %s", data)
	}
}

// The config wins: a saved locator with the name of one in bgp.locators, or
// the prefix of one the config registered, is not restored and leaves the
// file. A locator of a config name made over the API is never saved, even
// with BGP off, where the config's locators are not registered.
func TestLocatorRestart_ConfigWins(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	n := mustBootLocators(t, path, locatorBoot{bgp: true})
	for _, l := range []*v1.Locator{
		classicLocator("SAME", "fd00:1::/48"),
		classicLocator("OTHER", "fd00:2::/48"),
		classicLocator("KEEP", "fd00:3::/48"),
	} {
		if reason := n.create(t, l); reason != "" {
			t.Fatal(reason)
		}
	}
	cfg := []config.LocatorConfig{
		{Name: "SAME", Prefix: "fd00:9::/48", BlockLen: 32, NodeLen: 16, FunctionLen: 16, ArgumentLen: 64},
		{Name: "CFG2", Prefix: "fd00:2::/48", BlockLen: 32, NodeLen: 16, FunctionLen: 16, ArgumentLen: 64},
	}
	n2 := mustBootLocators(t, path, locatorBoot{configLocators: cfg, bgp: true})
	if !sameNames(n2.names(), "CFG2", "KEEP", "SAME") {
		t.Fatalf("locators = %v", n2.names())
	}
	if got, _ := n2.mgr.Get("SAME"); got.Prefix.String() != "fd00:9::/48" {
		t.Errorf("SAME is not the config's: %+v", got)
	}
	if recs := n2.res.RuntimeLocators(); len(recs) != 1 || recs[0].Name != "KEEP" {
		t.Errorf("records after the config won = %+v", recs)
	}
	// The dropped ones do not come back once the config no longer has them.
	n3 := mustBootLocators(t, path, locatorBoot{bgp: true})
	if !sameNames(n3.names(), "KEEP") {
		t.Errorf("after the config dropped them: %v", n3.names())
	}

	// BGP off: the config's names are still the config's.
	n4 := mustBootLocators(t, path, locatorBoot{configLocators: cfg, bgp: false})
	if reason := n4.create(t, classicLocator("SAME", "fd00:8::/48")); reason != "" {
		t.Fatal(reason)
	}
	if recs := n4.res.RuntimeLocators(); len(recs) != 1 {
		t.Errorf("a locator of a config name was saved: %+v", recs)
	}
	if reason := n4.delete(t, "SAME", false); reason != "" {
		t.Fatal(reason)
	}
}

// A create or a delete whose save fails changes nothing, and the same call
// made again succeeds and is written.
func TestLocatorRestart_SaveFailureThenRetry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	n := mustBootLocators(t, path, locatorBoot{bgp: true})
	if reason := n.create(t, classicLocator("LOC1", "fd00:1::/48")); reason != "" {
		t.Fatal(reason)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0755); err != nil {
		t.Fatal(err)
	}
	if reason := n.create(t, classicLocator("LOC2", "fd00:2::/48")); !strings.Contains(reason, "not created") {
		t.Errorf("create with a failed save: %q", reason)
	}
	if _, ok := n.mgr.Get("LOC2"); ok {
		t.Error("the locator whose save failed is registered")
	}
	if reason := n.delete(t, "LOC1", true); !strings.Contains(reason, "not deleted") {
		t.Errorf("delete with a failed save: %q", reason)
	}
	if _, ok := n.mgr.Get("LOC1"); !ok {
		t.Error("the locator whose delete failed to save is gone")
	}
	if recs := n.res.RuntimeLocators(); len(recs) != 1 || recs[0].Name != "LOC1" {
		t.Errorf("record after failed saves = %+v", recs)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	// The failed create is not on disk: a restart now has no file at all.
	if n0 := mustBootLocators(t, path, locatorBoot{}); len(n0.names()) != 0 {
		t.Errorf("a restart after the failed calls has %v", n0.names())
	}
	if reason := n.create(t, classicLocator("LOC2", "fd00:2::/48")); reason != "" {
		t.Fatal(reason)
	}
	n2 := mustBootLocators(t, path, locatorBoot{})
	if !sameNames(n2.names(), "LOC1", "LOC2") {
		t.Errorf("after the retry and a restart: %v", n2.names())
	}
}

// A function a plugin holds in a restored locator is not handed out again:
// the reservations are restored before the locator is registered.
func TestLocatorRestart_KeepsStoredReservations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	n := mustBootLocators(t, path, locatorBoot{})
	l := classicLocator("LOC1", "fd00:1::/48")
	l.FunctionAutoStart, l.FunctionAutoEnd = 5, 6
	if reason := n.create(t, l); reason != "" {
		t.Fatal(reason)
	}
	loc, _ := n.mgr.Get("LOC1")
	n2 := mustBootLocators(t, path, locatorBoot{reservations: []locator.SIDReservation{{Key: "plugin/a", Locator: loc, Function: 5}}})
	sid, _, err := n2.mgr.AllocateSID("LOC1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if fn, _, _ := loc.ParseSID(sid); fn != 6 {
		t.Errorf("auto allocation took function %d, want 6 (5 is reserved)", fn)
	}
}

// A saved locator that does not decode, or a second one of a name or a
// prefix, stops the start.
func TestSavedLocators_RefusesBadRecords(t *testing.T) {
	good := netresource.ManagedLocator{Name: "L", Prefix: "fd00:1::/48", BlockLen: 32, NodeLen: 16, FunctionLen: 16, ArgumentLen: 64, Behavior: "classic"}
	bad := func(f func(*netresource.ManagedLocator)) netresource.ManagedLocator {
		r := good
		f(&r)
		return r
	}
	for _, recs := range [][]netresource.ManagedLocator{
		{bad(func(r *netresource.ManagedLocator) { r.Name = "" })},
		{bad(func(r *netresource.ManagedLocator) { r.Prefix = "nope" })},
		{bad(func(r *netresource.ManagedLocator) { r.Behavior = "" })},
		{bad(func(r *netresource.ManagedLocator) { r.ArgumentLen = 0 })},
		{good, bad(func(r *netresource.ManagedLocator) { r.Prefix = "fd00:2::/48" })},
		{good, bad(func(r *netresource.ManagedLocator) { r.Name = "M" })},
	} {
		path := filepath.Join(t.TempDir(), "state.json")
		res, err := netresource.NewResourceManager(path, zap.NewNop())
		if err != nil {
			t.Fatal(err)
		}
		if err := res.SaveRuntimeLocators(recs); err != nil {
			t.Fatal(err)
		}
		if _, err := bootLocators(path, locatorBoot{}); err == nil {
			t.Errorf("%+v: booted", recs)
		}
	}
	// A layout another reservation of the name disagrees with stops it too.
	path := filepath.Join(t.TempDir(), "state.json")
	n := mustBootLocators(t, path, locatorBoot{})
	if reason := n.create(t, classicLocator("LOC1", "fd00:1::/48")); reason != "" {
		t.Fatal(reason)
	}
	other := locator.Locator{Name: "LOC1", Prefix: n.mgr.List()[0].Prefix, BlockLen: 32, NodeLen: 16, FunctionLen: 24, ArgumentLen: 56, Behavior: locator.BehaviorClassic}
	if _, err := bootLocators(path, locatorBoot{reservations: []locator.SIDReservation{{Key: "plugin/a", Locator: other, Function: 5}}}); err == nil {
		t.Error("booted with a locator its SID reservation disagrees with")
	}
}
