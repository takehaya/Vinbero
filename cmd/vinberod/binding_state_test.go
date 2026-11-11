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
	"google.golang.org/protobuf/proto"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/config"
	"github.com/takehaya/vinbero/pkg/netresource"
	"github.com/takehaya/vinbero/pkg/server"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

// bindingNode is the part of a daemon a binding lives in, booted from a state
// file the way run does: decode the saved bindings, restore the VRFs, restore
// the bindings, then bind the config's.
type bindingNode struct {
	res *netresource.ResourceManager
	mgr *vrfbgp.Manager
	srv *server.VrfBgpServer
}

func bootBindings(path string, cfg config.VRFsConfig, configBindings []string) (*bindingNode, error) {
	res, err := netresource.NewResourceManager(path, zap.NewNop())
	if err != nil {
		return nil, err
	}
	saved, err := savedBindings(res)
	if err != nil {
		return nil, err
	}
	mgr := vrfbgp.NewManager()
	if err := restoreVRFs(cfg, configBindings, true, mgr.VRF(), &recordingProg{}, nil, res, zap.NewNop()); err != nil {
		return nil, err
	}
	if err := restoreBindings(mgr, saved, configBindings, bindingStateStore{res: res}, zap.NewNop()); err != nil {
		return nil, err
	}
	for _, name := range configBindings {
		if err := mgr.Bind(vrfbgp.Binding{VRFName: name, RD: "65535:" + name}); err != nil {
			return nil, err
		}
	}
	return &bindingNode{res: res, mgr: mgr, srv: server.NewVrfBgpServer(mgr, nil, nil, nil, nil, nil)}, nil
}

func mustBoot(t *testing.T, path string, configBindings ...string) *bindingNode {
	t.Helper()
	n, err := bootBindings(path, config.VRFsConfig{}, configBindings)
	if err != nil {
		t.Fatalf("boot: %v", err)
	}
	return n
}

func (n *bindingNode) list(t *testing.T) []*v1.VrfBgpBinding {
	t.Helper()
	resp, err := n.srv.VrfBgpList(context.Background(), connect.NewRequest(&v1.VrfBgpListRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	out := resp.Msg.GetBindings()
	sort.Slice(out, func(i, j int) bool { return out[i].GetVrfName() < out[j].GetVrfName() })
	return out
}

func (n *bindingNode) bind(t *testing.T, b *v1.VrfBgpBinding) {
	t.Helper()
	resp, err := n.srv.VrfBgpBind(context.Background(), connect.NewRequest(&v1.VrfBgpBindRequest{Bindings: []*v1.VrfBgpBinding{b}}))
	if err != nil {
		t.Fatal(err)
	}
	if errs := resp.Msg.GetErrors(); len(errs) > 0 {
		t.Fatalf("bind %s: %s", b.GetVrfName(), errs[0].GetReason())
	}
}

func (n *bindingNode) unbind(t *testing.T, name string) *v1.VrfBgpUnbindResponse {
	t.Helper()
	resp, err := n.srv.VrfBgpUnbind(context.Background(), connect.NewRequest(&v1.VrfBgpUnbindRequest{VrfNames: []string{name}}))
	if err != nil {
		t.Fatal(err)
	}
	return resp.Msg
}

func requireSameBindings(t *testing.T, got, want []*v1.VrfBgpBinding) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%d bindings, want %d:\n got %v\nwant %v", len(got), len(want), got, want)
	}
	for i := range want {
		if !proto.Equal(got[i], want[i]) {
			t.Errorf("binding %s after the restart:\n got %v\nwant %v", want[i].GetVrfName(), got[i], want[i])
		}
	}
}

func boundNames(n *bindingNode) []string {
	var out []string
	for _, b := range n.mgr.List() {
		out = append(out, b.VRFName)
	}
	sort.Strings(out)
	return out
}

// Bindings made and edited over the API come back after a restart exactly
// as VrfBgpList showed them: legacy lists in their order, family-scoped
// L3 and EVPN policies, a family without route targets, an emptied family
// map, the MUP prefix and the advertise fields.
func TestBindingRestart_ComesBackAsItWas(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.json")
	n := mustBoot(t, path)
	n.bind(t, &v1.VrfBgpBinding{VrfName: "legacy", Rd: "65000:1", ImportRts: []string{"65000:1"}, ExportRts: []string{"65000:2", "65000:1"}})
	n.bind(t, &v1.VrfBgpBinding{
		VrfName: "l3", Rd: "65000:10", DefaultLocator: "LOC1", Redistribute: []string{"static", "connected"}, MaxPrefixes: 50,
		Families: map[string]*v1.VrfBgpFamily{
			"vpnv4": {RouteTargets: []*v1.VrfBgpRouteTarget{{Rt: "65000:10", Direction: "both"}, {Rt: "65000:11", Direction: "import"}}},
			"vpnv6": {RouteTargets: []*v1.VrfBgpRouteTarget{{Rt: "65000:12", Direction: "export"}}},
		},
	})
	n.bind(t, &v1.VrfBgpBinding{
		VrfName: "l2", Rd: "65000:20", DefaultLocator: "LOC1",
		Families: map[string]*v1.VrfBgpFamily{"evpn": {RouteTargets: []*v1.VrfBgpRouteTarget{{Rt: "65000:20", Direction: "both"}}}},
	})
	n.bind(t, &v1.VrfBgpBinding{
		VrfName: "mup", Rd: "65000:30", MupGtp4SourcePrefix: "2001:db8:1::/64",
		Families: map[string]*v1.VrfBgpFamily{"mup_ipv4": {RouteTargets: []*v1.VrfBgpRouteTarget{{Rt: "65000:30", Direction: "import"}}}},
	})
	n.bind(t, &v1.VrfBgpBinding{VrfName: "emptied", Rd: "65000:40", Families: map[string]*v1.VrfBgpFamily{"vpnv4": {}}})
	if _, err := n.srv.AddFamily(ctx, connect.NewRequest(&v1.AddFamilyRequest{VrfName: "l2", Family: "vpnv4"})); err != nil {
		t.Fatal(err)
	}
	if _, err := n.srv.RemoveFamily(ctx, connect.NewRequest(&v1.RemoveFamilyRequest{VrfName: "emptied", Family: "vpnv4"})); err != nil {
		t.Fatal(err)
	}
	before := n.list(t)
	ids := map[string]uint32{}
	for _, b := range n.mgr.List() {
		id, _ := n.mgr.VRF().IDForName(b.VRFName)
		ids[b.VRFName] = id
	}

	n2 := mustBoot(t, path)
	requireSameBindings(t, n2.list(t), before)
	for _, b := range n.mgr.List() {
		got, _ := n2.mgr.Get(b.VRFName)
		if b.Families == nil && got.Families != nil || b.Families != nil && got.Families == nil {
			t.Errorf("%s: families nil=%v before, nil=%v after", b.VRFName, b.Families == nil, got.Families == nil)
		}
		if id, _ := n2.mgr.VRF().IDForName(b.VRFName); id != ids[b.VRFName] {
			t.Errorf("%s: vrf_id %d after the restart, was %d", b.VRFName, id, ids[b.VRFName])
		}
	}
	// A second restart changes nothing either.
	requireSameBindings(t, mustBoot(t, path).list(t), before)
}

// An unbound binding does not come back, and the others still do.
func TestBindingRestart_UnbindStaysGone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	n := mustBoot(t, path)
	n.bind(t, &v1.VrfBgpBinding{VrfName: "a", Rd: "65000:1"})
	n.bind(t, &v1.VrfBgpBinding{VrfName: "b", Rd: "65000:2"})
	if errs := n.unbind(t, "a").GetErrors(); len(errs) > 0 {
		t.Fatal(errs[0].GetReason())
	}
	if got := boundNames(mustBoot(t, path)); len(got) != 1 || got[0] != "b" {
		t.Fatalf("after the restart: %v, want [b]", got)
	}
}

// A file without saved bindings, from before they were recorded, boots with
// only the config's.
func TestBindingRestart_OlderFile(t *testing.T) {
	_, path := resourceManagerAt(t, `{"vrfs":[],"bridges":[],"vrf_objects":{"next_vrf_id":2,"entries":[{"name":"cfg","vrf_id":1,"config":true}]}}`)
	n := mustBoot(t, path, "cfg")
	if got := boundNames(n); len(got) != 1 || got[0] != "cfg" {
		t.Fatalf("bindings = %v, want [cfg]", got)
	}
	if id, _ := n.mgr.VRF().IDForName("cfg"); id != 1 {
		t.Errorf("cfg vrf_id = %d, want 1", id)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "runtime_vrf_bindings") {
		t.Errorf("the config binding was saved: %s", data)
	}
}

// The config wins over a saved binding of the same VRF: it is dropped from
// the state file, so it does not come back once the config stops binding
// that VRF. Changes over the API to a config binding are not saved either.
func TestBindingRestart_ConfigWins(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	n := mustBoot(t, path)
	n.bind(t, &v1.VrfBgpBinding{VrfName: "x", Rd: "65000:1"})
	n.bind(t, &v1.VrfBgpBinding{VrfName: "y", Rd: "65000:2"})

	// The operator adds x to the config.
	n2 := mustBoot(t, path, "x")
	if b, _ := n2.mgr.Get("x"); b.RD != "65535:x" {
		t.Fatalf("x rd = %q, want the config's", b.RD)
	}
	if got := n2.res.RuntimeVrfBindings(); len(got) != 1 || got[0].VRFName != "y" {
		t.Fatalf("state file after the config took x: %+v", got)
	}
	// An edit of the config binding lasts until the restart.
	n2.bind(t, &v1.VrfBgpBinding{VrfName: "x", Rd: "65000:9"})
	n3 := mustBoot(t, path, "x")
	if b, _ := n3.mgr.Get("x"); b.RD != "65535:x" {
		t.Fatalf("x rd after an API edit and a restart = %q, want the config's", b.RD)
	}
	// The operator removes x from the config again: no binding comes back.
	if got := boundNames(mustBoot(t, path)); len(got) != 1 || got[0] != "y" {
		t.Fatalf("after the config dropped x: %v, want [y]", got)
	}
}

// A bind or unbind whose state file cannot be written changes nothing, and
// what a restart then finds is what the RPCs reported; repeating them once
// the file is writable succeeds.
func TestBindingRestart_FailedSaveThenRetry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	n := mustBoot(t, path)
	n.bind(t, &v1.VrfBgpBinding{VrfName: "kept", Rd: "65000:1"})
	// The rename onto a directory fails, also as root.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0755); err != nil {
		t.Fatal(err)
	}
	resp, err := n.srv.VrfBgpBind(context.Background(), connect.NewRequest(&v1.VrfBgpBindRequest{
		Bindings: []*v1.VrfBgpBinding{{VrfName: "new", Rd: "65000:2"}},
	}))
	if err != nil || len(resp.Msg.GetErrors()) != 1 || len(resp.Msg.GetBound()) != 0 {
		t.Fatalf("bind with an unwritable state file: err %v, resp %v", err, resp.Msg)
	}
	if errs := n.unbind(t, "kept").GetErrors(); len(errs) != 1 {
		t.Fatalf("unbind with an unwritable state file: %v", errs)
	}
	if got := boundNames(n); len(got) != 1 || got[0] != "kept" {
		t.Fatalf("in memory after the failures: %v, want [kept]", got)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	// Another writer's save now carries what the manager holds.
	if err := n.res.Save(); err != nil {
		t.Fatal(err)
	}
	if got := boundNames(mustBoot(t, path)); len(got) != 1 || got[0] != "kept" {
		t.Fatalf("after a restart: %v, want [kept]", got)
	}
	n.bind(t, &v1.VrfBgpBinding{VrfName: "new", Rd: "65000:2"})
	if errs := n.unbind(t, "kept").GetErrors(); len(errs) > 0 {
		t.Fatal(errs[0].GetReason())
	}
	if got := boundNames(mustBoot(t, path)); len(got) != 1 || got[0] != "new" {
		t.Fatalf("after the retries and a restart: %v, want [new]", got)
	}
}

// A VRF the config created and no longer declares stays, with its id, while
// a saved binding names it. Here the config gave it only an AC, which the
// state file does not keep, so without the binding nothing would hold it.
func TestBindingRestart_KeepsTheBoundVRF(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	cfg := config.VRFsConfig{Entries: []config.VRFConfig{{Name: "other", ACs: []config.VRFACConfig{{Interface: "lo", VLAN: 7}}},
		{Name: "tenant", ACs: []config.VRFACConfig{{Interface: "lo"}}}}}
	n, err := bootBindings(path, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	n.bind(t, &v1.VrfBgpBinding{VrfName: "tenant", Rd: "65000:1"})
	id, _ := n.mgr.VRF().IDForName("tenant")

	// The config no longer declares tenant.
	n2, err := bootBindings(path, config.VRFsConfig{Entries: cfg.Entries[:1]}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := n2.mgr.VRF().IDForName("tenant"); !ok || got != id {
		t.Fatalf("tenant vrf_id = %d (exists %v), want %d", got, ok, id)
	}
	if _, ok := n2.mgr.Get("tenant"); !ok {
		t.Fatal("binding not restored")
	}
}

// A saved binding that does not decode stops the start, naming the record.
func TestSavedBindings_RefusesBadRecords(t *testing.T) {
	for name, record := range map[string]string{
		"no name":          `{"vrf_name":"","families":null}`,
		"bad direction":    `{"vrf_name":"a","families":{"vpnv4":{"route_targets":[{"rt":"65000:1","direction":"sideways"}]}}}`,
		"no direction":     `{"vrf_name":"a","families":{"vpnv4":{"route_targets":[{"rt":"65000:1","direction":""}]}}}`,
		"bad family":       `{"vrf_name":"a","families":{"ipv4":{"route_targets":[]}}}`,
		"bad prefix":       `{"vrf_name":"a","rd":"65000:1","families":null,"mup_gtp4_source_prefix":"10.0.0.0/8"}`,
		"twice":            `{"vrf_name":"a","families":null},{"vrf_name":"a","families":null}`,
		"legacy disagrees": `{"vrf_name":"a","export_rts":["65000:9"],"families":{"vpnv4":{"route_targets":[{"rt":"65000:1","direction":"both"}]}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, path := resourceManagerAt(t, `{"vrfs":[],"bridges":[],"runtime_vrf_bindings":[`+record+`]}`)
			if _, err := bootBindings(path, config.VRFsConfig{}, nil); err == nil {
				t.Fatal("boot accepted the record")
			}
		})
	}
}
