package cplaneharness_test

import (
	"os"
	"testing"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/sdk/go/cplaneharness"
)

// The harness is exercised against the example plugin, which is what a
// plugin author's own test would look like. Building it needs TinyGo, so
// the tests skip when the artifact is absent rather than failing on a
// missing toolchain.
func exampleModule(t *testing.T) []byte {
	t.Helper()
	mod, err := os.ReadFile("../../examples/cplane-custom-behavior/plugin.wasm")
	if err != nil {
		t.Skip("sdk/examples/cplane-custom-behavior not built (make cplane-example)")
	}
	return mod
}

// advertise builds a route carrying the example's claimed behavior.
func advertise(prefix, sid string) *v1.PluginRoute {
	return &v1.PluginRoute{
		Family:           "vpnv4",
		Peer:             "192.0.2.1",
		EndpointBehavior: 0xFE01,
		Rd:               "65000:1",
		Prefix:           prefix,
		Srv6Sid:          sid,
	}
}

// withdraw is that route going away. It deliberately carries no behavior:
// BGP sends only the NLRI, so a plugin cannot recognize a withdrawal by
// the behavior its advertisement had.
func withdraw(prefix string) *v1.PluginRoute {
	return &v1.PluginRoute{
		Family:     "vpnv4",
		Peer:       "192.0.2.1",
		IsWithdraw: true,
		Rd:         "65000:1",
		Prefix:     prefix,
	}
}

func TestPluginDeclaresOnAdvertise(t *testing.T) {
	h := cplaneharness.New(t, exampleModule(t), cplaneharness.Options{})
	if _, err := h.Route(advertise("10.0.0.0/24", "fd00:2::100")); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	decl, ok := h.LastDeclaration()
	if !ok {
		t.Fatal("the plugin committed nothing")
	}
	if decl.Kind != v1.PluginApplyKind_PLUGIN_APPLY_KIND_HEADEND_V4 {
		t.Errorf("declared kind = %v, want headend v4", decl.Kind)
	}
	if len(decl.Entries) != 1 {
		t.Fatalf("declared %d entries, want 1", len(decl.Entries))
	}
	if got := decl.Entries[0].GetTriggerPrefix(); got != "10.0.0.0/24" {
		t.Errorf("trigger prefix = %q, want the advertised prefix", got)
	}
	if segs := decl.Entries[0].GetSegments(); len(segs) != 1 || segs[0] != "fd00:2::100" {
		t.Errorf("segments = %v, want the advertised SID", segs)
	}
}

func TestPluginDropsPrefixOnWithdraw(t *testing.T) {
	h := cplaneharness.New(t, exampleModule(t), cplaneharness.Options{})
	if _, err := h.Route(advertise("10.0.0.0/24", "fd00:2::100")); err != nil {
		t.Fatalf("advertise: %v", err)
	}
	if _, err := h.Route(withdraw("10.0.0.0/24")); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	decl, ok := h.LastDeclaration()
	if !ok {
		t.Fatal("the plugin committed nothing")
	}
	if len(decl.Entries) != 0 {
		t.Fatalf("after the withdraw the plugin still declares %d entries", len(decl.Entries))
	}
}

// A plugin must not depend on state from before a restart: the daemon
// re-instantiates after a trap or a budget overrun, and everything the
// plugin knows has to be rebuilt from what it is replayed.
func TestPluginConvergesAfterRestart(t *testing.T) {
	h := cplaneharness.New(t, exampleModule(t), cplaneharness.Options{})
	if _, err := h.Route(advertise("10.0.0.0/24", "fd00:2::100")); err != nil {
		t.Fatalf("advertise: %v", err)
	}

	h.Restart()

	// The fresh instance knows nothing until it is replayed.
	if _, err := h.Route(advertise("10.0.0.0/24", "fd00:2::100")); err != nil {
		t.Fatalf("replay: %v", err)
	}
	decl, ok := h.LastDeclaration()
	if !ok {
		t.Fatal("the plugin committed nothing after the restart")
	}
	if len(decl.Entries) != 1 || decl.Entries[0].GetTriggerPrefix() != "10.0.0.0/24" {
		t.Fatalf("after the restart the plugin declares %+v, want the replayed prefix", decl.Entries)
	}
}

// A route naming a behavior the plugin did not claim must not move it.
func TestPluginIgnoresUnclaimedBehavior(t *testing.T) {
	h := cplaneharness.New(t, exampleModule(t), cplaneharness.Options{})
	route := advertise("10.0.0.0/24", "fd00:2::100")
	route.EndpointBehavior = 0x0013 // End.DT4
	if _, err := h.Route(route); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if decls := h.Declarations(); len(decls) != 0 {
		t.Fatalf("the plugin declared %+v for a behavior it does not own", decls)
	}
}

// A plugin whose commit is refused must not be left holding an open
// transaction, and must not wedge: the next event still works.
func TestPluginSurvivesRefusedCommit(t *testing.T) {
	h := cplaneharness.New(t, exampleModule(t), cplaneharness.Options{DenyCommits: true})
	if _, err := h.Route(advertise("10.0.0.0/24", "fd00:2::100")); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if decls := h.Declarations(); len(decls) != 0 {
		t.Fatalf("a refused commit was recorded as applied: %+v", decls)
	}
	// Still responsive afterwards.
	if _, err := h.Route(advertise("10.0.1.0/24", "fd00:2::200")); err != nil {
		t.Fatalf("the plugin stopped working after a refused commit: %v", err)
	}
}

func TestHarnessCapturesPluginLogs(t *testing.T) {
	h := cplaneharness.New(t, exampleModule(t), cplaneharness.Options{})
	if _, err := h.Route(advertise("10.0.0.0/24", "fd00:2::100")); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if len(h.Logs()) == 0 {
		t.Fatal("no plugin log lines were captured")
	}
}

// exampleConfig builds the example plugin's own config message: its
// behavior codepoint, and optionally the locator, prefix, RD and slot that
// make it originate as well as receive.
func exampleConfig(behavior uint64, locator, prefix, rd string, slot uint64, nextHop string) []byte {
	var buf []byte
	putVarint := func(v uint64) {
		for v >= 0x80 {
			buf = append(buf, byte(v)|0x80)
			v >>= 7
		}
		buf = append(buf, byte(v))
	}
	field := func(n int, wire int) { putVarint(uint64(n)<<3 | uint64(wire)) }
	str := func(n int, s string) {
		if s == "" {
			return
		}
		field(n, 2)
		putVarint(uint64(len(s)))
		buf = append(buf, s...)
	}
	field(1, 0)
	putVarint(behavior)
	str(2, locator)
	str(3, prefix)
	str(4, rd)
	if slot != 0 {
		field(5, 0)
		putVarint(slot)
	}
	str(7, nextHop)
	return buf
}

// The config blob retunes the plugin without rebuilding it.
func TestHarnessAppliesConfig(t *testing.T) {
	h := cplaneharness.New(t, exampleModule(t), cplaneharness.Options{
		Config: exampleConfig(0xFE02, "", "", "", 0, ""),
	})
	if _, err := h.Route(advertise("10.0.0.0/24", "fd00:2::100")); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if decls := h.Declarations(); len(decls) != 0 {
		t.Fatalf("the plugin acted on its compiled-in behavior after being reconfigured: %+v", decls)
	}

	route := advertise("10.0.1.0/24", "fd00:2::200")
	route.EndpointBehavior = 0xFE02
	if _, err := h.Route(route); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	decl, ok := h.LastDeclaration()
	if !ok || len(decl.Entries) != 1 {
		t.Fatalf("the plugin ignored its configured behavior: %+v", h.Declarations())
	}
}

func TestHarnessTickIsCallable(t *testing.T) {
	h := cplaneharness.New(t, exampleModule(t), cplaneharness.Options{})
	if err := h.Tick(0); err != nil {
		t.Fatalf("tick: %v", err)
	}
}

// The originating half of a plugin, driven without a daemon: it asks for a
// local SID, is told the address, and advertises a prefix behind it naming
// its own behavior codepoint.
func TestHarnessDrivesTheOriginatingHalf(t *testing.T) {
	h := cplaneharness.New(t, exampleModule(t), cplaneharness.Options{
		Config: exampleConfig(0xFE01, "main", "10.7.0.0/24", "65000:7", 33, "2001:db8::1"),
	})

	var sidDecl, advDecl *cplaneharness.Declaration
	for i := range h.Declarations() {
		d := h.Declarations()[i]
		switch d.Kind {
		case v1.PluginApplyKind_PLUGIN_APPLY_KIND_LOCAL_SID:
			sidDecl = &d
		case v1.PluginApplyKind_PLUGIN_APPLY_KIND_ADVERTISE:
			advDecl = &d
		}
	}
	if sidDecl == nil {
		t.Fatal("the plugin never asked for a local SID")
	}
	if len(sidDecl.LocalSIDs) != 1 || sidDecl.LocalSIDs[0].GetSlot() != 33 {
		t.Fatalf("declared local SIDs = %+v, want one pointing at slot 33", sidDecl.LocalSIDs)
	}
	if advDecl == nil {
		t.Fatal("the plugin never advertised anything after being given its SID")
	}
	if len(advDecl.Routes) != 1 {
		t.Fatalf("advertised %d routes, want the configured prefix", len(advDecl.Routes))
	}
	route := advDecl.Routes[0]
	if route.GetPrefix() != "10.7.0.0/24" || route.GetRd() != "65000:7" {
		t.Errorf("advertised %+v, want the configured prefix and RD", route)
	}
	if route.GetEndpointBehavior() != 0xFE01 {
		t.Errorf("advertised behavior = %#x, want the plugin's own", route.GetEndpointBehavior())
	}
	if route.GetSrv6Sid() == "" {
		t.Error("advertised no SID, so it never learned the address it was given")
	}
}

// A plugin configured with no locator is receive-only, which is an
// ordinary way to run one: a node that consumes a behavior without
// originating anything.
func TestHarnessReceiveOnlyPluginOriginatesNothing(t *testing.T) {
	h := cplaneharness.New(t, exampleModule(t), cplaneharness.Options{
		Config: exampleConfig(0xFE01, "", "", "", 0, ""),
	})
	for _, d := range h.Declarations() {
		if d.Kind == v1.PluginApplyKind_PLUGIN_APPLY_KIND_ADVERTISE && len(d.Routes) > 0 {
			t.Fatalf("a receive-only plugin advertised %+v", d.Routes)
		}
	}
}

// After a restart the host keeps what the previous instance installed and
// replays the rib. If the replay brings back no matching route, the plugin
// still has to declare -- an empty set -- or the entries the host kept are
// never pruned and blackhole traffic until an unrelated route arrives.
func TestPluginPrunesStaleEntriesAtEndOfReplay(t *testing.T) {
	h := cplaneharness.New(t, exampleModule(t), cplaneharness.Options{
		Config: exampleConfig(0xFE01, "", "", "", 0, ""),
	})
	if _, err := h.Route(advertise("10.0.0.0/24", "fd00:2::100")); err != nil {
		t.Fatalf("advertise: %v", err)
	}
	h.Restart()

	// The replay brings nothing back: everything was withdrawn while the
	// plugin was down.
	before := len(h.Declarations())
	if _, err := h.Deliver(&v1.PluginEvent{
		Kind:         v1.PluginEventKind_PLUGIN_EVENT_KIND_END_OF_REPLAY,
		ReplaySource: "bgp",
	}); err != nil {
		t.Fatalf("end of replay: %v", err)
	}
	if len(h.Declarations()) == before {
		t.Fatal("the plugin declared nothing at end of replay, so stale entries would never be pruned")
	}
	decl, _ := h.LastDeclaration()
	if len(decl.Entries) != 0 {
		t.Fatalf("declared %+v, want the empty set that prunes what it no longer knows about", decl.Entries)
	}
}

// The harness has to refuse what the daemon refuses. A plugin granted only
// advertise cannot open a headend transaction there, so one that tries
// must not pass conformance here and fail in production.
func TestHarnessRefusesADeclarationTheCapabilitiesDoNotCover(t *testing.T) {
	h := cplaneharness.New(t, exampleModule(t), cplaneharness.Options{
		Capabilities: []string{"advertise"},
	})
	// The example declares headend entries, which this grant does not
	// cover. Delivering a route makes it try.
	if _, err := h.Route(advertise("10.0.0.0/24", "fd00:2::100")); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if _, ok := h.LastDeclaration(); ok {
		t.Fatal("a headend declaration was accepted from a plugin granted only advertise")
	}
}
