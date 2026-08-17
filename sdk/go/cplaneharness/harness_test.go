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

// The config blob retunes the plugin without rebuilding it.
func TestHarnessAppliesConfig(t *testing.T) {
	// A bare varint holding 0xFE02, the codepoint to claim instead.
	h := cplaneharness.New(t, exampleModule(t), cplaneharness.Options{
		Config: []byte{0x82, 0xfc, 0x03},
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
