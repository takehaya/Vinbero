package cplane

import (
	"context"
	"net/netip"
	"os"
	"testing"

	"github.com/takehaya/vinbero/pkg/bgp"
)

// examplePlugin is the TinyGo plugin under sdk/examples. Unlike the
// hand-written .wat fixtures, it is a plugin as an operator would actually
// write one -- a real language runtime, a real allocator, a real reactor
// initializer -- which is what makes it worth testing against the host.
// Building it needs TinyGo (make cplane-example), so the test skips when
// the artifact is not there rather than failing on a missing toolchain.
func examplePlugin(t *testing.T) []byte {
	t.Helper()
	mod, err := os.ReadFile("../../sdk/examples/cplane-custom-behavior/plugin.wasm")
	if err != nil {
		t.Skip("sdk/examples/cplane-custom-behavior not built (make cplane-example)")
	}
	return mod
}

// customBehaviorRoute builds a VPNv4 advertisement carrying the example's
// claimed behavior.
func customBehaviorRoute(prefix, sid string) bgp.RouteEvent {
	return bgp.RouteEvent{
		Family:           bgp.FamilyVPNv4,
		Source:           bgp.PathSource{Peer: netip.MustParseAddr("192.0.2.1")},
		EndpointBehavior: 0xFE01,
		VPN:              &bgp.VPNRoute{RD: "65000:1", Prefix: prefix, SRv6SID: sid},
	}
}

func exampleManager(t *testing.T) (*Manager, *fakeSource, *fakeHeadendOps) {
	t.Helper()
	src := newFakeSource()
	ops := newFakeHeadendOps()
	m, err := NewManager(ManagerConfig{
		Source:             src,
		Claims:             newFakeClaims(),
		Headend:            ops,
		DefaultEncapSource: netip.MustParseAddr("fd00:1::1"),
	})
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	t.Cleanup(func() { m.Close(context.Background()) })
	if err := m.Register(context.Background(), Registration{
		Name:      "custom-behavior",
		Module:    examplePlugin(t),
		Behaviors: []uint16{0xFE01},
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
	return m, src, ops
}

// The whole point of the mechanism, end to end: a route carrying an
// operator's own behavior reaches the plugin, and the plugin's declaration
// becomes a headend entry.
func TestExamplePluginSteersItsOwnBehavior(t *testing.T) {
	m, src, ops := exampleManager(t)
	src.emit("custom-behavior", customBehaviorRoute("10.0.0.0/24", "fd00:2::100"))
	waitDelivered(t, m, "custom-behavior")

	if ops.countV4() != 1 {
		t.Fatalf("data plane holds %d entries, want the one the plugin declared", ops.countV4())
	}
	entry, ok := ops.getV4("10.0.0.0/24")
	if !ok {
		t.Fatalf("entries are keyed %v, want the advertised prefix", sortedV4(ops))
	}
	if entry.NumSegments != 1 {
		t.Fatalf("entry has %d segments, want the advertised SID", entry.NumSegments)
	}
	if got := netip.AddrFrom16(entry.Segments[0]); got != netip.MustParseAddr("fd00:2::100") {
		t.Errorf("segment = %v, want the SID the route advertised", got)
	}
	// The source it never named falls back to the daemon's.
	if got := netip.AddrFrom16(entry.SrcAddr); got != netip.MustParseAddr("fd00:1::1") {
		t.Errorf("source = %v, want the daemon default", got)
	}
}

// A withdrawal carries no attributes, so the plugin cannot recognize it by
// behavior. It has to match on the prefix it is holding, and this is the
// test that says so.
func TestExamplePluginHandlesWithdrawWithoutAttributes(t *testing.T) {
	m, src, ops := exampleManager(t)
	src.emit("custom-behavior", customBehaviorRoute("10.0.0.0/24", "fd00:2::100"))
	waitDelivered(t, m, "custom-behavior")
	if ops.countV4() != 1 {
		t.Fatalf("setup: %d entries, want 1", ops.countV4())
	}

	withdraw := customBehaviorRoute("10.0.0.0/24", "")
	withdraw.IsWithdraw = true
	withdraw.EndpointBehavior = 0 // as it arrives on the wire
	src.emit("custom-behavior", withdraw)
	waitDelivered(t, m, "custom-behavior")

	if ops.countV4() != 0 {
		t.Fatalf("withdraw left %d entries behind", ops.countV4())
	}
}

// A route naming a behavior this plugin did not claim is not its business.
func TestExamplePluginIgnoresOtherBehaviors(t *testing.T) {
	m, src, ops := exampleManager(t)
	other := customBehaviorRoute("10.0.0.0/24", "fd00:2::100")
	other.EndpointBehavior = 0x0013 // End.DT4
	src.emit("custom-behavior", other)
	waitDelivered(t, m, "custom-behavior")
	if ops.countV4() != 0 {
		t.Fatalf("the plugin acted on a behavior it does not own: %v", sortedV4(ops))
	}
}

// The plugin declares the whole set every time, so several prefixes
// accumulate and removing one leaves the others alone.
func TestExamplePluginDeclaresTheWholeSet(t *testing.T) {
	m, src, ops := exampleManager(t)
	src.emit("custom-behavior", customBehaviorRoute("10.0.1.0/24", "fd00:2::1"))
	waitDelivered(t, m, "custom-behavior")
	src.emit("custom-behavior", customBehaviorRoute("10.0.2.0/24", "fd00:2::2"))
	waitDelivered(t, m, "custom-behavior")
	if ops.countV4() != 2 {
		t.Fatalf("data plane holds %v, want both prefixes", sortedV4(ops))
	}

	withdraw := customBehaviorRoute("10.0.1.0/24", "")
	withdraw.IsWithdraw = true
	withdraw.EndpointBehavior = 0
	src.emit("custom-behavior", withdraw)
	waitDelivered(t, m, "custom-behavior")

	got := sortedV4(ops)
	if len(got) != 1 || got[0] != "10.0.2.0/24" {
		t.Fatalf("data plane holds %v, want only the prefix that was not withdrawn", got)
	}
}

// A restart is the plugin's ordinary recovery path: it comes back with no
// memory of anything, the host replays the routes, and the same
// declaration converges on the same state.
func TestExamplePluginConvergesAfterRestart(t *testing.T) {
	m, src, ops := exampleManager(t)
	src.emit("custom-behavior", customBehaviorRoute("10.0.0.0/24", "fd00:2::100"))
	waitDelivered(t, m, "custom-behavior")
	if ops.countV4() != 1 {
		t.Fatalf("setup: %d entries, want 1", ops.countV4())
	}

	// Re-registering is the upgrade path and stands in for a restart: a
	// fresh instance over the same owner tag.
	if err := m.Register(context.Background(), Registration{
		Name:      "custom-behavior",
		Module:    examplePlugin(t),
		Behaviors: []uint16{0xFE01},
	}); err != nil {
		t.Fatalf("re-register: %v", err)
	}
	// The state is still there across the swap.
	if ops.countV4() != 1 {
		t.Fatalf("the restart disturbed the data plane: %v", sortedV4(ops))
	}
	// The new instance knows nothing yet; the replay is what tells it.
	src.emit("custom-behavior", customBehaviorRoute("10.0.0.0/24", "fd00:2::100"))
	waitDelivered(t, m, "custom-behavior")
	if ops.countV4() != 1 {
		t.Fatalf("after replay the data plane holds %v, want the same single entry", sortedV4(ops))
	}
}

// The config blob retunes the plugin without rebuilding it: the same
// module claims a different codepoint.
func TestExamplePluginHonoursConfiguredBehavior(t *testing.T) {
	src := newFakeSource()
	ops := newFakeHeadendOps()
	m, err := NewManager(ManagerConfig{
		Source:             src,
		Claims:             newFakeClaims(),
		Headend:            ops,
		DefaultEncapSource: netip.MustParseAddr("fd00:1::1"),
	})
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	defer m.Close(context.Background())

	// The example's config is a bare varint: the codepoint to claim.
	// 0xFE02 encodes as two continuation-marked bytes.
	config := []byte{0x82, 0xfc, 0x03}
	if err := m.Register(context.Background(), Registration{
		Name:      "custom-behavior",
		Module:    examplePlugin(t),
		Config:    config,
		Behaviors: []uint16{0xFE02},
	}); err != nil {
		t.Fatalf("register: %v", err)
	}

	// The codepoint it was built with is no longer the one it claims.
	src.emit("custom-behavior", customBehaviorRoute("10.0.0.0/24", "fd00:2::100"))
	waitDelivered(t, m, "custom-behavior")
	if ops.countV4() != 0 {
		t.Fatalf("the plugin acted on its compiled-in behavior after being reconfigured: %v", sortedV4(ops))
	}

	configured := customBehaviorRoute("10.0.1.0/24", "fd00:2::200")
	configured.EndpointBehavior = 0xFE02
	src.emit("custom-behavior", configured)
	waitDelivered(t, m, "custom-behavior")
	if ops.countV4() != 1 {
		t.Fatalf("the plugin ignored its configured behavior: %v", sortedV4(ops))
	}
}
