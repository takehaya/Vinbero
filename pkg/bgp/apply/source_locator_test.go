package apply

import (
	"net/netip"
	"testing"

	"go.uber.org/zap"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/locator"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

func addTestLocator(t *testing.T, mgr *locator.Manager, prefix string) {
	t.Helper()
	loc := locator.Locator{
		Name: "LOC1", Prefix: netip.MustParsePrefix(prefix),
		BlockLen: 32, NodeLen: 16, FunctionLen: 16, ArgumentLen: 64,
		Behavior: locator.BehaviorClassic, FunctionAutoStart: 0x10, FunctionAutoEnd: 0xFFFF,
	}
	if err := mgr.Add(&loc); err != nil {
		t.Fatalf("locator Add: %v", err)
	}
}

// MUP sessions received before the source locator exists are tracked but not
// written. ReconcileSourceLocator writes them once it is registered, and a
// downlink takes the new prefix when the locator comes back under another.
func TestReconcileSourceLocatorMUP(t *testing.T) {
	fh := newFakeHeadend()
	locs := locator.NewManager()
	a := NewApplier(fh, locs, vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop())

	const (
		uePrefix = "10.0.0.1/32"
		endpoint = "192.0.2.100"
	)
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyMUPIPv4, MUP: &bgp.MUPRoute{
		Type: bgp.MUPRouteTypeT1ST, RD: "65000:100",
		Prefix: uePrefix, Endpoint: "203.0.113.5", TEID: 0x12345678, TEIDLen: 32, QFI: 9,
		SRv6SID: "fd00:2:2:b::",
	}})
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyMUPIPv4, MUP: &bgp.MUPRoute{
		Type: bgp.MUPRouteTypeT2ST, RD: "65000:100",
		Endpoint: endpoint, TEID: 0xAB000000, TEIDLen: 8, SRv6SID: "fd00:3:3:c::",
	}})
	uplink := mupUplinkKey{0, endpoint, 0xAB000000, 8}
	if _, ok := fh.v4created[uePrefix]; ok {
		t.Fatal("T1ST written without a source locator")
	}
	if _, ok := fh.mupUplink[uplink]; ok {
		t.Fatal("T2ST written without a source locator")
	}

	addTestLocator(t, locs, "fd00:1:1::/48")
	a.ReconcileSourceLocator()
	down, ok := fh.v4created[uePrefix]
	if !ok {
		t.Fatal("T1ST not written after the source locator was registered")
	}
	if got := netip.AddrFrom16(down.SrcAddr); got != netip.MustParseAddr("fd00:1:1::") {
		t.Errorf("T1ST source = %s, want fd00:1:1::", got)
	}
	if _, ok := fh.mupUplink[uplink]; !ok {
		t.Error("T2ST not written after the source locator was registered")
	}
	if _, ok := fh.v4created[endpoint+"/32"]; !ok {
		t.Error("T2ST gate not written after the source locator was registered")
	}

	if err := locs.Delete("LOC1", false); err != nil {
		t.Fatal(err)
	}
	addTestLocator(t, locs, "fd00:9:9::/48")
	a.ReconcileSourceLocator()
	if got := netip.AddrFrom16(fh.v4created[uePrefix].SrcAddr); got != netip.MustParseAddr("fd00:9:9::") {
		t.Errorf("T1ST source after the locator moved = %s, want fd00:9:9::", got)
	}
}
