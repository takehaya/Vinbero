package apply

import (
	"errors"
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

func reconcileTracked(t *testing.T, a *Applier) {
	t.Helper()
	if err := a.ReconcileTracked(); err != nil {
		t.Fatalf("ReconcileTracked: %v", err)
	}
}

// MUP sessions received before the source locator exists are tracked but not
// written. ReconcileTracked writes them once it is registered, and a
// downlink takes the new prefix when the locator comes back under another.
func TestReconcileTrackedMUP(t *testing.T) {
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
	reconcileTracked(t, a) // still no locator: nothing to do, no error

	addTestLocator(t, locs, "fd00:1:1::/48")
	reconcileTracked(t, a)
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
	reconcileTracked(t, a)
	if got := netip.AddrFrom16(fh.v4created[uePrefix].SrcAddr); got != netip.MustParseAddr("fd00:9:9::") {
		t.Errorf("T1ST source after the locator moved = %s, want fd00:9:9::", got)
	}
}

// A write that fails during the pass is reported, so the caller can try again,
// and the next pass writes it.
func TestReconcileTrackedReportsFailedWrites(t *testing.T) {
	fh := newFakeHeadend()
	locs := locator.NewManager()
	a := NewApplier(fh, locs, vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop())
	a.Apply(vpnEventWithRT("10.1.0.0/24", "65000:100"))

	addTestLocator(t, locs, "fd00:1:1::/48")
	fh.putEcmpErr = errors.New("map full")
	if err := a.ReconcileTracked(); err == nil {
		t.Fatal("a failed group write was not reported")
	}
	if _, ok := fh.v4created["10.1.0.0/24"]; ok {
		t.Fatal("trigger written although its group write failed")
	}

	fh.putEcmpErr = nil
	reconcileTracked(t, a)
	if _, ok := fh.v4created["10.1.0.0/24"]; !ok {
		t.Fatal("the retry did not write the route")
	}
}

// A group's prober registration is part of what "unchanged" means. An SR
// Policy change while the source locator is gone cannot rebuild the probe
// journey and unregisters the group; registering the locator again under the
// same prefix leaves the entries as they were, but must register the group
// with the prober again.
func TestReconcileTrackedRestoresProber(t *testing.T) {
	fh := newFakeHeadend()
	locs := locator.NewManager()
	a := NewApplier(fh, locs, vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop())
	fp := newFakeProber()
	a.SetProber(fp)
	addTestLocator(t, locs, "fd00:1:1::/48")

	endpoint := netip.MustParseAddr("fd00::2")
	a.Apply(coloredVPNEvent("10.0.0.0/24", "65000:1", "fd00:1:1:a::", "fd00::2", 100))
	gid := fh.v4created["10.0.0.0/24"].GroupId
	if _, ok := fp.registered[gid]; !ok {
		t.Fatal("group not registered with the prober")
	}

	if err := locs.Delete("LOC1", false); err != nil {
		t.Fatal(err)
	}
	transport := []netip.Addr{netip.MustParseAddr("fd00:ee::1"), netip.MustParseAddr("fd00:ee::2")}
	a.ApplyLocalSRPolicy(LocalSRPolicy(100, endpoint, transport, 0), false)
	if _, ok := fp.registered[gid]; ok {
		t.Fatal("setup: the policy change without a source locator kept the registration")
	}

	addTestLocator(t, locs, "fd00:1:1::/48")
	reconcileTracked(t, a)
	got, ok := fp.registered[gid]
	if !ok {
		t.Fatal("prober registration not restored after the source locator came back")
	}
	if len(got) != 1 || len(got[0].Segments) != 1 || got[0].Segments[0] != transport[0] {
		t.Errorf("registration = %+v, want the new transport %v", got, transport[:1])
	}
}
