package apply

import (
	"errors"
	"maps"
	"net/netip"
	"testing"

	"go.uber.org/zap"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/locator"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

// vpnSourceLab programs one prefix over two PEs with the source locator
// under fd00:1:1::/48.
func vpnSourceLab(t *testing.T) (*Applier, *fakeHeadend, *locator.Manager) {
	t.Helper()
	fh := newFakeHeadend()
	locs := locator.NewManager()
	addTestLocator(t, locs, "fd00:1:1::/48")
	a := NewApplier(fh, locs, vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop())
	a.Apply(vpnEvent("10.0.0.0/24", "65000:1", "fd00:2:2:a::", "fd00::2", false))
	a.Apply(vpnEvent("10.0.0.0/24", "65000:1", "fd00:3:3:a::", "fd00::3", false))
	return a, fh, locs
}

func vpnGroupOf(t *testing.T, fh *fakeHeadend, prefix string) uint32 {
	t.Helper()
	trigger, ok := fh.v4created[prefix]
	if !ok {
		t.Fatalf("%s not programmed", prefix)
	}
	return trigger.GroupId
}

// A path withdrawn while the source locator is gone leaves the ECMP group
// at once, written with the source the group already carries.
func TestVPNPathWithdrawnWhileSourceLocatorGone(t *testing.T) {
	a, fh, locs := vpnSourceLab(t)
	group := vpnGroupOf(t, fh, "10.0.0.0/24")
	if n := len(fh.ecmpGroups[group]); n != 2 {
		t.Fatalf("setup: %d members, want 2", n)
	}
	if err := locs.Delete("LOC1", false); err != nil {
		t.Fatal(err)
	}
	a.Apply(vpnEvent("10.0.0.0/24", "65000:1", "fd00:3:3:a::", "fd00::3", true))
	paths := fh.ecmpGroups[group]
	if len(paths) != 1 || paths[0].Entry.Segments[0] != netip.MustParseAddr("fd00:2:2:a::").As16() {
		t.Fatalf("group after the withdraw = %v, want only fd00:2:2:a::", groupSIDs(t, fh, group))
	}
	if got := netip.AddrFrom16(paths[0].Entry.SrcAddr); got != netip.MustParseAddr("fd00:1:1::") {
		t.Errorf("member source = %s, want the one the group carried, fd00:1:1::", got)
	}
}

// A tracked write that fails on the live path asks for a tracked retry. One
// that fails inside a replay, or inside ReconcileTracked, does not: the pass
// reports it by its return value.
func TestLiveTrackedFailureRequestsRetry(t *testing.T) {
	a, fh, _ := vpnSourceLab(t)
	requests := 0
	a.SetTrackedRetry(func() { requests++ })

	fh.FailEcmpWrites(1)
	a.Apply(vpnEvent("10.1.0.0/24", "65000:1", "fd00:2:2:b::", "fd00::2", false))
	if requests != 1 {
		t.Fatalf("retry requests after a failed live write = %d, want 1", requests)
	}

	fh.FailEcmpWrites(1)
	err := a.ReplayAndReconcile(func(scope ReplayScope) error {
		return scope(func() error {
			a.Apply(vpnEvent("10.2.0.0/24", "65000:1", "fd00:2:2:c::", "fd00::2", false))
			return nil
		})
	})
	if requests != 1 {
		t.Errorf("a failed write inside a replay asked for a retry")
	}
	if err != nil {
		t.Errorf("replay = %v, want nil: the tracked pass after it wrote the route", err)
	}

	fh.FailEcmpWrites(2)
	a.Apply(vpnEvent("10.3.0.0/24", "65000:1", "fd00:2:2:d::", "fd00::2", false))
	requests = 0
	var tw *TrackedWriteError
	if err := a.ReconcileTracked(); !errors.As(err, &tw) {
		t.Errorf("ReconcileTracked = %v, want a *TrackedWriteError", err)
	}
	if requests != 0 {
		t.Errorf("ReconcileTracked asked for a retry of its own failure")
	}
}

// The live MUP path reports a failed removal of an uplink whose SID no
// longer resolves.
func TestLiveT2STRemovalFailureRequestsRetry(t *testing.T) {
	a, fh, _, _ := mupSourceLab(t)
	requests := 0
	a.SetTrackedRetry(func() { requests++ })
	fh.mupUplinkDelErr = errors.New("busy")
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyMUPIPv4, MUP: &bgp.MUPRoute{
		Type: bgp.MUPRouteTypeT2ST, RD: "65000:100",
		Endpoint: labGateEndpoint, TEID: 0xAB000000, TEIDLen: 8,
	}})
	if requests != 1 {
		t.Errorf("retry requests after a failed live removal = %d, want 1", requests)
	}
}

// Removals need no source: ReconcileTracked retries a failed one while the
// source locator is gone.
func TestReconcileTrackedRemovesWithoutSourceLocator(t *testing.T) {
	a, fh, locs, uplink := mupSourceLab(t)
	if err := locs.Delete("LOC1", false); err != nil {
		t.Fatal(err)
	}
	fh.mupUplinkDelErr = errors.New("busy")
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyMUPIPv4, MUP: &bgp.MUPRoute{
		Type: bgp.MUPRouteTypeT2ST, RD: "65000:100",
		Endpoint: labGateEndpoint, TEID: 0xAB000000, TEIDLen: 8,
	}})
	fh.mupUplinkDelErr = nil
	reconcileTracked(t, a)
	if _, ok := fh.mupUplink[uplink]; ok {
		t.Error("stale uplink entry still installed after a pass without the source locator")
	}
}

// A replay counts only the EVPN routes its own deliveries could not write.
// A live delivery's failure is not the replay's, and a replay that delivers
// no EVPN route reports no EVPN failure.
func TestReplayCountsOnlyItsOwnEVPNFailures(t *testing.T) {
	a, fh := evpnApplier(t)
	failing := bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: rt2("aa:bb:cc:00:00:01", "fd00:2:2:d2::")}
	err := a.ReplayAndReconcile(func(scope ReplayScope) error {
		fh.FailBdPeerWrites(1)
		a.Apply(failing) // live, before the replay holds delivery off
		return scope(func() error {
			a.Apply(vpnEvent("10.0.0.0/24", "65000:1", "fd00:2:2:a::", "fd00::2", false))
			return nil
		})
	})
	if err != nil {
		t.Errorf("replay = %v, want nil: the failed EVPN write was not the replay's", err)
	}

	fh.FailBdPeerWrites(1)
	err = a.ReplayAndReconcile(func(scope ReplayScope) error {
		return scope(func() error {
			a.Apply(failing)
			return nil
		})
	})
	var uw *UnwrittenRoutesError
	if !errors.As(err, &uw) || uw.Family != bgp.FamilyEVPN || uw.Routes != 1 {
		t.Errorf("replay = %v, want 1 unwritten EVPN route", err)
	}
}

// A segment an earlier failure unwound and that fails to form again counts
// as failed, however many passes it takes.
func TestReconcileTrackedCountsAliasingFormationFailures(t *testing.T) {
	a, fh, locs, _, _ := evpnSourceLab(t)
	if err := locs.Delete("LOC1", false); err != nil {
		t.Fatal(err)
	}
	addTestLocator(t, locs, "fd00:9:9::/48")
	fh.FailEcmpWrites(10)
	for pass := range 3 {
		if err := a.ReconcileTracked(); err == nil {
			t.Fatalf("pass %d reported success with every aliasing group write failing", pass)
		}
	}
	fh.FailEcmpWrites(0)
	reconcileTracked(t, a)
	if len(fh.ecmpGroups) != 1 {
		t.Errorf("%d aliasing groups after the writes succeed, want 1", len(fh.ecmpGroups))
	}
}

// With the source unchanged and nothing pending, the pass does not visit the
// segments at all. The test takes a segment's per-EVI state away behind the
// applier's back: a visit would dissolve the group, so a group still there
// shows the visit did not happen.
func TestReconcileTrackedSkipsSettledSegments(t *testing.T) {
	a, fh, _, _, _ := evpnSourceLab(t)
	reconcileTracked(t, a) // settles esSrc
	for k := range a.evpn.eviAD {
		delete(a.evpn.eviAD, k)
	}
	reconcileTracked(t, a)
	if len(fh.ecmpGroups) != 1 {
		t.Error("an unchanged source with nothing pending visited the segments")
	}
}

// Two peers of one bridge domain behind the same remote PE source share one
// reverse-map entry. A source move must leave it with the peer that holds
// it, and not write it at all.
func TestSourceMoveKeepsSharedReverseEntry(t *testing.T) {
	locs := locator.NewManager()
	addTestLocator(t, locs, "fd00:1:1::/48")
	a, fh := evpnApplierOn(t, locs)
	for _, r := range []struct{ mac, sid string }{
		{"aa:bb:cc:00:00:01", "fd00:4:4:d2::"},
		{"aa:bb:cc:00:00:02", "fd00:4:4:d3::"},
	} {
		ev := rt2From("65000:100:4", r.mac, r.sid, "fd00::4", [10]byte{})
		ev.RemoteSrc = "fd00:4:4::"
		a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: ev})
	}
	if len(fh.bdPeers) != 2 || len(fh.reverse) != 1 {
		t.Fatalf("setup: %d peers, %d reverse entries; want 2, 1", len(fh.bdPeers), len(fh.reverse))
	}
	before := maps.Clone(fh.reverse)
	writes := fh.reverseWrites
	for range 8 { // map order varies between passes
		if err := locs.Delete("LOC1", false); err != nil {
			t.Fatal(err)
		}
		addTestLocator(t, locs, "fd00:9:9::/48")
		reconcileTracked(t, a)
		if err := locs.Delete("LOC1", false); err != nil {
			t.Fatal(err)
		}
		addTestLocator(t, locs, "fd00:1:1::/48")
		reconcileTracked(t, a)
	}
	if !maps.Equal(before, fh.reverse) {
		t.Errorf("reverse map = %v, want %v", fh.reverse, before)
	}
	if n := fh.reverseWrites - writes; n != 0 {
		t.Errorf("source moves wrote the reverse map %d times, want 0", n)
	}
}

// A source move rewrites a bridge domain's peers in one call, so the BD's
// BUM flood state is rebuilt once.
func TestSourceMoveRewritesPeersOncePerBD(t *testing.T) {
	a, fh, locs, _, _ := evpnSourceLab(t)
	moveSourceLocator(t, a, locs, "fd00:9:9::/48")
	if n := fh.bdPeerUpdateCalls[100]; n != 1 {
		t.Errorf("peer update calls for bd 100 = %d, want 1", n)
	}
}

// While the source locator is gone, a MAC learned behind a PE whose peer is
// already written is installed, with the source that peer carries.
func TestEVPNMacBehindKnownPeerWhileSourceLocatorGone(t *testing.T) {
	a, fh, locs, _, _ := evpnSourceLab(t)
	if err := locs.Delete("LOC1", false); err != nil {
		t.Fatal(err)
	}
	ev := rt2From("65000:100:4", "aa:bb:cc:00:00:09", "fd00:4:4:d2::", "fd00::4", [10]byte{})
	ev.RemoteSrc = "fd00:4:4::"
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: ev})
	if !fh.HasFdb(100, "aa:bb:cc:00:00:09") {
		t.Fatal("MAC behind a known peer not installed while the locator is gone")
	}
	checkEVPNSource(t, fh, netip.MustParseAddr("fd00:1:1::"))
}

// While the source locator is gone, an uplink whose SID changes is written
// with the new SID and the source it already carries.
func TestT2STSIDChangeWhileSourceLocatorGone(t *testing.T) {
	a, fh, locs, uplink := mupSourceLab(t)
	if err := locs.Delete("LOC1", false); err != nil {
		t.Fatal(err)
	}
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyMUPIPv4, MUP: &bgp.MUPRoute{
		Type: bgp.MUPRouteTypeT2ST, RD: "65000:100",
		Endpoint: labGateEndpoint, TEID: 0xAB000000, TEIDLen: 8, SRv6SID: "fd00:3:3:d::",
	}})
	e := fh.mupUplink[uplink]
	if e == nil || e.Segments[0] != netip.MustParseAddr("fd00:3:3:d::").As16() {
		t.Fatalf("uplink entry = %+v, want the new SID", e)
	}
	if got := netip.AddrFrom16(e.SrcAddr); got != netip.MustParseAddr("fd00:1:1::") {
		t.Errorf("uplink source = %s, want fd00:1:1::", got)
	}
}
