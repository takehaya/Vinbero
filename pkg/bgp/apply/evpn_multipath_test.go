package apply

import (
	"errors"
	"fmt"
	"net/netip"
	"testing"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/locator"
)

// EVPN multi-path tracking: RT2/RT3 record one contribution per {NLRI,
// delivering path}, several contributions collapse onto one data-plane
// entry via a deterministic representative, and a per-source withdraw (a
// route reflector's session loss) removes only its own contribution.

func evSrc(peer string) bgp.PathSource {
	return bgp.PathSource{Peer: netip.MustParseAddr(peer)}
}

func evSrcPath(peer string, id uint32) bgp.PathSource {
	return bgp.PathSource{Peer: netip.MustParseAddr(peer), PathID: id}
}

func rt2ev(r *bgp.EVPNRoute, src bgp.PathSource, withdraw bool) bgp.RouteEvent {
	return bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: r, Source: src, IsWithdraw: withdraw}
}

func rt2ip(mac, ip, sid string) *bgp.EVPNRoute {
	r := rt2(mac, sid)
	r.IPAddr = ip
	return r
}

// --- Stage 1: the NLRI identity carries the IP ---

func TestApplier_EVPNRT2MacOnlyAndMacIPSeparateContribs(t *testing.T) {
	const mac = "aa:bb:cc:00:00:01"
	a, fh := evpnApplier(t)
	a.Apply(rt2ev(rt2(mac, "fd00:2:2:d2::"), bgp.PathSource{}, false))
	a.Apply(rt2ev(rt2ip(mac, "10.0.0.10", "fd00:2:2:d2::"), bgp.PathSource{}, false))

	if len(a.evpn.fdb) != 2 {
		t.Fatalf("ledger contributions = %d, want 2 (MAC-only and MAC+IP are distinct NLRIs)", len(a.evpn.fdb))
	}
	if len(fh.fdb) != 1 || len(fh.bdPeers) != 1 {
		t.Fatalf("data plane: fdb=%d peers=%d, want 1/1 (one shared entry)", len(fh.fdb), len(fh.bdPeers))
	}

	// Withdrawing the MAC+IP variant keeps the entry (survivor hand-off).
	a.Apply(rt2ev(rt2ip(mac, "10.0.0.10", "fd00:2:2:d2::"), bgp.PathSource{}, true))
	if _, ok := fh.fdb[fdbKey{100, mac}]; !ok {
		t.Error("MAC+IP withdraw removed the FDB entry the MAC-only route still backs")
	}
	a.Apply(rt2ev(rt2(mac, "fd00:2:2:d2::"), bgp.PathSource{}, true))
	if len(fh.fdb) != 0 || len(fh.bdPeers) != 0 {
		t.Errorf("after both withdraws: fdb=%d peers=%d, want 0/0", len(fh.fdb), len(fh.bdPeers))
	}
}

// --- Stage 2: per-source contributions ---

func TestApplier_EVPNRT2PerSourceWithdraw(t *testing.T) {
	const mac = "aa:bb:cc:00:00:01"
	a, fh := evpnApplier(t)
	// The same NLRI delivered by two route reflectors (the EVPN next hop --
	// the originating PE -- is identical; only the delivering peer differs).
	a.Apply(rt2ev(rt2(mac, "fd00:2:2:d2::"), evSrc("2001:db8::a"), false))
	a.Apply(rt2ev(rt2(mac, "fd00:2:2:d2::"), evSrc("2001:db8::b"), false))
	if len(a.evpn.fdb) != 2 {
		t.Fatalf("contributions = %d, want 2 (one per delivering peer)", len(a.evpn.fdb))
	}
	if len(fh.fdb) != 1 || len(fh.bdPeers) != 1 {
		t.Fatalf("data plane: fdb=%d peers=%d, want 1/1", len(fh.fdb), len(fh.bdPeers))
	}

	// RR A's session dies: gobgp delivers a per-peer withdraw. RR B still
	// backs the route.
	a.Apply(rt2ev(rt2(mac, "fd00:2:2:d2::"), evSrc("2001:db8::a"), true))
	if _, ok := fh.fdb[fdbKey{100, mac}]; !ok {
		t.Error("one RR's withdraw removed the entry the other RR still backs")
	}
	a.Apply(rt2ev(rt2(mac, "fd00:2:2:d2::"), evSrc("2001:db8::b"), true))
	if len(fh.fdb) != 0 || len(fh.bdPeers) != 0 {
		t.Errorf("after both withdraws: fdb=%d peers=%d, want 0/0", len(fh.fdb), len(fh.bdPeers))
	}
}

func TestApplier_EVPNRT2AddPathDistinctPathID(t *testing.T) {
	const mac = "aa:bb:cc:00:00:01"
	a, _ := evpnApplier(t)
	a.Apply(rt2ev(rt2(mac, "fd00:2:2:d2::"), evSrcPath("2001:db8::a", 1), false))
	a.Apply(rt2ev(rt2(mac, "fd00:2:2:d2::"), evSrcPath("2001:db8::a", 2), false))
	if len(a.evpn.fdb) != 2 {
		t.Errorf("contributions = %d, want 2 (ADD-PATH ids are distinct paths)", len(a.evpn.fdb))
	}
}

func TestApplier_EVPNRT2UnusableFromOtherSourceKeepsEntry(t *testing.T) {
	const mac = "aa:bb:cc:00:00:01"
	a, fh := evpnApplier(t)
	a.Apply(rt2ev(rt2(mac, "fd00:2:2:d2::"), evSrc("2001:db8::a"), false))

	// The same NLRI arrives mangled (no SID) from the OTHER reflector --
	// same originating PE next hop, different delivering peer. Its own
	// contribution was never tracked, so nothing may be torn down.
	bad := rt2(mac, "")
	a.Apply(rt2ev(bad, evSrc("2001:db8::b"), false))
	if _, ok := fh.fdb[fdbKey{100, mac}]; !ok {
		t.Error("an unusable copy from another delivering peer cleared the tracked entry")
	}
}

func TestApplier_EVPNRT2RepresentativeDeterministic(t *testing.T) {
	const mac = "aa:bb:cc:00:00:01"
	// Two PEs advertise the same MAC with different SIDs (a genuine
	// divergence). Whichever arrives first, the programmed FDB entry must
	// follow the contribLess-minimum contribution.
	mk := func(rd, sid, nh string) *bgp.EVPNRoute {
		r := rt2(mac, sid)
		r.RD = rd
		r.NextHop = nh
		return r
	}
	// The contribLess minimum is routes[0] (lowest RD), so whatever the
	// arrival order, the FDB entry must point at ITS peer (the peer index
	// number itself is allocation-order dependent; the identity that must
	// be stable is which SID's peer the entry targets).
	install := func(order []int) (int, int) {
		a, fh := evpnApplier(t)
		routes := []*bgp.EVPNRoute{
			mk("65000:100", "fd00:2:2:d2::", "2001:db8::1"),
			mk("65000:200", "fd00:3:3:d2::", "2001:db8::2"),
		}
		srcs := []bgp.PathSource{evSrc("2001:db8::a"), evSrc("2001:db8::b")}
		for _, i := range order {
			a.Apply(rt2ev(routes[i], srcs[i], false))
		}
		e, ok := fh.fdb[fdbKey{100, mac}]
		if !ok {
			t.Fatal("no FDB entry")
		}
		rep, ok := a.evpn.peers[evpnPeerKey{bdID: 100, sid: "fd00:2:2:d2::"}]
		if !ok {
			t.Fatal("representative SID has no peer")
		}
		if e.PeerIndex != rep.index {
			t.Errorf("order %v: FDB points at index %d, want the representative's peer %d",
				order, e.PeerIndex, rep.index)
		}
		return len(a.evpn.fdb), len(fh.bdPeers)
	}
	contribsAB, peersAB := install([]int{0, 1})
	contribsBA, peersBA := install([]int{1, 0})
	if contribsAB != 2 || contribsBA != 2 || peersAB != 2 || peersBA != 2 {
		t.Fatalf("contribs/peers = %d/%d and %d/%d, want 2/2 both", contribsAB, peersAB, contribsBA, peersBA)
	}
}

func TestApplier_EVPNRT2ContribCap(t *testing.T) {
	const mac = "aa:bb:cc:00:00:01"
	a, _ := evpnApplier(t)
	for i := 0; i < maxEVPNContribsPerEntry; i++ {
		a.Apply(rt2ev(rt2(mac, "fd00:2:2:d2::"), evSrcPath("2001:db8::a", uint32(i)), false))
	}
	if len(a.evpn.fdb) != maxEVPNContribsPerEntry {
		t.Fatalf("contributions = %d, want the cap %d", len(a.evpn.fdb), maxEVPNContribsPerEntry)
	}
	over := evSrcPath("2001:db8::a", uint32(maxEVPNContribsPerEntry))
	a.Apply(rt2ev(rt2(mac, "fd00:2:2:d2::"), over, false))
	if len(a.evpn.fdb) != maxEVPNContribsPerEntry {
		t.Errorf("contribution over the cap was tracked: %d", len(a.evpn.fdb))
	}
	// The dropped contribution's withdraw is a no-op, not an underflow.
	a.Apply(rt2ev(rt2(mac, "fd00:2:2:d2::"), over, true))
	if len(a.evpn.fdb) != maxEVPNContribsPerEntry {
		t.Errorf("withdraw of a dropped contribution changed the ledger: %d", len(a.evpn.fdb))
	}
}

func TestApplier_ReplayEVPNOrderIndependent(t *testing.T) {
	const mac = "aa:bb:cc:00:00:01"
	mkEvents := func() []bgp.RouteEvent {
		r1 := rt2(mac, "fd00:2:2:d2::")
		r2 := rt2(mac, "fd00:3:3:d2::")
		r2.RD = "65000:200"
		return []bgp.RouteEvent{
			rt2ev(r1, evSrc("2001:db8::a"), false),
			rt2ev(r2, evSrc("2001:db8::b"), false),
		}
	}
	replay := func(order []int) int {
		a, fh := evpnApplier(t)
		evs := mkEvents()
		err := a.ReplayEVPN(func(h bgp.RouteHandler) error {
			for _, i := range order {
				h(evs[i])
			}
			return nil
		})
		if err != nil {
			t.Fatalf("ReplayEVPN: %v", err)
		}
		e, ok := fh.fdb[fdbKey{100, mac}]
		if !ok {
			t.Fatal("no FDB entry after replay")
		}
		// The representative is the contribLess minimum ({rd 65000:100,
		// source ::a}) regardless of replay order.
		rep, ok := a.evpn.peers[evpnPeerKey{bdID: 100, sid: "fd00:2:2:d2::"}]
		if !ok {
			t.Fatal("representative SID has no peer")
		}
		if e.PeerIndex != rep.index {
			t.Errorf("order %v: FDB points at index %d, want the representative's peer %d",
				order, e.PeerIndex, rep.index)
		}
		return len(a.evpn.fdb)
	}
	nAB := replay([]int{0, 1})
	nBA := replay([]int{1, 0})
	if nAB != 2 || nBA != 2 {
		t.Fatalf("replayed contributions = %d and %d, want 2 (Source preserved per path)", nAB, nBA)
	}
}

// --- Stage 3: RT3 flood peers are shared and refcounted ---

// rt3ev is rt2ev under a name matching its section.
var rt3ev = rt2ev

func TestApplier_EVPNRT3PerSourceWithdraw(t *testing.T) {
	a, fh := evpnApplier(t)
	a.Apply(rt3ev(rt3("fd00:2:2:24::"), evSrc("2001:db8::a"), false))
	a.Apply(rt3ev(rt3("fd00:2:2:24::"), evSrc("2001:db8::b"), false))
	if len(fh.bdPeers) != 1 {
		t.Fatalf("flood peers = %d, want 1 (shared by both contributions)", len(fh.bdPeers))
	}
	if mcastContribs(a) != 2 {
		t.Fatalf("mcast contributions = %d, want 2", mcastContribs(a))
	}

	a.Apply(rt3ev(rt3("fd00:2:2:24::"), evSrc("2001:db8::a"), true))
	if len(fh.bdPeers) != 1 {
		t.Error("one RR's withdraw removed the flood peer the other RR still backs")
	}
	a.Apply(rt3ev(rt3("fd00:2:2:24::"), evSrc("2001:db8::b"), true))
	if len(fh.bdPeers) != 0 || len(a.evpn.floodPeers) != 0 {
		t.Errorf("after both withdraws: peers=%d ledger=%d, want 0/0", len(fh.bdPeers), len(a.evpn.floodPeers))
	}
}

func TestApplier_EVPNRT3AnycastSIDSharesFloodPeer(t *testing.T) {
	a, fh := evpnApplier(t)
	// Two PEs anycasting one End.DT2M SID under distinct RDs: one flood
	// peer, or every BUM frame is replicated twice toward the same SID.
	r1 := rt3("fd00:2:2:24::")
	r2 := rt3("fd00:2:2:24::")
	r2.RD = "65000:200"
	a.Apply(rt3ev(r1, bgp.PathSource{}, false))
	a.Apply(rt3ev(r2, bgp.PathSource{}, false))
	if len(fh.bdPeers) != 1 {
		t.Fatalf("flood peers = %d, want 1 (anycast SID deduped)", len(fh.bdPeers))
	}
	a.Apply(rt3ev(r1, bgp.PathSource{}, true))
	if len(fh.bdPeers) != 1 {
		t.Error("withdrawing one anycast contribution removed the shared flood peer")
	}
	a.Apply(rt3ev(r2, bgp.PathSource{}, true))
	if len(fh.bdPeers) != 0 {
		t.Errorf("flood peer survived both withdraws: %v", fh.bdPeers)
	}
}

func TestApplier_EVPNRT3MidRefWithdrawIgnoresDeleteError(t *testing.T) {
	a, fh := evpnApplier(t)
	a.Apply(rt3ev(rt3("fd00:2:2:24::"), evSrc("2001:db8::a"), false))
	a.Apply(rt3ev(rt3("fd00:2:2:24::"), evSrc("2001:db8::b"), false))

	// Releasing a non-final reference touches no map, so a wedged map
	// cannot fail it.
	fh.bdPeerDelErr = errors.New("map is wedged")
	a.Apply(rt3ev(rt3("fd00:2:2:24::"), evSrc("2001:db8::a"), true))
	if mcastContribs(a) != 1 {
		t.Errorf("mid-ref withdraw did not release the contribution: %d", mcastContribs(a))
	}
	if len(fh.bdPeers) != 1 {
		t.Errorf("mid-ref withdraw touched the shared peer: %v", fh.bdPeers)
	}
}

func TestApplier_EVPNRT3SidMoveSharedPeerSurvives(t *testing.T) {
	a, fh := evpnApplier(t)
	r1 := rt3("fd00:2:2:24::")
	r2 := rt3("fd00:2:2:24::")
	r2.RD = "65000:200"
	a.Apply(rt3ev(r1, bgp.PathSource{}, false))
	a.Apply(rt3ev(r2, bgp.PathSource{}, false))

	// r1 moves to a new SID: the shared peer survives on r2's ref and a
	// second peer appears for the new SID.
	moved := rt3("fd00:2:2:25::")
	a.Apply(rt3ev(moved, bgp.PathSource{}, false))
	if len(fh.bdPeers) != 2 {
		t.Fatalf("flood peers = %d, want 2 (old shared + new)", len(fh.bdPeers))
	}
	if fs, ok := a.evpn.floodPeers[evpnPeerKey{bdID: 100, sid: "fd00:2:2:24::"}]; !ok || fs.refs != 1 {
		t.Errorf("old shared peer refs = %v, want 1 (r2's contribution)", fs)
	}
}

// Distinct NLRIs (one per RD) anycasting one SID each hold a flood
// reference; the shared peer's fan-in stops at the cap and the refused
// NLRI's later withdraw is a no-op.
func TestApplier_EVPNRT3FloodRefCap(t *testing.T) {
	a, _ := evpnApplier(t)
	over := rt3("fd00:2:2:24::")
	for i := 0; i <= maxEVPNContribsPerEntry; i++ {
		r := rt3("fd00:2:2:24::")
		r.RD = fmt.Sprintf("65000:%d", 100+i)
		if i == maxEVPNContribsPerEntry {
			over = r
		}
		a.Apply(rt3ev(r, bgp.PathSource{}, false))
	}
	// The over-cap NLRI's contribution is dropped when its acquire is
	// refused, so its withdraw must change nothing.
	if mcastContribs(a) != maxEVPNContribsPerEntry {
		t.Errorf("mcast contributions = %d, want the cap %d", mcastContribs(a), maxEVPNContribsPerEntry)
	}
	fs := a.evpn.floodPeers[evpnPeerKey{bdID: 100, sid: "fd00:2:2:24::"}]
	if fs == nil || fs.refs != maxEVPNContribsPerEntry {
		t.Fatalf("flood refs = %v, want %d", fs, maxEVPNContribsPerEntry)
	}
	a.Apply(rt3ev(over, bgp.PathSource{}, true))
	if fs.refs != maxEVPNContribsPerEntry || mcastContribs(a) != maxEVPNContribsPerEntry {
		t.Errorf("over-cap withdraw changed state: refs=%d mcast=%d", fs.refs, mcastContribs(a))
	}
}

// One NLRI's contributions (one per delivering path) stop at the per-NLRI
// cap: the 33rd ADD-PATH copy is dropped before tracking and its withdraw
// is a no-op.
func TestApplier_EVPNRT3PerNLRIContribCap(t *testing.T) {
	a, _ := evpnApplier(t)
	for i := 0; i <= maxEVPNContribsPerEntry; i++ {
		a.Apply(rt3ev(rt3("fd00:2:2:24::"), evSrcPath("2001:db8::a", uint32(i)), false))
	}
	if mcastContribs(a) != maxEVPNContribsPerEntry {
		t.Errorf("mcast contributions = %d, want the per-NLRI cap %d", mcastContribs(a), maxEVPNContribsPerEntry)
	}
	fs := a.evpn.floodPeers[evpnPeerKey{bdID: 100, sid: "fd00:2:2:24::"}]
	if fs == nil || fs.refs != 1 {
		t.Fatalf("one NLRI holds one flood ref however many paths deliver it; refs = %v", fs)
	}
	a.Apply(rt3ev(rt3("fd00:2:2:24::"), evSrcPath("2001:db8::a", uint32(maxEVPNContribsPerEntry)), true))
	if mcastContribs(a) != maxEVPNContribsPerEntry || fs.refs != 1 {
		t.Errorf("over-cap withdraw changed state: refs=%d mcast=%d", fs.refs, mcastContribs(a))
	}
}

// Two legitimate RT3s can arrive from one peer differing only in the
// NLRI's Originating Router's IP (RFC 7432 §7.3). They are distinct
// contributions and withdrawing one must not tear down the other.
func TestApplier_EVPNRT3DistinctOriginatingIP(t *testing.T) {
	a, fh := evpnApplier(t)
	r1 := rt3("fd00:2:2:24::")
	r1.IPAddr = "2001:db8::24"
	r2 := rt3("fd00:2:2:25::")
	r2.IPAddr = "2001:db8::25"
	a.Apply(rt3ev(r1, evSrc("2001:db8::a"), false))
	a.Apply(rt3ev(r2, evSrc("2001:db8::a"), false))
	if mcastContribs(a) != 2 || len(fh.bdPeers) != 2 {
		t.Fatalf("distinct originating IPs must track separately: mcast=%d peers=%d",
			mcastContribs(a), len(fh.bdPeers))
	}
	w := rt3("fd00:2:2:24::")
	w.IPAddr = "2001:db8::24"
	a.Apply(rt3ev(w, evSrc("2001:db8::a"), true))
	if len(fh.bdPeers) != 1 {
		t.Fatalf("withdrawing one originating IP tore down the other: peers=%d", len(fh.bdPeers))
	}
	if _, ok := a.evpn.floodPeers[evpnPeerKey{bdID: 100, sid: "fd00:2:2:25::"}]; !ok {
		t.Errorf("surviving NLRI lost its flood peer: %v", a.evpn.floodPeers)
	}
}

// A failed repair (slot freed underneath the ledger, reinstall refused)
// must keep the shared flood state: refs counts sibling NLRIs on the same
// {bd, SID}, and dropping the entry would strand their references so a
// later recreation undercounts them and a withdraw could delete a peer
// still in use. The kept state repairs on a later refresh with refs
// intact.
func TestApplier_EVPNRT3FailedRepairKeepsSharedRefs(t *testing.T) {
	a, fh := evpnApplier(t)
	// Two NLRIs (distinct RDs) anycast one SID: shared peer, refs 2.
	r2 := rt3("fd00:2:2:24::")
	r2.RD = "65000:101"
	a.Apply(rt3ev(rt3("fd00:2:2:24::"), evSrc("2001:db8::a"), false))
	a.Apply(rt3ev(r2, evSrc("2001:db8::a"), false))
	pk := evpnPeerKey{bdID: 100, sid: "fd00:2:2:24::"}
	if fs := a.evpn.floodPeers[pk]; fs == nil || fs.refs != 2 {
		t.Fatalf("shared flood refs = %v, want 2", a.evpn.floodPeers[pk])
	}

	// Operator flush frees the slot; the repair on refresh fails too.
	for k := range fh.bdPeers {
		delete(fh.bdPeers, k)
	}
	fh.bdPeerErr = errors.New("injected create failure")
	a.Apply(rt3ev(rt3("fd00:2:2:24::"), evSrc("2001:db8::a"), false))
	fs := a.evpn.floodPeers[pk]
	if fs == nil || fs.refs != 2 {
		t.Fatalf("failed repair must keep the shared state and refs: %v", fs)
	}
	if len(a.evpn.rt3Flood) != 2 {
		t.Fatalf("failed repair must keep sibling flood refs: %v", a.evpn.rt3Flood)
	}

	// The failure clears; the next refresh repairs in place, refs intact,
	// and a single withdraw only decrements.
	fh.bdPeerErr = nil
	a.Apply(rt3ev(rt3("fd00:2:2:24::"), evSrc("2001:db8::a"), false))
	if len(fh.bdPeers) != 1 || fs.refs != 2 {
		t.Fatalf("repair after clear: peers=%d refs=%d, want 1/2", len(fh.bdPeers), fs.refs)
	}
	a.Apply(rt3ev(r2, evSrc("2001:db8::a"), true))
	if fs.refs != 1 || len(fh.bdPeers) != 1 {
		t.Errorf("sibling withdraw after repair: refs=%d peers=%d, want 1/1", fs.refs, len(fh.bdPeers))
	}
}

// A foreign bd_peer that merely shares the SID (an operator entry with its
// own attributes on a reused index) must not be adopted: the refresh moves
// the ledger to a fresh slot and the final withdraw leaves the foreign
// entry alone.
func TestApplier_EVPNRT3ForeignSameSIDSlotNotAdopted(t *testing.T) {
	a, fh := evpnApplier(t)
	a.Apply(rt3ev(rt3("fd00:2:2:24::"), evSrc("2001:db8::a"), false))
	fs := a.evpn.floodPeers[evpnPeerKey{bdID: 100, sid: "fd00:2:2:24::"}]
	if fs == nil {
		t.Fatal("flood peer not installed")
	}

	// Operator flush, then an operator-owned peer with the same first
	// segment but different attributes lands on the freed index.
	foreign := &bpf.HeadendEntry{NumSegments: 1, FloodExclude: 1}
	foreign.Segments[0] = fh.bdPeers[bdPeerKey{100, fs.index}].Segments[0]
	oldIdx := fs.index
	for k := range fh.bdPeers {
		delete(fh.bdPeers, k)
	}
	fh.bdPeers[bdPeerKey{100, oldIdx}] = foreign

	a.Apply(rt3ev(rt3("fd00:2:2:24::"), evSrc("2001:db8::a"), false))
	if fs.index == oldIdx {
		t.Fatalf("refresh adopted the foreign same-SID entry at index %d", oldIdx)
	}
	if got := fh.bdPeers[bdPeerKey{100, oldIdx}]; got != foreign {
		t.Fatalf("foreign entry was touched: %v", got)
	}

	a.Apply(rt3ev(rt3("fd00:2:2:24::"), evSrc("2001:db8::a"), true))
	if got := fh.bdPeers[bdPeerKey{100, oldIdx}]; got != foreign {
		t.Errorf("final withdraw deleted the foreign entry")
	}
	if len(fh.bdPeers) != 1 {
		t.Errorf("peers after withdraw = %d, want only the foreign entry", len(fh.bdPeers))
	}
}

// A locator delete/recreate changes the encap source, but the ledger must
// not disown the slot it installed: the refresh keeps the existing peer
// (no duplicate flooding) and the final withdraw still deletes the real
// map entry, because both are guarded by the entry as installed, not a
// rebuild from the current locator.
func TestApplier_EVPNRT3LocatorChangeKeepsOwnedSlot(t *testing.T) {
	a, fh := evpnApplier(t)
	a.Apply(rt3ev(rt3("fd00:2:2:24::"), evSrc("2001:db8::a"), false))
	if len(fh.bdPeers) != 1 {
		t.Fatalf("flood peer not installed: %d", len(fh.bdPeers))
	}

	// The operator deletes and recreates the source locator with another
	// prefix; a rebuilt expectation would no longer match our own entry.
	if err := a.locators.Delete("LOC1", true); err != nil {
		t.Fatalf("Delete locator: %v", err)
	}
	if err := a.locators.Add(&locator.Locator{
		Name: "LOC1", Prefix: netip.MustParsePrefix("fd00:9:9::/48"),
		BlockLen: 32, NodeLen: 16, FunctionLen: 16, ArgumentLen: 64,
		Behavior: locator.BehaviorClassic,
	}); err != nil {
		t.Fatalf("Add locator: %v", err)
	}

	a.Apply(rt3ev(rt3("fd00:2:2:24::"), evSrc("2001:db8::a"), false))
	if len(fh.bdPeers) != 1 {
		t.Fatalf("locator change duplicated the flood peer: %d entries", len(fh.bdPeers))
	}

	a.Apply(rt3ev(rt3("fd00:2:2:24::"), evSrc("2001:db8::a"), true))
	if len(fh.bdPeers) != 0 {
		t.Errorf("final withdraw left the flood peer orphaned: %v", fh.bdPeers)
	}
}

// The final withdraw itself must also refuse a foreign same-SID entry on a
// reused index: with no refresh in between, the conditional delete is the
// only guard, and it compares the whole entry.
func TestApplier_EVPNRT3WithdrawSparesForeignSameSIDEntry(t *testing.T) {
	a, fh := evpnApplier(t)
	a.Apply(rt3ev(rt3("fd00:2:2:24::"), evSrc("2001:db8::a"), false))
	fs := a.evpn.floodPeers[evpnPeerKey{bdID: 100, sid: "fd00:2:2:24::"}]
	if fs == nil {
		t.Fatal("flood peer not installed")
	}
	foreign := &bpf.HeadendEntry{NumSegments: 1, FloodExclude: 1}
	foreign.Segments[0] = fh.bdPeers[bdPeerKey{100, fs.index}].Segments[0]
	idx := fs.index
	delete(fh.bdPeers, bdPeerKey{100, idx}) // operator frees the slot
	fh.bdPeers[bdPeerKey{100, idx}] = foreign

	a.Apply(rt3ev(rt3("fd00:2:2:24::"), evSrc("2001:db8::a"), true))
	if got := fh.bdPeers[bdPeerKey{100, idx}]; got != foreign {
		t.Errorf("withdraw deleted the foreign same-SID entry")
	}
	if len(a.evpn.floodPeers) != 0 || len(a.evpn.rt3Flood) != 0 || mcastContribs(a) != 0 {
		t.Errorf("ledger not cleared: floodPeers=%v rt3Flood=%v contribs=%d",
			a.evpn.floodPeers, a.evpn.rt3Flood, mcastContribs(a))
	}
}

// A repair failure on the still-held representative ref must not delete
// the contribution being updated: a non-representative SID change during a
// broken-slot window keeps its contribution so a later representative
// withdraw can still fail over to it.
func TestApplier_EVPNRT3RepairFailureKeepsUpdatedContribution(t *testing.T) {
	a, fh := evpnApplier(t)
	a.Apply(rt3ev(rt3("fd00:2:2:25::"), evSrc("2001:db8::a"), false)) // representative
	a.Apply(rt3ev(rt3("fd00:2:2:24::"), evSrc("2001:db8::b"), false)) // non-representative

	// The representative's slot breaks (flush) and reinstalls fail while
	// the non-representative changes its SID.
	for k := range fh.bdPeers {
		delete(fh.bdPeers, k)
	}
	fh.bdPeerErr = errors.New("injected create failure")
	a.Apply(rt3ev(rt3("fd00:2:2:26::"), evSrc("2001:db8::b"), false))
	if mcastContribs(a) != 2 {
		t.Fatalf("repair failure dropped the updated contribution: mcast=%d, want 2", mcastContribs(a))
	}

	// The failure clears and the representative withdraws: the flood must
	// fail over to the survivor's new SID.
	fh.bdPeerErr = nil
	a.Apply(rt3ev(rt3("fd00:2:2:25::"), evSrc("2001:db8::a"), true))
	if _, ok := a.evpn.floodPeers[evpnPeerKey{bdID: 100, sid: "fd00:2:2:26::"}]; !ok {
		t.Errorf("failover to the surviving contribution did not happen: %v", a.evpn.floodPeers)
	}
}

// An operator flush frees the slot underneath the ledger; a refresh of the
// unchanged contribution must notice and reinstall instead of trusting the
// ledger forever.
func TestApplier_EVPNRT3OperatorFlushHealsOnRefresh(t *testing.T) {
	a, fh := evpnApplier(t)
	a.Apply(rt3ev(rt3("fd00:2:2:24::"), evSrc("2001:db8::a"), false))
	for k := range fh.bdPeers {
		delete(fh.bdPeers, k) // operator flush behind the applier's back
	}
	a.Apply(rt3ev(rt3("fd00:2:2:24::"), evSrc("2001:db8::a"), false))
	if len(fh.bdPeers) != 1 {
		t.Fatalf("refresh did not reinstall the flushed flood peer: %d", len(fh.bdPeers))
	}
	fs := a.evpn.floodPeers[evpnPeerKey{bdID: 100, sid: "fd00:2:2:24::"}]
	if fs == nil || fs.refs != 1 {
		t.Errorf("flood ledger after heal = %v, want refs 1", fs)
	}
}

// An operator flush can free a slot underneath the ledger and the next
// allocation can reuse the index. A later withdraw of a stale contribution
// must verify the occupant's identity instead of deleting whatever now
// lives at the remembered index.
func TestApplier_EVPNRT3StaleIndexWithdrawSparesReusedSlot(t *testing.T) {
	a, fh := evpnApplier(t)
	a.Apply(rt3ev(rt3("fd00:2:2:24::"), evSrc("2001:db8::a"), false))

	// External flush frees the slot; a different SID's flood peer lands on
	// the same index.
	for k := range fh.bdPeers {
		delete(fh.bdPeers, k)
	}
	other := rt3("fd00:9:9:24::")
	other.RD = "65000:900"
	a.Apply(rt3ev(other, evSrc("2001:db8::b"), false))
	if len(fh.bdPeers) != 1 {
		t.Fatalf("reused slot count = %d, want 1", len(fh.bdPeers))
	}

	// The stale contribution withdraws: the reused slot holds a different
	// SID and must survive.
	a.Apply(rt3ev(rt3("fd00:2:2:24::"), evSrc("2001:db8::a"), true))
	if len(fh.bdPeers) != 1 {
		t.Errorf("stale-index withdraw deleted the reused slot: %v", fh.bdPeers)
	}
	if _, ok := a.evpn.floodPeers[evpnPeerKey{bdID: 100, sid: "fd00:9:9:24::"}]; !ok {
		t.Error("the reused slot's ledger vanished")
	}
}

// One NLRI whose sources diverge on the SID (a reflector lagging a PE's
// SID change) must flood toward exactly ONE of them -- flood peers are
// replication targets, not ECMP alternatives, so programming both would
// deliver every BUM frame twice.
func TestApplier_EVPNRT3DivergentSIDsSingleFloodPeer(t *testing.T) {
	a, fh := evpnApplier(t)
	fresh := rt3("fd00:2:2:25::")
	stale := rt3("fd00:2:2:24::")
	a.Apply(rt3ev(fresh, evSrc("2001:db8::a"), false))
	a.Apply(rt3ev(stale, evSrc("2001:db8::b"), false))
	if len(fh.bdPeers) != 1 {
		t.Fatalf("flood peers = %d, want 1 (divergent copies of one NLRI must not both replicate)", len(fh.bdPeers))
	}
	// The representative is the contribLess-minimum source (::a), so the
	// programmed peer is its SID.
	if _, ok := a.evpn.floodPeers[evpnPeerKey{bdID: 100, sid: "fd00:2:2:25::"}]; !ok {
		t.Errorf("flood peer is not the representative's SID: %v", a.evpn.floodPeers)
	}

	// The lagging reflector catches up: still one peer, now trivially
	// converged.
	caughtUp := rt3("fd00:2:2:25::")
	a.Apply(rt3ev(caughtUp, evSrc("2001:db8::b"), false))
	if len(fh.bdPeers) != 1 {
		t.Errorf("flood peers after convergence = %d, want 1", len(fh.bdPeers))
	}

	// The representative source withdraws while the other still diverges:
	// the survivor's SID takes over.
	a.Apply(rt3ev(rt3("fd00:2:2:25::"), evSrc("2001:db8::a"), true))
	if len(fh.bdPeers) != 1 {
		t.Errorf("flood peers after representative withdraw = %d, want 1", len(fh.bdPeers))
	}
}

// An NLRI left floodless by an acquire failure self-heals on the next
// refresh of any surviving contribution: the unchanged-contribution early
// return still reconciles when no flood ref is held. The floodless state
// arises when the representative withdraws, the old flood peer releases,
// and the survivor's SID cannot be installed at that moment.
func TestApplier_EVPNRT3FloodlessNLRIHealsOnRefresh(t *testing.T) {
	a, fh := evpnApplier(t)
	a.Apply(rt3ev(rt3("fd00:2:2:25::"), evSrc("2001:db8::a"), false)) // representative
	a.Apply(rt3ev(rt3("fd00:2:2:24::"), evSrc("2001:db8::b"), false)) // divergent survivor

	// Withdraw the representative while bd_peer creation fails: the old
	// flood peer releases but the survivor's SID cannot install, leaving
	// the NLRI floodless with a live contribution.
	fh.bdPeerErr = errors.New("injected create failure")
	a.Apply(rt3ev(rt3("fd00:2:2:25::"), evSrc("2001:db8::a"), true))
	if mcastContribs(a) != 1 {
		t.Fatalf("surviving contributions = %d, want 1", mcastContribs(a))
	}
	if len(a.evpn.rt3Flood) != 0 {
		t.Fatalf("NLRI should be floodless after the failed acquire: %v", a.evpn.rt3Flood)
	}

	// The failure clears; the survivor re-advertises unchanged (a refresh)
	// and the flood peer must materialize.
	fh.bdPeerErr = nil
	a.Apply(rt3ev(rt3("fd00:2:2:24::"), evSrc("2001:db8::b"), false))
	if _, ok := a.evpn.floodPeers[evpnPeerKey{bdID: 100, sid: "fd00:2:2:24::"}]; !ok {
		t.Errorf("floodless NLRI did not heal on refresh: %v", a.evpn.floodPeers)
	}
	if len(fh.bdPeers) != 1 {
		t.Errorf("flood peers in map = %d, want 1", len(fh.bdPeers))
	}
}
