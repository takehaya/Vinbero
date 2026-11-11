package apply

import (
	"errors"
	"fmt"
	"testing"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bpf"
)

// peRT2 / peRT3 are the RT2 (one MAC) and RT3 routes of remote PE n, each
// under its own RD, End.DT2U / End.DT2M SID and next hop.
func peRT2(n int) bgp.RouteEvent {
	return bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: &bgp.EVPNRoute{
		Type:    bgp.EVPNRouteTypeMACIP,
		RD:      fmt.Sprintf("65000:%d", n),
		RTs:     []string{"65000:100"},
		MAC:     fmt.Sprintf("aa:bb:cc:00:%02x:01", n),
		SRv6SID: fmt.Sprintf("fd00:2:%x:d2::", n),
		NextHop: fmt.Sprintf("fd00:ff::%x", n),
	}}
}

func peRT3(n int) bgp.RouteEvent {
	return bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: &bgp.EVPNRoute{
		Type:    bgp.EVPNRouteTypeInclusiveMulticast,
		RD:      fmt.Sprintf("65000:%d", n),
		RTs:     []string{"65000:100"},
		SRv6SID: fmt.Sprintf("fd00:2:%x:d3::", n),
		NextHop: fmt.Sprintf("fd00:ff::%x", n),
	}}
}

// Eight remote PEs, each with its RT2 and RT3, fit one bridge domain: the
// RT3 flood peers take the eight flood slots and the RT2 unicast peers the
// unicast range, so a ninth node is reachable with eight flood slots.
func TestEVPNEightRT3AndEightRT2InOneBD(t *testing.T) {
	a, fh := evpnApplier(t)
	for n := 1; n <= bpf.MaxBumNexthops; n++ {
		a.Apply(peRT3(n))
		a.Apply(peRT2(n))
	}
	if len(fh.bdPeers) != 2*bpf.MaxBumNexthops {
		t.Fatalf("peers = %d, want %d (an RT2 and an RT3 peer per PE)", len(fh.bdPeers), 2*bpf.MaxBumNexthops)
	}
	flood, unicast := 0, 0
	for k, e := range fh.bdPeers {
		switch {
		case bpf.FloodPeerRange.Contains(k.index):
			flood++
			if e.FloodExclude != 0 {
				t.Errorf("flood slot %d holds a flood-excluded peer", k.index)
			}
		case bpf.UnicastPeerRange.Contains(k.index):
			unicast++
			if e.FloodExclude == 0 {
				t.Errorf("unicast index %d holds a flood peer", k.index)
			}
			if !fh.bdPeerReverse[k] {
				t.Errorf("RT2 peer %d did not write its reverse entry", k.index)
			}
		default:
			t.Errorf("peer at index %d, outside the flood and unicast ranges", k.index)
		}
	}
	if flood != bpf.MaxBumNexthops || unicast != bpf.MaxBumNexthops {
		t.Errorf("flood peers = %d, unicast peers = %d, want %d each", flood, unicast, bpf.MaxBumNexthops)
	}
	for n := 1; n <= bpf.MaxBumNexthops; n++ {
		fdb := fh.fdb[fdbKey{100, fmt.Sprintf("aa:bb:cc:00:%02x:01", n)}]
		if fdb == nil || !bpf.UnicastPeerRange.Contains(fdb.PeerIndex) {
			t.Errorf("PE %d's MAC = %+v, want a pointer into the unicast range", n, fdb)
		}
	}
	// The reverse map names each PE's RT2 peer, which MAC learning uses.
	for k, v := range fh.reverse {
		if !bpf.UnicastPeerRange.Contains(v.index) {
			t.Errorf("reverse entry %v -> %d, want the RT2 peer", k, v.index)
		}
	}
}

// With every flood slot taken, a further RT3 is not installed and is not
// counted as a route the replay failed to write (the replayer would retry it
// for a minute for nothing); once a slot is freed, the replay that the freed
// slot asks for installs it.
func TestEVPNRT3ReplayedAfterFloodSlotFreed(t *testing.T) {
	a, fh := evpnApplier(t)
	for n := 1; n <= bpf.MaxBumNexthops; n++ {
		a.Apply(peRT3(n))
	}
	ninth := peRT3(bpf.MaxBumNexthops + 1)
	snapshot := func(h bgp.RouteHandler) error {
		for n := 2; n <= bpf.MaxBumNexthops+1; n++ {
			h(peRT3(n))
		}
		return nil
	}
	err := a.ReplayAndReconcile(func(scope ReplayScope) error {
		return scope(func() error { return a.ReplayEVPN(snapshot) })
	})
	var uw *UnwrittenRoutesError
	if errors.As(err, &uw) {
		t.Errorf("replay = %v: an RT3 that found the flood slots full counted as unwritten", err)
	}
	if _, ok := a.evpn.mcast[evpnMcastKey{rd: ninth.EVPN.RD}]; ok {
		t.Fatal("the ninth RT3 was installed with every flood slot taken")
	}

	a.Apply(withdrawn(peRT3(1)))
	if err := a.ReplayEVPN(snapshot); err != nil {
		t.Fatal(err)
	}
	st, ok := a.evpn.mcast[evpnMcastKey{rd: ninth.EVPN.RD}]
	if !ok || !bpf.FloodPeerRange.Contains(st.index) {
		t.Fatalf("after a freed slot the replay did not install the ninth RT3: %+v %v", st, ok)
	}
	if len(fh.bdPeers) != bpf.MaxBumNexthops {
		t.Errorf("flood peers = %d, want %d", len(fh.bdPeers), bpf.MaxBumNexthops)
	}
}

// The RT2 of a full unicast range is installed by the replay after an RT2
// peer is released, and its index is the one released.
func TestEVPNRT2ReplayedAfterUnicastIndexFreed(t *testing.T) {
	a, fh := evpnApplier(t)
	for n := 1; n <= bpf.MaxUnicastPeersPerBd; n++ {
		a.Apply(peRT2(n))
	}
	extra := peRT2(bpf.MaxUnicastPeersPerBd + 1)
	a.Apply(extra)
	if fh.HasFdb(100, extra.EVPN.MAC) {
		t.Fatal("an RT2 was installed with the unicast range full")
	}
	freed := fh.fdb[fdbKey{100, peRT2(5).EVPN.MAC}].PeerIndex
	a.Apply(withdrawn(peRT2(5)))
	if _, ok := fh.bdPeers[bdPeerKey{100, freed}]; ok {
		t.Fatalf("the last MAC's withdraw kept RT2 peer %d", freed)
	}
	if err := a.ReplayEVPN(func(h bgp.RouteHandler) error { h(extra); return nil }); err != nil {
		t.Fatal(err)
	}
	fdb := fh.fdb[fdbKey{100, extra.EVPN.MAC}]
	if fdb == nil || fdb.PeerIndex != freed {
		t.Fatalf("replayed RT2 = %+v, want the freed index %d", fdb, freed)
	}
}

// Withdrawing a PE's RT2 releases its unicast index and leaves the flood
// slots alone; withdrawing its RT3 releases the flood slot only.
func TestEVPNWithdrawReleasesOwnRangeOnly(t *testing.T) {
	a, fh := evpnApplier(t)
	a.Apply(peRT3(1))
	a.Apply(peRT2(1))
	slot := a.evpn.mcast[evpnMcastKey{rd: "65000:1"}].index
	uni := fh.fdb[fdbKey{100, peRT2(1).EVPN.MAC}].PeerIndex
	if !bpf.FloodPeerRange.Contains(slot) || !bpf.UnicastPeerRange.Contains(uni) {
		t.Fatalf("RT3 at %d, RT2 at %d: want a flood slot and a unicast index", slot, uni)
	}
	a.Apply(withdrawn(peRT2(1)))
	if _, ok := fh.bdPeers[bdPeerKey{100, uni}]; ok {
		t.Error("RT2 withdraw kept the unicast peer")
	}
	if _, ok := fh.bdPeers[bdPeerKey{100, slot}]; !ok {
		t.Error("RT2 withdraw removed the PE's flood peer")
	}
	a.Apply(withdrawn(peRT3(1)))
	if len(fh.bdPeers) != 0 {
		t.Errorf("peers left after both withdraws: %v", fh.bdPeers)
	}
}

// The startup sweep removes an earlier layout's EVPN state from pinned maps:
// an unowned ES peer at the earlier ES range [8, 40) and the FDB pointer to
// it, and a learned MAC that pointed at a peer the sweep removed. A MAC
// learned towards a peer that stays (the operator's) is kept.
func TestSweepRemovesEarlierLayoutState(t *testing.T) {
	a, fh := evpnApplier(t)
	legacyES := uint16(9)
	operator := uint16(2)
	fh.bdPeers[bdPeerKey{100, legacyES}] = &bpf.HeadendEntry{FloodExclude: 1, GroupId: 77}
	fh.bdPeers[bdPeerKey{100, operator}] = &bpf.HeadendEntry{}
	fh.fdb[fdbKey{100, "aa:bb:cc:00:00:01"}] = &bpf.FdbEntry{IsRemote: 1, PeerIndex: legacyES, BdId: 100}
	// Learned (dynamic, unowned) MACs: one towards an index no peer holds
	// any more (an RT2 peer of the earlier layout the owner sweep removed),
	// one towards the operator's peer, and a static one.
	fh.fdb[fdbKey{100, "aa:bb:cc:00:00:02"}] = &bpf.FdbEntry{IsRemote: 1, PeerIndex: 5, BdId: 100, LastSeen: 1}
	fh.fdb[fdbKey{100, "aa:bb:cc:00:00:03"}] = &bpf.FdbEntry{IsRemote: 1, PeerIndex: operator, BdId: 100, LastSeen: 1}
	fh.fdb[fdbKey{100, "aa:bb:cc:00:00:04"}] = &bpf.FdbEntry{IsRemote: 1, IsStatic: 1, PeerIndex: 5, BdId: 100}
	fh.fdb[fdbKey{100, "aa:bb:cc:00:00:05"}] = &bpf.FdbEntry{Oif: 3, BdId: 100}

	if _, ok := a.sweepEVPNState(); !ok {
		t.Fatal("sweep reported a failure")
	}
	if _, ok := fh.bdPeers[bdPeerKey{100, legacyES}]; ok {
		t.Error("the earlier layout's ES peer survived the sweep")
	}
	if _, ok := fh.bdPeers[bdPeerKey{100, operator}]; !ok {
		t.Error("the sweep removed the operator's flood peer")
	}
	for mac, want := range map[string]bool{
		"aa:bb:cc:00:00:01": false, // pointer to the earlier ES peer
		"aa:bb:cc:00:00:02": false, // learned, its peer is gone
		"aa:bb:cc:00:00:03": true,  // learned, its peer stays
		"aa:bb:cc:00:00:04": true,  // static: not learned
		"aa:bb:cc:00:00:05": true,  // local
	} {
		if got := fh.HasFdb(100, mac); got != want {
			t.Errorf("FDB %s present = %v, want %v", mac, got, want)
		}
	}
}

// The earlier ES range [8, 40) now lies mostly in the flood slots: there the
// sweep takes only what is an ES peer (an ECMP group) and the FDB pointers to
// it. A flood peer in slots 8 to 31 that it does not own, and the MACs that
// point at it, stay; the part of the earlier range inside today's ES range,
// [32, 40), is swept as the ES range is.
func TestSweepKeepsFloodSlotsOfEarlierESRange(t *testing.T) {
	a, fh := evpnApplier(t)
	fh.bdPeers[bdPeerKey{100, 8}] = &bpf.HeadendEntry{}                              // unowned flood peer
	fh.bdPeers[bdPeerKey{100, 31}] = &bpf.HeadendEntry{}                             // unowned flood peer
	fh.bdPeers[bdPeerKey{100, 20}] = &bpf.HeadendEntry{FloodExclude: 1, GroupId: 70} // earlier ES peer
	fh.bdPeers[bdPeerKey{100, 35}] = &bpf.HeadendEntry{FloodExclude: 1}              // in today's ES range
	fh.fdb[fdbKey{100, "aa:bb:cc:00:00:01"}] = &bpf.FdbEntry{IsRemote: 1, PeerIndex: 8, BdId: 100, LastSeen: 1}
	fh.fdb[fdbKey{100, "aa:bb:cc:00:00:02"}] = &bpf.FdbEntry{IsRemote: 1, IsStatic: 1, PeerIndex: 31, BdId: 100}
	fh.fdb[fdbKey{100, "aa:bb:cc:00:00:03"}] = &bpf.FdbEntry{IsRemote: 1, IsStatic: 1, PeerIndex: 20, BdId: 100}
	fh.fdb[fdbKey{100, "aa:bb:cc:00:00:04"}] = &bpf.FdbEntry{IsRemote: 1, IsStatic: 1, PeerIndex: 35, BdId: 100}

	if _, ok := a.sweepEVPNState(); !ok {
		t.Fatal("sweep reported a failure")
	}
	for idx, want := range map[uint16]bool{8: true, 31: true, 20: false, 35: false} {
		if _, got := fh.bdPeers[bdPeerKey{100, idx}]; got != want {
			t.Errorf("peer %d present = %v, want %v", idx, got, want)
		}
	}
	for mac, want := range map[string]bool{
		"aa:bb:cc:00:00:01": true,  // learned towards flood slot 8
		"aa:bb:cc:00:00:02": true,  // static towards flood slot 31
		"aa:bb:cc:00:00:03": false, // pointer to the earlier ES peer
		"aa:bb:cc:00:00:04": false, // pointer into the ES range
	} {
		if got := fh.HasFdb(100, mac); got != want {
			t.Errorf("FDB %s present = %v, want %v", mac, got, want)
		}
	}
}
