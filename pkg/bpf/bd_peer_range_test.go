package bpf

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"

	vinberov1 "github.com/takehaya/vinbero/api/vinbero/v1"
)

func rangeTestPeer(t *testing.T, n int, floodExclude bool) *HeadendEntry {
	t.Helper()
	src, _ := ParseIPv6("fc00::1")
	segs, num, err := ParseSegments([]string{fmt.Sprintf("fd00:%x::1", n+1)})
	if err != nil {
		t.Fatal(err)
	}
	e := &HeadendEntry{Mode: uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2), NumSegments: num, SrcAddr: src, Segments: segs, BdId: 100}
	if floodExclude {
		e.FloodExclude = 1
	}
	return e
}

func rangeTestSrc(n int) [IPv6AddrLen]byte {
	a, _ := ParseIPv6(fmt.Sprintf("fd00:ff::%x", n+1))
	return a
}

// A flood peer takes a flood slot and a FloodExclude (RT2) peer an index of
// the unicast range, so eight of each fit one bridge domain; each range
// fails on its own with ErrBdPeerRangeFull once full.
func TestBdPeerAllocationByRange(t *testing.T) {
	m := newXDPTestHelper(t).mapOps
	var noESI [ESILen]byte
	for n := 0; n < MaxBumNexthops; n++ {
		i, err := m.CreateBdPeerAtFreeIndexOwned(100, rangeTestPeer(t, n, false), noESI, rangeTestSrc(n), false, OwnerBGPEVPN(65000))
		if err != nil || !FloodPeerRange.Contains(i) {
			t.Fatalf("flood peer %d: index %d, %v", n, i, err)
		}
		j, err := m.CreateBdPeerAtFreeIndexOwned(100, rangeTestPeer(t, 100+n, true), noESI, rangeTestSrc(100+n), true, OwnerBGPEVPN(65000))
		if err != nil || !UnicastPeerRange.Contains(j) {
			t.Fatalf("unicast peer %d: index %d, %v", n, j, err)
		}
	}
	if _, err := m.CreateBdPeerAtFreeIndex(100, rangeTestPeer(t, 50, false), noESI, rangeTestSrc(50), true); !errors.Is(err, ErrBdPeerRangeFull) {
		t.Fatalf("ninth flood peer: %v, want ErrBdPeerRangeFull", err)
	}
	for n := MaxBumNexthops; n < MaxUnicastPeersPerBd; n++ {
		if _, err := m.CreateBdPeerAtFreeIndexOwned(100, rangeTestPeer(t, 100+n, true), noESI, rangeTestSrc(100+n), true, OwnerBGPEVPN(65000)); err != nil {
			t.Fatalf("unicast peer %d: %v", n, err)
		}
	}
	if _, err := m.CreateBdPeerAtFreeIndexOwned(100, rangeTestPeer(t, 999, true), noESI, rangeTestSrc(999), true, OwnerBGPEVPN(65000)); !errors.Is(err, ErrBdPeerRangeFull) {
		t.Fatalf("unicast peer beyond the range: %v, want ErrBdPeerRangeFull", err)
	}
	// Another bridge domain has its own ranges.
	if i, err := m.CreateBdPeerAtFreeIndex(200, rangeTestPeer(t, 1, false), noESI, rangeTestSrc(1), true); err != nil || i != 0 {
		t.Fatalf("first flood peer of bd 200: index %d, %v", i, err)
	}
}

// An index written explicitly must be in the layout: never in the reserved
// part of the flood range or past the unicast range, and a flood peer never
// in the unicast range.
func TestBdPeerExplicitIndexChecked(t *testing.T) {
	m := newXDPTestHelper(t).mapOps
	var noESI [ESILen]byte
	var noSrc [IPv6AddrLen]byte
	for _, c := range []struct {
		index        uint16
		floodExclude bool
	}{
		{MaxBumNexthops, true},          // reserved flood range
		{BdPeerFloodReserved - 1, true}, // reserved flood range
		{UnicastPeerIndexBase, false},   // a flood peer in the unicast range
		{UnicastPeerRange.End(), true},  // past the unicast range
	} {
		if err := m.CreateBdPeer(100, c.index, rangeTestPeer(t, 1, c.floodExclude), noESI, noSrc, false); err == nil {
			t.Errorf("index %d (FloodExclude=%v) was accepted", c.index, c.floodExclude)
		}
	}
	if err := m.CreateBdPeer(100, EsPeerIndexBase, rangeTestPeer(t, 1, true), noESI, noSrc, false); err != nil {
		t.Errorf("ES index: %v", err)
	}
	if err := m.CreateBdPeer(100, UnicastPeerIndexBase, rangeTestPeer(t, 2, true), noESI, noSrc, false); err != nil {
		t.Errorf("unicast index: %v", err)
	}
}

// The freed hook runs once when an index of a range that turned an
// allocation away is freed in that bridge domain, by whichever path frees
// it, and not for a range or BD nothing waits on.
func TestBdPeerFreedHook(t *testing.T) {
	m := newXDPTestHelper(t).mapOps
	calls := 0
	m.SetBdPeerFreedHook(func() { calls++ })
	var noESI [ESILen]byte
	for n := 0; n < MaxBumNexthops; n++ {
		if _, err := m.CreateBdPeerAtFreeIndex(100, rangeTestPeer(t, n, false), noESI, rangeTestSrc(n), false); err != nil {
			t.Fatal(err)
		}
	}
	uni, err := m.CreateBdPeerAtFreeIndexOwned(100, rangeTestPeer(t, 50, true), noESI, rangeTestSrc(50), true, OwnerBGPEVPN(65000))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.DeleteBdPeerOwned(100, uni, OwnerBGPEVPN(65000)); err != nil || calls != 0 {
		t.Fatalf("freeing an index nothing waits on: calls = %d, %v", calls, err)
	}
	if _, err := m.CreateBdPeerAtFreeIndex(100, rangeTestPeer(t, 60, false), noESI, rangeTestSrc(60), false); !errors.Is(err, ErrBdPeerRangeFull) {
		t.Fatalf("ninth flood peer: %v", err)
	}
	if calls != 0 {
		t.Fatalf("a refused allocation ran the hook")
	}
	if _, err := m.DeleteBdPeer(200, 0); err != nil || calls != 0 {
		t.Fatalf("a delete in another BD: calls = %d, %v", calls, err)
	}
	if _, err := m.DeleteBdPeer(100, 3); err != nil || calls != 1 {
		t.Fatalf("freeing a flood slot after a refusal: calls = %d, %v", calls, err)
	}
	if _, err := m.DeleteBdPeer(100, 4); err != nil || calls != 1 {
		t.Fatalf("a second free with nothing waiting: calls = %d, %v", calls, err)
	}
	// Refused again, then freed by a flush.
	for n := 0; n < 2; n++ {
		if _, err := m.CreateBdPeerAtFreeIndex(100, rangeTestPeer(t, 70+n, false), noESI, rangeTestSrc(70+n), false); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := m.CreateBdPeerAtFreeIndex(100, rangeTestPeer(t, 80, false), noESI, rangeTestSrc(80), false); !errors.Is(err, ErrBdPeerRangeFull) {
		t.Fatalf("refill: %v", err)
	}
	if _, err := m.FlushBdPeers(100); err != nil || calls != 2 {
		t.Fatalf("flush after a refusal: calls = %d, %v", calls, err)
	}
}

// The operator RPC and the BGP applier allocate concurrently in one bridge
// domain: every index is handed out once, each class stays in its range, and
// exactly the range's size succeeds.
func TestBdPeerConcurrentAllocation(t *testing.T) {
	m := newXDPTestHelper(t).mapOps
	var noESI [ESILen]byte
	const tries = 24
	type result struct {
		index uint16
		err   error
		flood bool
	}
	results := make(chan result, 2*tries)
	var wg sync.WaitGroup
	for n := 0; n < tries; n++ {
		wg.Add(2)
		go func(n int) {
			defer wg.Done()
			i, err := m.CreateBdPeerAtFreeIndex(100, rangeTestPeer(t, n, false), noESI, rangeTestSrc(n), true)
			results <- result{i, err, true}
		}(n)
		go func(n int) {
			defer wg.Done()
			i, err := m.CreateBdPeerAtFreeIndexOwned(100, rangeTestPeer(t, 100+n, true), noESI, rangeTestSrc(100+n), true, OwnerBGPEVPN(65000))
			results <- result{i, err, false}
		}(n)
	}
	wg.Wait()
	close(results)
	seen := map[uint16]bool{}
	flood, unicast := 0, 0
	for r := range results {
		if r.err != nil {
			if !errors.Is(r.err, ErrBdPeerRangeFull) {
				t.Errorf("allocation failed with %v", r.err)
			}
			continue
		}
		if seen[r.index] {
			t.Errorf("index %d handed out twice", r.index)
		}
		seen[r.index] = true
		if r.flood {
			flood++
			if !FloodPeerRange.Contains(r.index) {
				t.Errorf("flood peer at %d", r.index)
			}
		} else {
			unicast++
			if !UnicastPeerRange.Contains(r.index) {
				t.Errorf("unicast peer at %d", r.index)
			}
		}
	}
	if flood != MaxBumNexthops || unicast != tries {
		t.Errorf("flood = %d (want %d), unicast = %d (want %d)", flood, MaxBumNexthops, unicast, tries)
	}
	peers, err := m.ListBdPeers()
	if err != nil || len(peers) != MaxBumNexthops+tries {
		t.Errorf("peers in the map = %d, %v", len(peers), err)
	}
}

// The layout check names every peer, owner record, reverse entry and remote
// FDB pointer at an index of the reserved flood range, and passes once they
// are gone.
func TestCheckBdPeerLayout(t *testing.T) {
	h := newXDPTestHelper(t)
	m := h.mapOps
	if err := m.CheckBdPeerLayout(); err != nil {
		t.Fatalf("empty maps: %v", err)
	}
	var noESI [ESILen]byte
	// Entries the layout allows.
	if _, err := m.CreateBdPeerAtFreeIndex(100, rangeTestPeer(t, 1, false), noESI, rangeTestSrc(1), true); err != nil {
		t.Fatal(err)
	}
	if _, err := m.CreateBdPeerAtFreeIndexOwned(100, rangeTestPeer(t, 2, true), noESI, rangeTestSrc(2), true, OwnerBGPEVPN(65000)); err != nil {
		t.Fatal(err)
	}
	if err := m.CreateBdPeer(100, EsPeerIndexBase, rangeTestPeer(t, 3, true), noESI, [IPv6AddrLen]byte{}, false); err != nil {
		t.Fatal(err)
	}
	if err := m.CheckBdPeerLayout(); err != nil {
		t.Fatalf("layout entries only: %v", err)
	}

	peerKey := BdPeerKey{BdId: 100, Index: 9}
	if err := h.objs.BdPeerMap.Put(&peerKey, rangeTestPeer(t, 9, true)); err != nil {
		t.Fatal(err)
	}
	ownerKey := BdPeerKey{BdId: 101, Index: 10}
	if err := m.bdPeerOwners.Put(&ownerKey, OwnerBGPEVPN(65001)); err != nil {
		t.Fatal(err)
	}
	revKey := BdPeerReverseKey{BdId: 102, SrcAddr: rangeTestSrc(11)}
	if err := h.objs.BdPeerReverseMap.Put(&revKey, &BdPeerReverseVal{Index: 11}); err != nil {
		t.Fatal(err)
	}
	mac := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	fdbKey := buildFdbKey(103, mac)
	if err := h.objs.FdbMap.Put(fdbKey, &FdbEntry{IsRemote: 1, PeerIndex: 12, BdId: 103}); err != nil {
		t.Fatal(err)
	}
	err := m.CheckBdPeerLayout()
	if err == nil {
		t.Fatal("entries in the reserved flood range passed")
	}
	for _, want := range []string{
		"peer {bd 100, index 9} (no owner)",
		"owner record {bd 101, index 10} (" + string(OwnerBGPEVPN(65001)) + ") without a peer",
		"reverse entry {bd 102, source fd00:ff::c} -> index 11",
		"FDB entry {bd 103, 02:00:00:00:00:01} -> peer index 12 (no owner)",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not name %q: %v", want, err)
		}
	}
	for _, del := range []func() error{
		func() error { return h.objs.BdPeerMap.Delete(&peerKey) },
		func() error { return m.bdPeerOwners.Delete(&ownerKey) },
		func() error { return h.objs.BdPeerReverseMap.Delete(&revKey) },
		func() error { return h.objs.FdbMap.Delete(fdbKey) },
	} {
		if err := del(); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.CheckBdPeerLayout(); err != nil {
		t.Errorf("after removing them: %v", err)
	}
}

// MAC learning on End.DT2 moves an FDB entry that points at a unicast-range
// peer (another PE's RT2 peer) to the sending PE's peer: only the ES range
// is a control-plane pointer that learning leaves alone.
func TestXDPProgEndDT2LearnMovesUnicastPointer(t *testing.T) {
	h := newXDPTestHelper(t)
	bdID := uint16(100)
	h.createSidFunctionWithBD("fd00:1:100::10/128", actionEndDT2, bdID)
	sender, _ := ParseIPv6("fd00:1:1::1")
	senderIdx := uint16(UnicastPeerIndexBase + 1)
	e := &HeadendEntry{Mode: uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2), NumSegments: 1, SrcAddr: sender, FloodExclude: 1}
	if err := h.mapOps.CreateBdPeer(bdID, senderIdx, e, [ESILen]byte{}, sender, true); err != nil {
		t.Fatalf("CreateBdPeer: %v", err)
	}
	// newTestEthernet's source MAC, last seen behind another PE's RT2 peer.
	srcMAC := net.HardwareAddr{0, 0, 0, 0, 0, 1}
	if err := h.objs.FdbMap.Put(buildFdbKey(bdID, srcMAC), &FdbEntry{IsRemote: 1, PeerIndex: UnicastPeerIndexBase, BdId: bdID}); err != nil {
		t.Fatal(err)
	}
	pkt, err := buildL2EncapsulatedPacket(
		net.ParseIP("fd00:1:1::1"), net.ParseIP("fd00:1:100::10"),
		[]net.IP{net.ParseIP("fd00:1:100::10")}, 0,
		100, net.ParseIP("10.0.0.1"), net.ParseIP("192.0.2.100"), true,
	)
	if err != nil {
		t.Fatal(err)
	}
	h.run(pkt)
	got, err := h.mapOps.GetFdb(bdID, srcMAC)
	if err != nil {
		t.Fatal(err)
	}
	if got.PeerIndex != senderIdx || got.LastSeen == 0 {
		t.Errorf("learned entry = index %d last_seen %d, want the sender's peer %d with a timestamp", got.PeerIndex, got.LastSeen, senderIdx)
	}
}

// On the AC side, a frame whose source MAC the FDB holds as remote refreshes
// last_seen when the entry points at a PE's peer (unicast range included),
// and leaves an ES-range pointer as the control plane wrote it.
func TestXDPProgHeadendL2RefreshesUnicastPointerOnly(t *testing.T) {
	h := newXDPTestHelper(t)
	bdID := uint16(100)
	src, _ := ParseIPv6("fc00::1")
	segs, n, _ := ParseSegments([]string{"fc00::200"})
	h.createHeadendL2Entry(0, 100, src, segs, n, bdID)
	h.createHeadendL2Entry(1, 100, src, segs, n, bdID)
	uniMAC := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	esMAC := net.HardwareAddr{2, 0, 0, 0, 0, 2}
	for _, c := range []struct {
		mac net.HardwareAddr
		idx uint16
	}{{uniMAC, UnicastPeerIndexBase}, {esMAC, EsPeerIndexBase}} {
		if err := h.objs.FdbMap.Put(buildFdbKey(bdID, c.mac), &FdbEntry{IsRemote: 1, PeerIndex: c.idx, BdId: bdID}); err != nil {
			t.Fatal(err)
		}
	}
	bcast := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	for _, mac := range []net.HardwareAddr{uniMAC, esMAC} {
		pkt, err := buildVlanTaggedARPPacket(100, mac, bcast)
		if err != nil {
			t.Fatal(err)
		}
		h.run(pkt)
	}
	uni, err := h.mapOps.GetFdb(bdID, uniMAC)
	if err != nil {
		t.Fatal(err)
	}
	if uni.LastSeen == 0 || uni.PeerIndex != UnicastPeerIndexBase {
		t.Errorf("unicast pointer = index %d last_seen %d, want refreshed in place", uni.PeerIndex, uni.LastSeen)
	}
	es, err := h.mapOps.GetFdb(bdID, esMAC)
	if err != nil {
		t.Fatal(err)
	}
	if es.LastSeen != 0 || es.PeerIndex != EsPeerIndexBase {
		t.Errorf("ES pointer = index %d last_seen %d, want untouched", es.PeerIndex, es.LastSeen)
	}
}
