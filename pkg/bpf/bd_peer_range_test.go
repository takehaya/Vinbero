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
// the unicast range, so 32 of each fit one bridge domain; each range fails
// on its own with ErrBdPeerRangeFull once full: the 33rd flood peer and the
// 65th unicast peer.
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
		t.Fatalf("flood peer %d: %v, want ErrBdPeerRangeFull", MaxBumNexthops+1, err)
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

// An index written explicitly must be in the layout: never past the unicast
// range, and a flood peer never in the unicast range. Every flood slot,
// 8 to 31 included, takes a flood peer.
func TestBdPeerExplicitIndexChecked(t *testing.T) {
	m := newXDPTestHelper(t).mapOps
	var noESI [ESILen]byte
	var noSrc [IPv6AddrLen]byte
	for _, c := range []struct {
		index        uint16
		floodExclude bool
	}{
		{UnicastPeerIndexBase, false},  // a flood peer in the unicast range
		{UnicastPeerRange.End(), true}, // past the unicast range
	} {
		if err := m.CreateBdPeer(100, c.index, rangeTestPeer(t, 1, c.floodExclude), noESI, noSrc, false); err == nil {
			t.Errorf("index %d (FloodExclude=%v) was accepted", c.index, c.floodExclude)
		}
	}
	for _, i := range []uint16{7, 8, MaxBumNexthops - 1} {
		if err := m.CreateBdPeer(100, i, rangeTestPeer(t, int(i)+10, false), noESI, noSrc, false); err != nil {
			t.Errorf("flood slot %d: %v", i, err)
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
	// More flood peers than slots, fewer unicast peers than indices.
	const tries = MaxBumNexthops + 8
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

// The layout check names every flood-range peer that carries an ECMP group
// (an Ethernet Segment peer of the layout in which they took [8, 40)),
// whatever its owner, and passes once they are gone. Flood peers at any
// slot, the ES peers in their range and the unicast peers pass.
func TestCheckBdPeerLayout(t *testing.T) {
	h := newXDPTestHelper(t)
	m := h.mapOps
	if err := m.CheckBdPeerLayout(); err != nil {
		t.Fatalf("empty maps: %v", err)
	}
	var noESI [ESILen]byte
	// Entries the layout allows: flood peers in slots 0 to 31, an RT2 peer,
	// an ES peer with its group in the ES range.
	for n := 0; n < MaxBumNexthops; n++ {
		if _, err := m.CreateBdPeerAtFreeIndex(100, rangeTestPeer(t, n, false), noESI, rangeTestSrc(n), true); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := m.CreateBdPeerAtFreeIndexOwned(100, rangeTestPeer(t, 50, true), noESI, rangeTestSrc(50), true, OwnerBGPEVPN(65000)); err != nil {
		t.Fatal(err)
	}
	es := rangeTestPeer(t, 51, true)
	es.GroupId = 77
	if err := m.CreateBdPeer(100, EsPeerIndexBase, es, noESI, [IPv6AddrLen]byte{}, false); err != nil {
		t.Fatal(err)
	}
	if err := m.CheckBdPeerLayout(); err != nil {
		t.Fatalf("layout entries only: %v", err)
	}

	// ES peers of the earlier layout at 9 (no owner) and 31 (another ASN),
	// written past the index check as that version did.
	old9 := rangeTestPeer(t, 60, true)
	old9.GroupId = 78
	old31 := rangeTestPeer(t, 61, true)
	old31.GroupId = 79
	k9, k31 := BdPeerKey{BdId: 101, Index: 9}, BdPeerKey{BdId: 101, Index: 31}
	if err := h.objs.BdPeerMap.Put(&k9, old9); err != nil {
		t.Fatal(err)
	}
	if err := h.objs.BdPeerMap.Put(&k31, old31); err != nil {
		t.Fatal(err)
	}
	if err := m.bdPeerOwners.Put(&k31, OwnerBGPEVPN(65001)); err != nil {
		t.Fatal(err)
	}
	err := m.CheckBdPeerLayout()
	if err == nil {
		t.Fatal("ES peers in the flood range passed")
	}
	for _, want := range []string{
		"peer {bd 101, index 9} with ECMP group 78 (no owner)",
		"peer {bd 101, index 31} with ECMP group 79 (" + string(OwnerBGPEVPN(65001)) + ")",
		"(2 in all)",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not name %q: %v", want, err)
		}
	}
	for _, k := range []BdPeerKey{k9, k31} {
		if err := h.objs.BdPeerMap.Delete(&k); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.CheckBdPeerLayout(); err != nil {
		t.Errorf("after removing them: %v", err)
	}
}

// bd_flood_slots_map follows the flood peers: a bit per occupied slot, set
// by every create, cleared by every delete, the rollback of a failed create
// included, and rebuilt from bd_peer_map by RecoverBdFloodSlots.
func TestBdFloodSlots(t *testing.T) {
	h := newXDPTestHelper(t)
	m := h.mapOps
	slots := func(bd uint16) uint32 {
		t.Helper()
		var v uint32
		if err := h.objs.BdFloodSlotsMap.Lookup(uint32(bd), &v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	var noESI [ESILen]byte
	for n := 0; n < MaxBumNexthops; n++ {
		if _, err := m.CreateBdPeerAtFreeIndex(100, rangeTestPeer(t, n, false), noESI, rangeTestSrc(n), true); err != nil {
			t.Fatal(err)
		}
	}
	if got := slots(100); got != 0xffffffff {
		t.Fatalf("32 flood peers: slots %#x", got)
	}
	// Unicast and ES peers take no bit.
	if _, err := m.CreateBdPeerAtFreeIndexOwned(100, rangeTestPeer(t, 40, true), noESI, rangeTestSrc(40), true, OwnerBGPEVPN(65000)); err != nil {
		t.Fatal(err)
	}
	for _, i := range []uint16{7, 8, 31} {
		if _, err := m.DeleteBdPeer(100, i); err != nil {
			t.Fatal(err)
		}
	}
	if got, want := slots(100), uint32(0xffffffff&^(1<<7|1<<8|1<<31)); got != want {
		t.Fatalf("after deleting 7, 8, 31: slots %#x, want %#x", got, want)
	}
	if got := slots(200); got != 0 {
		t.Fatalf("bd 200: slots %#x", got)
	}
	// The allocator refills the lowest free slot first, and its bit.
	if i, err := m.CreateBdPeerAtFreeIndex(100, rangeTestPeer(t, 41, false), noESI, rangeTestSrc(41), true); err != nil || i != 7 {
		t.Fatalf("refill: index %d, %v", i, err)
	}
	if slots(100)&(1<<7) == 0 {
		t.Fatal("slot 7 refilled without its bit")
	}

	// A start over pinned maps: the slots map is not pinned and comes up
	// empty, or stale.
	if err := h.objs.BdFloodSlotsMap.Put(uint32(100), uint32(0)); err != nil {
		t.Fatal(err)
	}
	if err := h.objs.BdFloodSlotsMap.Put(uint32(300), uint32(0x5)); err != nil {
		t.Fatal(err)
	}
	if err := m.RecoverBdFloodSlots(); err != nil {
		t.Fatal(err)
	}
	if got, want := slots(100), uint32(0xffffffff&^(1<<8|1<<31)); got != want {
		t.Errorf("recovered bd 100: slots %#x, want %#x", got, want)
	}
	if got := slots(300); got != 0 {
		t.Errorf("recovered bd 300 (no peers): slots %#x", got)
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
