package bpf

import (
	"encoding/binary"
	"fmt"
	"net"
	"slices"
	"testing"

	"github.com/cilium/ebpf"
	vinberov1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"go.uber.org/zap"
)

const l2EncapMode = vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2

// rawDevmapKeys reads outer[bd]'s keys as they are, slot keys with their
// build number.
func rawDevmapKeys(t *testing.T, outer *ebpf.Map, bd uint16) []uint32 {
	t.Helper()
	var id ebpf.MapID
	if err := outer.Lookup(uint32(bd), &id); err != nil {
		t.Fatalf("outer lookup: %v", err)
	}
	inner, err := ebpf.NewMapFromID(id)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = inner.Close() }()
	var (
		keys []uint32
		k    uint32
		v    devmapVal
	)
	it := inner.Iterate()
	for it.Next(&k, &v) {
		keys = append(keys, k)
	}
	if err := it.Err(); err != nil {
		t.Fatal(err)
	}
	slices.Sort(keys)
	return keys
}

// innerMaxEntries is the size of outer[bd]'s inner map.
func innerMaxEntries(t *testing.T, outer *ebpf.Map, bd uint16) uint32 {
	t.Helper()
	var id ebpf.MapID
	if err := outer.Lookup(uint32(bd), &id); err != nil {
		t.Fatalf("outer lookup: %v", err)
	}
	inner, err := ebpf.NewMapFromID(id)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = inner.Close() }()
	info, err := inner.Info()
	if err != nil {
		t.Fatal(err)
	}
	return info.MaxEntries
}

func bumSlotsOf(t *testing.T, objs *BpfObjects, bd uint16) BpfBumSlots {
	t.Helper()
	var v BpfBumSlots
	if err := objs.BumSlotsMap.Lookup(uint32(bd), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// Flood slots on both sides of 8 and at the top of the 32-bit set: the plan
// lists them per uplink, bum_slots_map lists the devmap's slots under the
// build number every slot key carries, and the copies for an uplink take
// its slots in order, slot 31 included. A rebuild numbers its keys anew.
func TestBumPlanSlotsAcross32Bits(t *testing.T) {
	c := newEgressCase(t)
	nh := c.nexthop.String()
	l2 := bumFrame(t)
	var noESI [ESILen]byte
	behind := []uint16{0, 7, 8, 31}
	for _, i := range behind {
		c.peer(t, i, l2EncapMode, []string{nh, lastSegment(i).String()}, noESI, false)
	}
	c.uplinkOf["fc00::99"] = 1 // a second uplink (lo)
	c.peer(t, 30, l2EncapMode, []string{"fc00::99", lastSegment(30).String()}, noESI, false)

	plan := c.ingress(t, l2)
	type up struct {
		ifindex uint32
		slots   uint32
		n       uint8
	}
	var got []up
	for i := range int(plan.N_uplinks) {
		got = append(got, up{plan.Up[i].Ifindex, plan.Up[i].Slots, plan.Up[i].N})
	}
	want := []up{{c.uplink, 1<<0 | 1<<7 | 1<<8 | 1<<31, 4}, {1, 1 << 30, 1}}
	if !slices.Equal(got, want) {
		t.Fatalf("plan uplinks = %+v, want %+v", got, want)
	}
	sl := bumSlotsOf(t, c.h.objs, bumTestBD)
	if sl.Mask != 1<<0|1<<7|1<<8|1<<30|1<<31 || sl.Gen == 0 {
		t.Errorf("bum_slots = %+v, want slots 0, 7, 8, 30, 31 and a build number", sl)
	}
	slotKeys := func(gen uint32) []uint32 {
		var keys []uint32
		for _, k := range rawDevmapKeys(t, c.h.objs.BumFloodMap, bumTestBD) {
			if _, ok := BumSlotIndex(k); ok {
				keys = append(keys, k)
			}
		}
		return keys
	}
	wantKeys := func(gen uint32, slots ...uint16) []uint32 {
		var keys []uint32
		for _, i := range slots {
			keys = append(keys, BumSlotKey(gen, i))
		}
		return keys
	}
	if got, want := slotKeys(sl.Gen), wantKeys(sl.Gen, 0, 7, 8, 30, 31); !slices.Equal(got, want) {
		t.Errorf("slot keys = %#x, want %#x", got, want)
	}
	for _, slot := range behind {
		ret, out := c.egress(t, 1, c.uplink, false, l2)
		if ret != XDP_PASS {
			t.Fatalf("copy for slot %d: action = %d, want XDP_PASS", slot, ret)
		}
		if got := net.IP(out[ethHeaderLen+ipv6HeaderLen+srhBaseLen : ethHeaderLen+ipv6HeaderLen+srhBaseLen+ipv6AddrLen]); !got.Equal(lastSegment(slot)) {
			t.Errorf("copy for slot %d: SRH[0] = %v, want %v", slot, got, lastSegment(slot))
		}
	}
	if ret, _ := c.egress(t, 1, c.uplink, false, l2); ret != XDP_DROP {
		t.Errorf("fifth copy for the uplink: action = %d, want XDP_DROP (surplus)", ret)
	}

	c.peer(t, 9, l2EncapMode, []string{nh, lastSegment(9).String()}, noESI, false)
	c.ingress(t, l2)
	next := bumSlotsOf(t, c.h.objs, bumTestBD)
	if next.Gen == sl.Gen || next.Mask != sl.Mask|1<<9 {
		t.Errorf("after adding slot 9: bum_slots = %+v (was %+v)", next, sl)
	}
	if got, want := slotKeys(next.Gen), wantKeys(next.Gen, 0, 7, 8, 9, 30, 31); !slices.Equal(got, want) {
		t.Errorf("slot keys after the rebuild = %#x, want %#x", got, want)
	}
}

// A plan is only made against the devmap bum_slots_map describes: a slot
// key that misses (another build's devmap, or an entry the kernel removed
// with its device) sends the frame to the tc path, so no copy of that
// devmap leaves without a plan item. With no slot listed, the frame goes
// out through the local devmap, which has no slot entry of any build.
func TestBumPlanOtherBuildTakesTCPath(t *testing.T) {
	c := newEgressCase(t)
	nh := c.nexthop.String()
	l2 := bumFrame(t)
	var noESI [ESILen]byte
	for i := range uint16(2) {
		c.peer(t, i, l2EncapMode, []string{nh, lastSegment(i).String()}, noESI, false)
	}
	c.ingress(t, l2)
	good := bumSlotsOf(t, c.h.objs, bumTestBD)
	put := func(v BpfBumSlots) {
		t.Helper()
		if err := c.h.objs.BumSlotsMap.Put(uint32(bumTestBD), &v); err != nil {
			t.Fatal(err)
		}
	}
	tcPath := func(name string) {
		t.Helper()
		ret, out := c.h.run(l2)
		if ret != XDP_PASS || len(out) != len(l2)+8 || binary.LittleEndian.Uint64(out[:8])>>32 != uint64(vnbuMarker) {
			t.Errorf("%s: action = %d, len %d; want XDP_PASS with the VNBU meta (tc path)", name, ret, len(out))
		}
	}
	put(BpfBumSlots{Gen: good.Gen + 1, Mask: good.Mask})
	tcPath("slots of another build")
	put(BpfBumSlots{Gen: good.Gen, Mask: good.Mask | 1<<5})
	tcPath("a slot the devmap does not hold")
	put(good)
	if ret, _ := c.h.run(l2); ret != XDP_REDIRECT {
		t.Errorf("slots of the devmap's build: action = %d, want XDP_REDIRECT", ret)
	}

	put(BpfBumSlots{Gen: good.Gen})
	if ret, _ := c.h.run(l2); ret != XDP_REDIRECT {
		t.Errorf("no slots listed: action = %d, want XDP_REDIRECT (local devmap)", ret)
	}
	if err := c.h.objs.BumLocalMap.Delete(uint32(bumTestBD)); err != nil {
		t.Fatal(err)
	}
	tcPath("no slots listed and no local devmap")
}

// A BD of 32 flood slots fits one devmap: its devmaps are sized to what
// they hold, the plan takes up to BumPlanMaxUplinks uplinks, and a ninth
// uplink sends the BD to the tc path until the peers fit again.
func TestBumDevmapSyncAt32Slots(t *testing.T) {
	h := newXDPBumHelper(t)
	uplinks := make([]uint32, BumPlanMaxUplinks+1)
	for i := range uplinks {
		uplinks[i] = dummyIfindex(t, fmt.Sprintf("bum32-u%d", i))
	}
	// Peer i leaves through uplink i % spread.
	spread := BumPlanMaxUplinks
	s := NewBumDevmapSync(h.objs, func(uint16) uint8 { return BumModeXDP }, func(q UplinkQuery) (BumUplink, error) {
		return BumUplink{Ifindex: uplinks[int(q.Dst[15])%spread]}, nil
	}, zap.NewNop())
	h.mapOps.SetBumDevmapSync(s)
	t.Cleanup(func() { h.mapOps.SetBumDevmapSync(nil) })
	h.bumAC(1)
	ac2 := dummyIfindex(t, "bum32-ac")
	h.bumAC(ac2)

	var noESI [ESILen]byte
	for i := range uint16(MaxBumNexthops) {
		seg := lastSegment(i)
		e := &HeadendEntry{Mode: uint8(l2EncapMode), NumSegments: 1}
		copy(e.Segments[0][:], seg.To16())
		if err := h.mapOps.CreateBdPeer(bumTestBD, i, e, noESI, [IPv6AddrLen]byte{}, false); err != nil {
			t.Fatalf("peer %d: %v", i, err)
		}
	}
	flood := devmapEntries(t, h.objs.BumFloodMap, bumTestBD)
	if len(flood) != 2+MaxBumNexthops {
		t.Fatalf("flood devmap has %d entries, want 2 ACs and %d slots", len(flood), MaxBumNexthops)
	}
	if got := innerMaxEntries(t, h.objs.BumFloodMap, bumTestBD); got != 64 {
		t.Errorf("flood devmap of 34 entries is sized %d, want 64", got)
	}
	if got := innerMaxEntries(t, h.objs.BumLocalMap, bumTestBD); got != bumDevmapMinEntries {
		t.Errorf("local devmap of 2 ACs is sized %d, want %d", got, bumDevmapMinEntries)
	}
	if sl := bumSlotsOf(t, h.objs, bumTestBD); sl.Mask != 0xffffffff {
		t.Errorf("bum_slots mask = %#x, want all 32", sl.Mask)
	}

	// The 33rd flood peer has no slot.
	e := &HeadendEntry{Mode: uint8(l2EncapMode), NumSegments: 1}
	if _, err := h.mapOps.CreateBdPeerAtFreeIndex(bumTestBD, e, noESI, [IPv6AddrLen]byte{1}, true); err == nil {
		t.Error("a 33rd flood peer was accepted")
	}

	// Nine uplinks: more than a plan holds.
	spread = BumPlanMaxUplinks + 1
	if err := s.SyncBD(bumTestBD); err != nil {
		t.Fatal(err)
	}
	if devmapEntries(t, h.objs.BumFloodMap, bumTestBD) != nil {
		t.Error("a BD of nine uplinks kept a devmap")
	}
	if reason := s.unserved[bumTestBD]; reason == "" {
		t.Error("the BD is not recorded as falling back")
	}
	if sl := bumSlotsOf(t, h.objs, bumTestBD); sl != (BpfBumSlots{}) {
		t.Errorf("bum_slots of a BD without devmap = %+v, want none", sl)
	}
	spread = BumPlanMaxUplinks
	if err := s.SyncBD(bumTestBD); err != nil {
		t.Fatal(err)
	}
	if len(devmapEntries(t, h.objs.BumFloodMap, bumTestBD)) != 2+MaxBumNexthops {
		t.Error("back at eight uplinks, the BD has no full devmap")
	}
	if _, ok := s.unserved[bumTestBD]; ok {
		t.Error("the BD still counts as falling back")
	}
}
