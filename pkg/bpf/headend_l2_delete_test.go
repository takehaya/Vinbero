package bpf

import (
	"testing"

	vinberov1 "github.com/takehaya/vinbero/api/vinbero/v1"
)

func headendL2TestEntry(bd uint16) *HeadendEntry {
	return &HeadendEntry{
		Mode:        uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2),
		NumSegments: 1,
		BdId:        bd,
	}
}

// DeleteHeadendL2Where removes only the interfaces it selects, on every
// VLAN, and skips an entry that is already gone.
func TestDeleteHeadendL2Where(t *testing.T) {
	h := newXDPTestHelperWithStats(t)
	for _, c := range []struct {
		ifindex uint32
		vlan    uint16
	}{{12, 0}, {12, 5}, {11, 0}} {
		if err := h.mapOps.CreateHeadendL2(c.ifindex, c.vlan, headendL2TestEntry(100), [ESILen]byte{}); err != nil {
			t.Fatal(err)
		}
	}

	n, err := h.mapOps.DeleteHeadendL2Where(func(i uint32) bool { return i == 12 })
	if err != nil || n != 2 {
		t.Fatalf("DeleteHeadendL2Where = %d, %v; want 2, nil", n, err)
	}
	entries, err := h.mapOps.ListHeadendL2()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("%d entries left, want the one on ifindex 11: %v", len(entries), entries)
	}
	if n, err := h.mapOps.DeleteHeadendL2Where(func(i uint32) bool { return i == 12 }); err != nil || n != 0 {
		t.Errorf("second pass = %d, %v; want 0, nil", n, err)
	}
}

// bd_local_esi_map follows the BD's ACs: a plain AC created or removed leaves
// the ESI of an AC on a segment, and the entry goes only with the last AC on
// a segment.
func TestBdLocalEsiFollowsACs(t *testing.T) {
	h := newXDPTestHelperWithStats(t)
	const bd = uint16(100)
	esi := [ESILen]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	localESI := func() ([ESILen]byte, bool) {
		bdKey := uint32(bd)
		var got BpfBdLocalEsiVal
		if err := h.objs.BdLocalEsiMap.Lookup(&bdKey, &got); err != nil {
			return [ESILen]byte{}, false
		}
		return got.Esi, true
	}
	create := func(ifindex uint32, e [ESILen]byte) {
		t.Helper()
		if err := h.mapOps.CreateHeadendL2(ifindex, 0, headendL2TestEntry(bd), e); err != nil {
			t.Fatal(err)
		}
	}
	remove := func(ifindex uint32) {
		t.Helper()
		if err := h.mapOps.DeleteHeadendL2(ifindex, 0); err != nil {
			t.Fatal(err)
		}
	}
	want := func(stage string, wantSet bool) {
		t.Helper()
		got, ok := localESI()
		if ok != wantSet || (ok && got != esi) {
			t.Errorf("%s: local ESI = %x (set=%v), want set=%v", stage, got, ok, wantSet)
		}
	}

	create(1, esi)
	create(2, esi)
	create(3, [ESILen]byte{})
	want("a plain AC created beside segment ACs", true)
	remove(3)
	want("a plain AC removed", true)
	remove(1)
	want("one of two segment ACs removed", true)

	// The last segment AC becomes plain: nothing is left on the segment.
	create(2, [ESILen]byte{})
	want("the last segment AC recreated as plain", false)
	create(2, esi)
	want("the AC back on the segment", true)
	remove(2)
	want("the last segment AC removed", false)

	// An AC moving to another BD takes its ESI with it.
	create(4, esi)
	if err := h.mapOps.CreateHeadendL2(4, 0, headendL2TestEntry(200), [ESILen]byte{}); err != nil {
		t.Fatal(err)
	}
	want("the only segment AC moved away", false)
}

// The BD's ESI is the lowest-key AC's on a segment, whatever the order of the
// changes, so an unrelated plain AC cannot flip it.
func TestBdLocalEsiIsDeterministic(t *testing.T) {
	h := newXDPTestHelperWithStats(t)
	const bd = uint16(100)
	esiLow := [ESILen]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	esiHigh := [ESILen]byte{2, 2, 2, 2, 2, 2, 2, 2, 2, 2}
	local := func() [ESILen]byte {
		bdKey := uint32(bd)
		var got BpfBdLocalEsiVal
		if err := h.objs.BdLocalEsiMap.Lookup(&bdKey, &got); err != nil {
			t.Fatalf("local ESI: %v", err)
		}
		return got.Esi
	}
	create := func(ifindex uint32, e [ESILen]byte) {
		t.Helper()
		if err := h.mapOps.CreateHeadendL2(ifindex, 0, headendL2TestEntry(bd), e); err != nil {
			t.Fatal(err)
		}
	}
	create(5, esiHigh)
	create(2, esiLow) // the lower key wins, not the last write
	if local() != esiLow {
		t.Errorf("local ESI = %x, want the lowest-key AC's", local())
	}
	create(9, [ESILen]byte{})
	if local() != esiLow {
		t.Errorf("a plain AC flipped the local ESI to %x", local())
	}
	create(5, esiHigh) // rewriting a higher-key AC leaves it too
	if local() != esiLow {
		t.Errorf("rewriting another AC flipped the local ESI to %x", local())
	}
	if err := h.mapOps.DeleteHeadendL2(2, 0); err != nil {
		t.Fatal(err)
	}
	if local() != esiHigh {
		t.Errorf("after deleting the lowest AC: local ESI = %x", local())
	}
}

// A flush removes everything and still works after entries have gone.
func TestFlushHeadendL2(t *testing.T) {
	h := newXDPTestHelperWithStats(t)
	if err := h.mapOps.CreateHeadendL2(1, 0, headendL2TestEntry(0), [ESILen]byte{}); err != nil {
		t.Fatal(err)
	}
	if err := h.mapOps.CreateHeadendL2(2, 0, headendL2TestEntry(100), [ESILen]byte{}); err != nil {
		t.Fatal(err)
	}
	n, err := h.mapOps.FlushHeadendL2()
	if err != nil || n != 2 {
		t.Fatalf("FlushHeadendL2 = %d, %v; want 2, nil", n, err)
	}
}
