package bpf

import (
	"testing"
)

// UpdateBdPeersOwned rewrites the forward entries in place and leaves the
// reverse map alone: two peers sharing one reverse key keep it with the
// peer that holds it. A slot that is gone is reported, not recreated.
func TestUpdateBdPeersOwned(t *testing.T) {
	h := newXDPTestHelper(t)
	m := h.mapOps
	owner := OwnerBGPEVPN(65000)
	remote, _ := ParseIPv6("fc00:4::")
	esi, _ := ParseESI("01:02:03:04:05:06:07:08:09:0a")
	oldSrc, _ := ParseIPv6("fc00:1::")
	newSrc, _ := ParseIPv6("fc00:9::")
	for i := uint16(0); i < 2; i++ {
		e := &HeadendEntry{Mode: 1, NumSegments: 1, SrcAddr: oldSrc}
		if err := m.CreateBdPeerOwned(100, i, e, esi, remote, true, owner); err != nil {
			t.Fatalf("CreateBdPeerOwned(%d): %v", i, err)
		}
	}
	rKey := &BdPeerReverseKey{BdId: 100, SrcAddr: remote}
	var rVal BdPeerReverseVal
	if err := h.objs.BdPeerReverseMap.Lookup(rKey, &rVal); err != nil || rVal.Index != 1 {
		t.Fatalf("setup: reverse entry = %+v, %v; want index 1", rVal, err)
	}

	errs := m.UpdateBdPeersOwned(100, []BdPeerUpdate{
		{Index: 1, Entry: &HeadendEntry{Mode: 1, NumSegments: 1, SrcAddr: newSrc}, ESI: esi},
		{Index: 0, Entry: &HeadendEntry{Mode: 1, NumSegments: 1, SrcAddr: newSrc}, ESI: esi},
		{Index: 7, Entry: &HeadendEntry{Mode: 1, NumSegments: 1, SrcAddr: newSrc}, ESI: esi},
	}, owner)
	if errs[0] != nil || errs[1] != nil {
		t.Fatalf("updates of present peers failed: %v", errs)
	}
	if errs[2] == nil {
		t.Error("update of an absent slot succeeded")
	}
	var absent HeadendEntry
	if err := h.objs.BdPeerMap.Lookup(&BdPeerKey{BdId: 100, Index: 7}, &absent); err == nil {
		t.Error("update recreated an absent slot")
	}
	for i := uint16(0); i < 2; i++ {
		var got HeadendEntry
		if err := h.objs.BdPeerMap.Lookup(&BdPeerKey{BdId: 100, Index: i}, &got); err != nil {
			t.Fatalf("lookup peer %d: %v", i, err)
		}
		if got.SrcAddr != newSrc {
			t.Errorf("peer %d source = %x, want %x", i, got.SrcAddr, newSrc)
		}
	}
	if err := h.objs.BdPeerReverseMap.Lookup(rKey, &rVal); err != nil || rVal.Index != 1 {
		t.Errorf("reverse entry after the updates = %+v, %v; want it still at index 1", rVal, err)
	}
	var ext BpfBdPeerL2ExtVal
	if err := h.objs.BdPeerL2ExtMap.Lookup(&BpfBdPeerL2ExtKey{BdId: 100, Index: 0}, &ext); err != nil || ext.Esi != esi {
		t.Errorf("ESI side entry after the update = %+v, %v; want %x", ext, err, esi)
	}
}
