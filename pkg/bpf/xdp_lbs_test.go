package bpf

import (
	"encoding/binary"
	"net"
	"testing"
)

// End.LBS / End.XLBS (RFC 9800 Sec.7) data-plane tests. The behaviors run
// in the uN/uA/REPLACE slots with the target locator block carried in the
// aux; a non-zero target makes the advance compose the new DA on that
// block instead of in place.

func (h *xdpTestHelper) createSidFunctionLbs(prefix string, action uint8, nexthop [16]byte, blockLen, csidLen uint8, target net.IP, targetLen uint8) {
	h.t.Helper()
	entry := &SidFunctionEntry{Action: action}
	var aux *SidAuxEntry
	if csidLen != 0 {
		aux = NewSidAuxReplace(nexthop, blockLen, csidLen)
	} else {
		aux = NewSidAuxUsid(nexthop, blockLen)
	}
	var tgt [16]uint8
	copy(tgt[:], target.To16())
	NewSidAuxUsidTarget(aux, tgt, targetLen)
	if err := h.mapOps.CreateSidFunction(prefix, entry, aux, OwnerRPC); err != nil {
		h.t.Fatalf("Failed to create SID function entry: %v", err)
	}
}

func TestXDPProgEndLbs(t *testing.T) {
	h := newXDPTestHelper(t)
	// uN-shaped LBS at block fd00:aaaa, node bbbb; target block
	// fd77:7777:7777/48.
	h.createSidFunctionLbs("fd00:aaaa:bbbb::/48", actionEndUn, [16]byte{}, 4, 0, net.ParseIP("fd77:7777:7777::"), 6)

	src := net.ParseIP("fd00:1:1::1")

	t.Run("shift lands on the target block", func(t *testing.T) {
		// N05.1-N06: A = B2, Argument copied to [m..m+AL-1].
		pkt, err := buildUsidIPv6Packet(src, net.ParseIP("fd00:aaaa:bbbb:cccc:dddd::"), 64)
		if err != nil {
			t.Fatal(err)
		}
		ret, out := h.run(pkt)
		if ret != XDP_DROP {
			t.Errorf("expected fail-closed XDP_DROP (FIB miss), got %d", ret)
		}
		if got, want := outPktDA(t, out), net.ParseIP("fd77:7777:7777:cccc:dddd::"); !got.Equal(want) {
			t.Errorf("DA = %v, want %v (argument on the target block)", got, want)
		}
		if hl := outPktHopLimit(t, out); hl != 63 {
			t.Errorf("hop limit = %d, want 63", hl)
		}
	})

	t.Run("terminal is untouched by the target", func(t *testing.T) {
		// Argument zero falls through to classic End; the swap applies
		// only to the shift (N05-N06 replacement).
		pkt, err := buildUsidIPv6Packet(src, net.ParseIP("fd00:aaaa:bbbb::"), 64)
		if err != nil {
			t.Fatal(err)
		}
		ret, out := h.run(pkt)
		if ret != XDP_PASS {
			t.Errorf("expected XDP_PASS, got %d", ret)
		}
		if got, want := outPktDA(t, out), net.ParseIP("fd00:aaaa:bbbb::"); !got.Equal(want) {
			t.Errorf("DA = %v, want %v (untouched)", got, want)
		}
	})

	t.Run("swap into a local SID of the new block re-dispatches", func(t *testing.T) {
		// A /32 target block whose geometry matches the F3216 shape on
		// the other side: after the swap the first argument C-SID (cccc)
		// is the node selector in the new block, and this node's own uN
		// there must be handed the packet by the shift loop's re-lookup
		// instead of FIB-bouncing.
		h.createSidFunctionLbs("fd00:aaaa:cccc::/48", actionEndUn, [16]byte{}, 4, 0, net.ParseIP("fd77:7777::"), 4)
		h.createSidFunctionUsid("fd77:7777:cccc::/48", actionEndUn, 0, [16]byte{}, usidBlockLenBytes)
		pkt, err := buildUsidIPv6Packet(src, net.ParseIP("fd00:aaaa:cccc:cccc:dddd::"), 64)
		if err != nil {
			t.Fatal(err)
		}
		// LBS swap: DA -> fd77:7777:cccc:dddd::, which matches the new
		// block's uN (node cccc); that uN consumes dddd with one shift.
		ret, out := h.run(pkt)
		if ret != XDP_DROP {
			t.Errorf("expected fail-closed XDP_DROP after both steps, got %d", ret)
		}
		if got, want := outPktDA(t, out), net.ParseIP("fd77:7777:dddd::"); !got.Equal(want) {
			t.Errorf("DA = %v, want %v (LBS swap, then uN shift in the new block)", got, want)
		}
		if hl := outPktHopLimit(t, out); hl != 62 {
			t.Errorf("hop limit = %d, want 62 (two logical hops)", hl)
		}
	})
}

func TestXDPProgEndXlbs(t *testing.T) {
	h := newXDPTestHelper(t)
	var nexthop [16]byte
	copy(nexthop[:], net.ParseIP("fe80::1").To16())
	// uA-shaped XLBS (/64); target block fd77:7777:7777:7777/64.
	h.createSidFunctionLbs("fd00:aaaa:ffff:cccc::/64", actionEndUa, nexthop, 4, 0, net.ParseIP("fd77:7777:7777:7777::"), 8)

	pkt, err := buildUsidIPv6Packet(net.ParseIP("fd00:1:1::1"), net.ParseIP("fd00:aaaa:ffff:cccc:bbbb:dddd::"), 64)
	if err != nil {
		t.Fatal(err)
	}
	ret, out := h.run(pkt)
	if ret != XDP_DROP {
		t.Errorf("expected fail-closed XDP_DROP (unresolved adjacency), got %d", ret)
	}
	if got, want := outPktDA(t, out), net.ParseIP("fd77:7777:7777:7777:bbbb:dddd::"); !got.Equal(want) {
		t.Errorf("DA = %v, want %v (argument on the target block)", got, want)
	}
}

// A hand-installed entry with an out-of-range target length must fail
// closed, not alias to a shorter block through the verifier mask.
func TestXDPProgEndLbsBadTargetLenDrops(t *testing.T) {
	h := newXDPTestHelper(t)
	h.createSidFunctionLbs("fd00:aaaa:bbbb::/48", actionEndUn, [16]byte{}, 4, 0, net.ParseIP("fd77:7777:7777::"), 17)

	pkt, err := buildUsidIPv6Packet(net.ParseIP("fd00:1:1::1"), net.ParseIP("fd00:aaaa:bbbb:cccc::"), 64)
	if err != nil {
		t.Fatal(err)
	}
	ret, out := h.run(pkt)
	if ret != XDP_DROP {
		t.Errorf("expected XDP_DROP, got %d", ret)
	}
	// In particular the DA must not have been composed on a /8 block.
	if got, want := outPktDA(t, out), net.ParseIP("fd00:aaaa:bbbb:cccc::"); !got.Equal(want) {
		t.Errorf("DA = %v, want %v (unmutated)", got, want)
	}
}

// XLBS with REPLACE-CSID: the R20 composition on the target block plus
// the adjacency forward (fail-closed on the unresolved neighbour).
func TestXDPProgEndXlbsReplace(t *testing.T) {
	h := newXDPTestHelper(t)
	var nexthop [16]byte
	copy(nexthop[:], net.ParseIP("fe80::1").To16())
	h.createSidFunctionLbs("fd00:aabb:ccdd:1111:2222::/80", actionEndXReplace, nexthop, 6, 4, net.ParseIP("fd77:7777:7777::"), 6)

	segs := []net.IP{
		mkContainer32(0, 0, 0, 0),
		mkContainer32(0x510500aa, 0x510500bb, 0x510500cc, 0x510500dd),
	}
	pkt, err := buildSRv6Packet(net.ParseIP("fd00:1:1::1"), replDA(0x11112222, 2), segs, 1)
	if err != nil {
		t.Fatal(err)
	}
	ret, out := h.run(pkt)
	if ret != XDP_DROP {
		t.Errorf("expected fail-closed XDP_DROP (unresolved adjacency), got %d", ret)
	}
	want := make(net.IP, 16)
	copy(want, net.ParseIP("fd77:7777:7777::").To16())
	binary.BigEndian.PutUint32(want[6:], 0x510500bb)
	want[15] = 1
	if got := outPktDA(t, out); !got.Equal(want) {
		t.Errorf("DA = %v, want %v", got, want)
	}
}

// LBS with the 16-bit LNFL variant: K=8, 3 index bits, and the C-SID
// lands at [m..m+2) of the target block.
func TestXDPProgEndLbsReplaceCsid16(t *testing.T) {
	h := newXDPTestHelper(t)
	h.createSidFunctionLbs("fd00:aabb:ccdd:1111::/64", actionEndReplace, [16]byte{}, 6, 2, net.ParseIP("fd77:7777:7777::"), 6)

	da := make(net.IP, 16)
	copy(da, []byte{0xfd, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x11})
	da[15] = 5 // idx
	container := make(net.IP, 16)
	for i := 0; i < 8; i++ {
		binary.BigEndian.PutUint16(container[i*2:], uint16(0xa0a0+i))
	}
	segs := []net.IP{mkContainer32(0, 0, 0, 0), container}
	pkt, err := buildSRv6Packet(net.ParseIP("fd00:1:1::1"), da, segs, 1)
	if err != nil {
		t.Fatal(err)
	}
	ret, out := h.run(pkt)
	if ret != XDP_DROP {
		t.Errorf("expected fail-closed XDP_DROP, got %d", ret)
	}
	want := make(net.IP, 16)
	copy(want, net.ParseIP("fd77:7777:7777::").To16())
	binary.BigEndian.PutUint16(want[6:], 0xa0a4) // SegList[1][4]
	want[15] = 4
	if got := outPktDA(t, out); !got.Equal(want) {
		t.Errorf("DA = %v, want %v", got, want)
	}
}

func TestXDPProgEndLbsReplace(t *testing.T) {
	h := newXDPTestHelper(t)
	// REPLACE-shaped LBS at block fd00:aabb:ccdd (/48+32 = /80); target
	// block fd77:7777:7777/48.
	h.createSidFunctionLbs("fd00:aabb:ccdd:1111:2222::/80", actionEndReplace, [16]byte{}, 6, 4, net.ParseIP("fd77:7777:7777::"), 6)

	// Walk step idx=2 -> 1 reads SegList[1][1]; R20.1-R20.4 compose the
	// DA on the target block: C-SID at [m..m+LNFL-1], index in the low
	// bits, nothing else carried over.
	segs := []net.IP{
		mkContainer32(0, 0, 0, 0),
		mkContainer32(0x510500aa, 0x510500bb, 0x510500cc, 0x510500dd),
	}
	pkt, err := buildSRv6Packet(net.ParseIP("fd00:1:1::1"), replDA(0x11112222, 2), segs, 1)
	if err != nil {
		t.Fatal(err)
	}
	ret, out := h.run(pkt)
	if ret != XDP_DROP {
		t.Errorf("expected fail-closed XDP_DROP, got %d", ret)
	}
	want := make(net.IP, 16)
	copy(want, net.ParseIP("fd77:7777:7777::").To16())
	binary.BigEndian.PutUint32(want[6:], 0x510500bb)
	want[15] = 1
	if got := outPktDA(t, out); !got.Equal(want) {
		t.Errorf("DA = %v, want %v (C-SID and index on the target block)", got, want)
	}
	if out[ethHeaderLen+ipv6HeaderLen+3] != 1 {
		t.Errorf("segments_left mutated to %d, want 1", out[ethHeaderLen+ipv6HeaderLen+3])
	}

	t.Run("container cross composes on the target block", func(t *testing.T) {
		// idx=0: SL 1 -> 0, idx wraps to K-1, and the next container's
		// least significant C-SID lands on the target block.
		segs := []net.IP{
			mkContainer32(0x52060011, 0x52060022, 0x52060033, 0x52060044),
			mkContainer32(0, 0, 0, 0),
		}
		pkt, err := buildSRv6Packet(net.ParseIP("fd00:1:1::1"), replDA(0x11112222, 0), segs, 1)
		if err != nil {
			t.Fatal(err)
		}
		ret, out := h.run(pkt)
		if ret != XDP_DROP {
			t.Errorf("expected fail-closed XDP_DROP, got %d", ret)
		}
		want := make(net.IP, 16)
		copy(want, net.ParseIP("fd77:7777:7777::").To16())
		binary.BigEndian.PutUint32(want[6:], 0x52060044)
		want[15] = 3
		if got := outPktDA(t, out); !got.Equal(want) {
			t.Errorf("DA = %v, want %v", got, want)
		}
		if out[ethHeaderLen+ipv6HeaderLen+3] != 0 {
			t.Errorf("segments_left = %d, want 0", out[ethHeaderLen+ipv6HeaderLen+3])
		}
	})
}
