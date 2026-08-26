package bpf

import (
	"encoding/binary"
	"net"
	"testing"

	vinberov1 "github.com/takehaya/vinbero/api/vinbero/v1"
)

// End / End.X with REPLACE-CSID (RFC 9800 Sec.4.2) data-plane tests.
//
// Layout used throughout (LNFL=32, K=4 unless noted): 48-bit locator
// block fd00:aabb:ccdd, 32-bit C-SID, so the trigger prefix is /80 and
// the DA's low 2 bits carry the container index. Packed containers are
// encoded as 16-byte segment list entries with position 0 in the most
// significant bytes.
const (
	actionEndReplace  = uint8(vinberov1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_REPLACE)
	actionEndXReplace = uint8(vinberov1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_X_REPLACE)

	replBlockBytes = uint8(6)
)

func (h *xdpTestHelper) createSidFunctionReplace(prefix string, action uint8, flavor uint8, nexthop [16]byte, csidLen uint8) {
	h.t.Helper()
	entry := &SidFunctionEntry{Action: action, Flavor: flavor}
	aux := NewSidAuxReplace(nexthop, replBlockBytes, csidLen)
	if err := h.mapOps.CreateSidFunction(prefix, entry, aux, OwnerRPC); err != nil {
		h.t.Fatalf("Failed to create SID function entry: %v", err)
	}
}

// mkContainer32 builds a packed container for LNFL=32: pos0 lands in the
// most significant 4 bytes (IETF bit order), pos3 in the least.
func mkContainer32(pos0, pos1, pos2, pos3 uint32) net.IP {
	b := make([]byte, 16)
	binary.BigEndian.PutUint32(b[0:], pos0)
	binary.BigEndian.PutUint32(b[4:], pos1)
	binary.BigEndian.PutUint32(b[8:], pos2)
	binary.BigEndian.PutUint32(b[12:], pos3)
	return net.IP(b)
}

// replDA builds a DA for the /80 entry: block + csid + zero argument with
// the index in the low bits of byte 15.
func replDA(csid uint32, idx uint8) net.IP {
	b := make([]byte, 16)
	copy(b, []byte{0xfd, 0x00, 0xaa, 0xbb, 0xcc, 0xdd})
	binary.BigEndian.PutUint32(b[6:], csid)
	b[15] = idx
	return net.IP(b)
}

func TestXDPProgEndReplace(t *testing.T) {
	h := newXDPTestHelper(t)
	h.createSidFunctionReplace("fd00:aabb:ccdd:1111:2222::/80", actionEndReplace, 0, [16]byte{}, 4)

	src := net.ParseIP("fd00:1:1::1")

	t.Run("walk within a container", func(t *testing.T) {
		// idx=2: read SegList[SL=1][1], replace the C-SID, idx becomes 1.
		// SL and the SRH stay untouched.
		segs := []net.IP{
			mkContainer32(0, 0, 0, 0),                                  // SegList[0], unused this hop
			mkContainer32(0x510500aa, 0x510500bb, 0x510500cc, 0x510500dd), // SegList[1], current
		}
		pkt, err := buildSRv6Packet(src, replDA(0x11112222, 2), segs, 1)
		if err != nil {
			t.Fatal(err)
		}
		ret, out := h.run(pkt)
		if ret != XDP_DROP {
			t.Errorf("expected fail-closed XDP_DROP (FIB miss), got %d", ret)
		}
		if got, want := outPktDA(t, out), replDA(0x510500bb, 1); !got.Equal(want) {
			t.Errorf("DA = %v, want %v", got, want)
		}
		if out[ethHeaderLen+ipv6HeaderLen+3] != 1 {
			t.Errorf("segments_left mutated to %d, want 1", out[ethHeaderLen+ipv6HeaderLen+3])
		}
		if hl := outPktHopLimit(t, out); hl != 63 {
			t.Errorf("hop limit = %d, want 63", hl)
		}
	})

	t.Run("cross into the next container", func(t *testing.T) {
		// idx=0: SL 1 -> 0, idx wraps to K-1=3 and the C-SID comes from
		// the new container's least significant position.
		segs := []net.IP{
			mkContainer32(0x52060011, 0x52060022, 0x52060033, 0x52060044), // becomes current
			mkContainer32(0, 0, 0, 0),
		}
		pkt, err := buildSRv6Packet(src, replDA(0x11112222, 0), segs, 1)
		if err != nil {
			t.Fatal(err)
		}
		ret, out := h.run(pkt)
		if ret != XDP_DROP {
			t.Errorf("expected fail-closed XDP_DROP, got %d", ret)
		}
		if got, want := outPktDA(t, out), replDA(0x52060044, 3); !got.Equal(want) {
			t.Errorf("DA = %v, want %v", got, want)
		}
		if out[ethHeaderLen+ipv6HeaderLen+3] != 0 {
			t.Errorf("segments_left = %d, want 0", out[ethHeaderLen+ipv6HeaderLen+3])
		}
	})

	t.Run("early container end loads the next full SID", func(t *testing.T) {
		// idx=2 but SegList[1][1] == 0: R06-R10 replaces the whole DA
		// with SegList[0] (a fully formed SID, not a packed container).
		next := net.ParseIP("fd00:9:9::99")
		segs := []net.IP{
			next,
			mkContainer32(0x510500aa, 0, 0x510500cc, 0x510500dd),
		}
		pkt, err := buildSRv6Packet(src, replDA(0x11112222, 2), segs, 1)
		if err != nil {
			t.Fatal(err)
		}
		ret, out := h.run(pkt)
		if ret != XDP_DROP {
			t.Errorf("expected fail-closed XDP_DROP, got %d", ret)
		}
		if got := outPktDA(t, out); !got.Equal(next) {
			t.Errorf("DA = %v, want %v (full SID load)", got, next)
		}
		if out[ethHeaderLen+ipv6HeaderLen+3] != 0 {
			t.Errorf("segments_left = %d, want 0", out[ethHeaderLen+ipv6HeaderLen+3])
		}
	})

	t.Run("terminal with index zero passes up", func(t *testing.T) {
		segs := []net.IP{mkContainer32(0, 0, 0, 0)}
		pkt, err := buildSRv6Packet(src, replDA(0x11112222, 0), segs, 0)
		if err != nil {
			t.Fatal(err)
		}
		ret, out := h.run(pkt)
		if ret != XDP_PASS {
			t.Errorf("expected XDP_PASS, got %d", ret)
		}
		if got, want := outPktDA(t, out), replDA(0x11112222, 0); !got.Equal(want) {
			t.Errorf("DA = %v, want %v (untouched)", got, want)
		}
	})

	t.Run("terminal via zero C-SID below the index passes up", func(t *testing.T) {
		// SL=0, idx=2, SegList[0][1] == 0: S02's second disjunct.
		segs := []net.IP{mkContainer32(0x510500aa, 0, 0x510500cc, 0x510500dd)}
		pkt, err := buildSRv6Packet(src, replDA(0x11112222, 2), segs, 0)
		if err != nil {
			t.Fatal(err)
		}
		ret, out := h.run(pkt)
		if ret != XDP_PASS {
			t.Errorf("expected XDP_PASS, got %d", ret)
		}
		if got, want := outPktDA(t, out), replDA(0x11112222, 2); !got.Equal(want) {
			t.Errorf("DA = %v, want %v (untouched)", got, want)
		}
	})

	t.Run("hop limit exhausted drops before any mutation", func(t *testing.T) {
		segs := []net.IP{
			mkContainer32(0, 0, 0, 0),
			mkContainer32(0x510500aa, 0x510500bb, 0x510500cc, 0x510500dd),
		}
		pkt, err := buildSRv6Packet(src, replDA(0x11112222, 2), segs, 1)
		if err != nil {
			t.Fatal(err)
		}
		pkt[ethHeaderLen+7] = 1 // hop limit
		ret, out := h.run(pkt)
		if ret != XDP_DROP {
			t.Errorf("expected XDP_DROP, got %d", ret)
		}
		if got, want := outPktDA(t, out), replDA(0x11112222, 2); !got.Equal(want) {
			t.Errorf("DA = %v, want %v (unmutated)", got, want)
		}
	})

	t.Run("inflated last entry beyond the declared SRH drops", func(t *testing.T) {
		// A short SRH whose first_segment points past its Hdr Ext Len
		// must not let payload bytes be read as C-SIDs.
		segs := []net.IP{mkContainer32(0x510500aa, 0x510500bb, 0x510500cc, 0x510500dd)}
		pkt, err := buildSRv6Packet(src, replDA(0x11112222, 2), segs, 0)
		if err != nil {
			t.Fatal(err)
		}
		pkt[ethHeaderLen+ipv6HeaderLen+4] = 5 // first_segment, but hdrlen covers 1 entry
		ret, out := h.run(pkt)
		if ret != XDP_DROP {
			t.Errorf("expected XDP_DROP, got %d", ret)
		}
		if got, want := outPktDA(t, out), replDA(0x11112222, 2); !got.Equal(want) {
			t.Errorf("DA = %v, want %v (unmutated)", got, want)
		}
	})

	t.Run("terminal non-tunnel payload with USD passes up", func(t *testing.T) {
		// RFC 8986 Sec.4.16.3: USD decaps tunnelled payloads only; a plain
		// ICMPv6 terminal packet keeps normal upper-layer processing.
		h2 := newXDPTestHelper(t)
		h2.createSidFunctionReplace("fd00:aabb:ccdd:1111:2222::/80", actionEndReplace, flavorUSD, [16]byte{}, 4)
		segs := []net.IP{mkContainer32(0, 0, 0, 0)}
		pkt, err := buildSRv6Packet(src, replDA(0x11112222, 0), segs, 0)
		if err != nil {
			t.Fatal(err)
		}
		ret, _ := h2.run(pkt)
		if ret != XDP_PASS {
			t.Errorf("expected XDP_PASS, got %d", ret)
		}
	})

	t.Run("segments_left beyond last entry drops", func(t *testing.T) {
		segs := []net.IP{mkContainer32(0x510500aa, 0x510500bb, 0x510500cc, 0x510500dd)}
		pkt, err := buildSRv6Packet(src, replDA(0x11112222, 2), segs, 3)
		if err != nil {
			t.Fatal(err)
		}
		ret, _ := h.run(pkt)
		if ret != XDP_DROP {
			t.Errorf("expected XDP_DROP, got %d", ret)
		}
	})
}

// PSP at the R09 insertion point: a zero C-SID ends the container early,
// the next entry is loaded as a full 128-bit SID, and since it is the
// last segment (nsl == 0) the SRH is popped around it.
func TestXDPProgEndReplacePSPEarlyContainerEnd(t *testing.T) {
	h := newXDPTestHelper(t)
	h.createSidFunctionReplace("fd00:aabb:ccdd:1111:2222::/80", actionEndReplace, flavorPSP, [16]byte{}, 4)

	next := net.ParseIP("fd00:9:9::99")
	segs := []net.IP{
		next,
		mkContainer32(0x510500aa, 0, 0x510500cc, 0x510500dd), // SegList[1][1] == 0
	}
	pkt, err := buildSRv6Packet(net.ParseIP("fd00:1:1::1"), replDA(0x11112222, 2), segs, 1)
	if err != nil {
		t.Fatal(err)
	}
	ret, out := h.run(pkt)
	if ret != XDP_DROP {
		t.Errorf("expected fail-closed XDP_DROP, got %d", ret)
	}
	if got := outPktDA(t, out); !got.Equal(next) {
		t.Errorf("DA = %v, want %v (full SID load)", got, next)
	}
	if nh := out[ethHeaderLen+6]; nh == 43 {
		t.Errorf("SRH still present after PSP (nexthdr=%d)", nh)
	}
}

// A zero C-SID in position K-1 of the next container is the reserved
// terminator where a well-formed sequence always has its first C-SID:
// the cross path must drop without advancing anything.
func TestXDPProgEndReplaceZeroFirstCsidDrops(t *testing.T) {
	h := newXDPTestHelper(t)
	h.createSidFunctionReplace("fd00:aabb:ccdd:1111:2222::/80", actionEndReplace, 0, [16]byte{}, 4)

	segs := []net.IP{
		mkContainer32(0x52060011, 0x52060022, 0x52060033, 0), // K-1 (first C-SID) zero
		mkContainer32(0, 0, 0, 0),
	}
	pkt, err := buildSRv6Packet(net.ParseIP("fd00:1:1::1"), replDA(0x11112222, 0), segs, 1)
	if err != nil {
		t.Fatal(err)
	}
	ret, out := h.run(pkt)
	if ret != XDP_DROP {
		t.Errorf("expected XDP_DROP, got %d", ret)
	}
	if got, want := outPktDA(t, out), replDA(0x11112222, 0); !got.Equal(want) {
		t.Errorf("DA = %v, want %v (unmutated)", got, want)
	}
	if out[ethHeaderLen+ipv6HeaderLen+3] != 1 {
		t.Errorf("segments_left = %d, want 1 (unmutated)", out[ethHeaderLen+ipv6HeaderLen+3])
	}
}

// Consecutive C-SIDs on the same node: an advance whose new DA matches
// another local entry cannot be reached by FIB self-forwarding, so it is
// re-dispatched to that entry's slot (like uN's shift loop). Two entries
// on one node walk two steps of the same container in a single pass.
func TestXDPProgEndReplaceSameNodeRedispatch(t *testing.T) {
	h := newXDPTestHelper(t)
	h.createSidFunctionReplace("fd00:aabb:ccdd:1111:2222::/80", actionEndReplace, 0, [16]byte{}, 4)
	h.createSidFunctionReplace("fd00:aabb:ccdd:3333:4444::/80", actionEndReplace, 0, [16]byte{}, 4)

	// DA = entry A, idx=2; SegList[0][1] = entry B's C-SID, [0][0] a
	// foreign C-SID. Execution 1 (A): idx->1, DA C-SID = B -> local
	// re-match, tail call into B. Execution 2 (B): idx->0, DA C-SID =
	// foreign -> FIB (miss, fail-closed drop). Two hop limits spent.
	segs := []net.IP{mkContainer32(0x510500aa, 0x33334444, 0, 0)}
	pkt, err := buildSRv6Packet(net.ParseIP("fd00:1:1::1"), replDA(0x11112222, 2), segs, 0)
	if err != nil {
		t.Fatal(err)
	}
	ret, out := h.run(pkt)
	if ret != XDP_DROP {
		t.Errorf("expected fail-closed XDP_DROP after both steps, got %d", ret)
	}
	if got, want := outPktDA(t, out), replDA(0x510500aa, 0); !got.Equal(want) {
		t.Errorf("DA = %v, want %v (replace at A, re-dispatch, replace at B)", got, want)
	}
	if hl := outPktHopLimit(t, out); hl != 62 {
		t.Errorf("hop limit = %d, want 62 (two logical hops)", hl)
	}
}

// The early-container-end full-SID load can also land on a local SID
// (Copilot round-3 finding): it must be re-dispatched, not FIB-dropped.
func TestXDPProgEndReplaceEarlyEndLandsOnLocalSid(t *testing.T) {
	h := newXDPTestHelper(t)
	h.createSidFunctionReplace("fd00:aabb:ccdd:1111:2222::/80", actionEndReplace, 0, [16]byte{}, 4)
	h.createSidFunctionReplace("fd00:aabb:ccdd:3333:4444::/80", actionEndReplace, 0, [16]byte{}, 4)

	// idx=2 but SegList[1][1]==0: load SegList[0] as the full next SID,
	// which is entry B's bare SID (idx=0, SL now 0) -> re-dispatch -> B
	// terminal -> XDP_PASS (local delivery).
	segs := []net.IP{
		net.ParseIP("fd00:aabb:ccdd:3333:4444::"),
		mkContainer32(0x510500aa, 0, 0x510500cc, 0x510500dd),
	}
	pkt, err := buildSRv6Packet(net.ParseIP("fd00:1:1::1"), replDA(0x11112222, 2), segs, 1)
	if err != nil {
		t.Fatal(err)
	}
	ret, out := h.run(pkt)
	if ret != XDP_PASS {
		t.Errorf("expected XDP_PASS (terminal at the loaded local SID), got %d", ret)
	}
	if got, want := outPktDA(t, out), net.ParseIP("fd00:aabb:ccdd:3333:4444::"); !got.Equal(want) {
		t.Errorf("DA = %v, want %v", got, want)
	}
}

// PSP fires before a same-node re-dispatch: the pop is the advancing
// entry's own step, so the next entry receives the packet already
// SRH-less and is dispatched on the no-SRH contract.
func TestXDPProgEndReplacePSPThenSameNodeTerminal(t *testing.T) {
	h := newXDPTestHelper(t)
	h.createSidFunctionReplace("fd00:aabb:ccdd:1111:2222::/80", actionEndReplace, flavorPSP, [16]byte{}, 4)
	h.createSidFunctionReplace("fd00:aabb:ccdd:3333:4444::/80", actionEndReplace, 0, [16]byte{}, 4)

	// SL=0, idx=1 at A: advance reads SegList[0][0] = B, idx becomes 0,
	// R20.1 holds (SL==0 && idx==0) so A pops the SRH, then the local
	// re-match hands the bare packet to B, whose terminal passes it up.
	segs := []net.IP{mkContainer32(0x33334444, 0, 0, 0)}
	pkt, err := buildSRv6Packet(net.ParseIP("fd00:1:1::1"), replDA(0x11112222, 1), segs, 0)
	if err != nil {
		t.Fatal(err)
	}
	ret, out := h.run(pkt)
	if ret != XDP_PASS {
		t.Errorf("expected XDP_PASS (terminal at B after the pop), got %d", ret)
	}
	if got, want := outPktDA(t, out), replDA(0x33334444, 0); !got.Equal(want) {
		t.Errorf("DA = %v, want %v", got, want)
	}
	if nh := out[ethHeaderLen+6]; nh == 43 {
		t.Errorf("SRH still present after PSP (nexthdr=%d)", nh)
	}
}

func TestXDPProgEndReplacePSP(t *testing.T) {
	h := newXDPTestHelper(t)
	h.createSidFunctionReplace("fd00:aabb:ccdd:1111:2222::/80", actionEndReplace, flavorPSP, [16]byte{}, 4)

	// SL=0, idx=1: not terminal (SegList[0][0] != 0). The execution
	// replaces the C-SID, idx becomes 0, and R20.1 (SL==0 && idx==0)
	// pops the SRH.
	segs := []net.IP{mkContainer32(0x510500aa, 0, 0, 0)}
	pkt, err := buildSRv6Packet(net.ParseIP("fd00:1:1::1"), replDA(0x11112222, 1), segs, 0)
	if err != nil {
		t.Fatal(err)
	}
	ret, out := h.run(pkt)
	if ret != XDP_DROP {
		t.Errorf("expected fail-closed XDP_DROP, got %d", ret)
	}
	if got, want := outPktDA(t, out), replDA(0x510500aa, 0); !got.Equal(want) {
		t.Errorf("DA = %v, want %v", got, want)
	}
	if nh := out[ethHeaderLen+6]; nh == 43 {
		t.Errorf("SRH still present after PSP (nexthdr=%d)", nh)
	}
}

func TestXDPProgEndXReplace(t *testing.T) {
	h := newXDPTestHelper(t)
	var nexthop [16]byte
	copy(nexthop[:], net.ParseIP("fe80::1").To16())
	h.createSidFunctionReplace("fd00:aabb:ccdd:1111:2222::/80", actionEndXReplace, 0, nexthop, 4)

	// Same walk as End(REP), forwarded towards the aux nexthop
	// (fail-closed on the unresolved neighbour, like End.X / uA).
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
	if got, want := outPktDA(t, out), replDA(0x510500bb, 1); !got.Equal(want) {
		t.Errorf("DA = %v, want %v", got, want)
	}
}

func TestXDPProgEndReplaceCsid16(t *testing.T) {
	h := newXDPTestHelper(t)
	// LNFL=16: K=8, 3 index bits, C-SID at bytes [6..8), trigger /64.
	h.createSidFunctionReplace("fd00:aabb:ccdd:1111::/64", actionEndReplace, 0, [16]byte{}, 2)

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
	copy(want, da)
	binary.BigEndian.PutUint16(want[6:], 0xa0a4) // SegList[1][4]
	want[15] = 4
	if got := outPktDA(t, out); !got.Equal(want) {
		t.Errorf("DA = %v, want %v", got, want)
	}
}

// Terminal USD with the SRH present: SL=0 at a bare REPLACE SID with a
// tunnelled payload strips everything down to the inner packet
// (endpoint_handle_usd), exactly like classic End+USD.
func TestXDPProgEndReplaceUSDTerminal(t *testing.T) {
	h := newXDPTestHelper(t)
	h.createSidFunctionReplace("fd00:aabb:ccdd:1111:2222::/80", actionEndReplace, flavorUSD, [16]byte{}, 4)

	segs := []net.IP{replDA(0x11112222, 0)}
	pkt, err := buildEncapsulatedPacket(
		net.ParseIP("fd00:1:1::1"), replDA(0x11112222, 0), segs, 0,
		net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2"), innerTypeIPv6)
	if err != nil {
		t.Fatal(err)
	}
	ret, out := h.run(pkt)
	if ret == XDP_PASS {
		t.Errorf("expected XDP_REDIRECT or XDP_DROP after decap, got XDP_PASS")
	}
	if got, want := outPktDA(t, out), net.ParseIP("2001:db8::2"); !got.Equal(want) {
		t.Errorf("inner DA = %v, want %v (outer + SRH stripped)", got, want)
	}
}

// Terminal USP: the SRH is popped and the packet continues to the DA.
func TestXDPProgEndReplaceUSPTerminal(t *testing.T) {
	h := newXDPTestHelper(t)
	h.createSidFunctionReplace("fd00:aabb:ccdd:1111:2222::/80", actionEndReplace, flavorUSP, [16]byte{}, 4)

	segs := []net.IP{replDA(0x11112222, 0)}
	pkt, err := buildSRv6Packet(net.ParseIP("fd00:1:1::1"), replDA(0x11112222, 0), segs, 0)
	if err != nil {
		t.Fatal(err)
	}
	ret, out := h.run(pkt)
	if ret != XDP_PASS {
		t.Errorf("expected XDP_PASS (post-strip FIB miss on lo), got %d", ret)
	}
	if nh := out[ethHeaderLen+6]; nh == 43 {
		t.Errorf("SRH still present after USP (nexthdr=%d)", nh)
	}
	if got, want := outPktDA(t, out), replDA(0x11112222, 0); !got.Equal(want) {
		t.Errorf("DA = %v, want %v (unchanged)", got, want)
	}
}

func TestXDPProgEndReplaceUSDNoSrh(t *testing.T) {
	h := newXDPTestHelper(t)
	h.createSidFunctionReplace("fd00:aabb:ccdd:1111:2222::/80", actionEndReplace, flavorUSD, [16]byte{}, 4)

	// A bare REPLACE SID as the last C-SID of a reduced-encaps packet:
	// no SRH, tunnelled payload, USD decaps. The nonzero index is ignored
	// (RFC 9800 Sec.4.2: without an SRH the Argument is not processed).
	pkt, err := buildEncapsulatedPacketNoSRH(
		net.ParseIP("fd00:1:1::1"), replDA(0x11112222, 2),
		net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2"), innerTypeIPv6)
	if err != nil {
		t.Fatal(err)
	}
	ret, out := h.run(pkt)
	if ret == XDP_PASS {
		t.Errorf("expected XDP_REDIRECT or XDP_DROP, got XDP_PASS")
	}
	if got, want := outPktDA(t, out), net.ParseIP("2001:db8::2"); !got.Equal(want) {
		t.Errorf("inner DA = %v, want %v (decapped)", got, want)
	}
}
