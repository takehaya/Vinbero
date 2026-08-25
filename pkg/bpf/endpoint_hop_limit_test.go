package bpf

import (
	"net"
	"testing"

	vinberov1 "github.com/takehaya/vinbero/api/vinbero/v1"
)

// hop limit lives at byte 7 of the IPv6 header.
func pktHopLimit(t *testing.T, pkt []byte) uint8 {
	t.Helper()
	if len(pkt) < ethHeaderLen+ipv6HeaderLen {
		t.Fatalf("packet too short: %d", len(pkt))
	}
	return pkt[ethHeaderLen+7]
}

func setPktHopLimit(t *testing.T, pkt []byte, hl uint8) {
	t.Helper()
	if len(pkt) < ethHeaderLen+ipv6HeaderLen {
		t.Fatalf("packet too short: %d", len(pkt))
	}
	pkt[ethHeaderLen+7] = hl
}

func endTestPacket(t *testing.T, segmentsLeft uint8) []byte {
	t.Helper()
	segs := []net.IP{net.ParseIP("fd00:1:100::3"), net.ParseIP("fd00:1:100::2")}
	pkt, err := buildSRv6Packet(net.ParseIP("fd00:1:1::1"), net.ParseIP("fd00:1:100::2"), segs, segmentsLeft)
	if err != nil {
		t.Fatalf("build packet: %v", err)
	}
	return pkt
}

// Advancing the segment list makes this node a hop on the path, and RFC
// 8986 S12 spends a hop limit on it -- but only when the packet leaves
// through an interface. In BPF_PROG_TEST_RUN the FIB lookup never resolves,
// so the packet goes to the kernel, whose own forwarding spends the hop
// instead; the header has to arrive there unchanged. The redirect case is
// what the netns examples exercise.
func TestEndpointHopLimit_GivenBackWhenTheKernelTakesOver(t *testing.T) {
	h := newXDPTestHelper(t)
	h.createSidFunction("fd00:1:100::2/128", actionEnd)

	ret, out := h.run(endTestPacket(t, 1))
	if ret != XDP_PASS {
		t.Fatalf("action = %d, want XDP_PASS (FIB miss on lo)", ret)
	}
	if got := pktHopLimit(t, out); got != 64 {
		t.Errorf("hop limit = %d, want 64 (the kernel spends the hop)", got)
	}
	// The segment list still advanced: this is the forwarding path.
	if got, want := net.IP(out[ethHeaderLen+24:ethHeaderLen+40]), net.ParseIP("fd00:1:100::3"); !got.Equal(want) {
		t.Errorf("DA = %v, want %v", got, want)
	}
}

// RFC 8986 S05: an exhausted hop limit stops the packet here. Vinbero drops
// without the ICMPv6 Time Exceeded the pseudocode asks for, and the segment
// list must not have moved.
func TestEndpointHopLimit_ExhaustedDropsBeforeTheSegmentListMoves(t *testing.T) {
	h := newXDPTestHelper(t)
	h.createSidFunction("fd00:1:100::2/128", actionEnd)

	pkt := endTestPacket(t, 1)
	setPktHopLimit(t, pkt, 1)
	ret, out := h.run(pkt)
	if ret != XDP_DROP {
		t.Errorf("action = %d, want XDP_DROP", ret)
	}
	if got, want := net.IP(out[ethHeaderLen+24:ethHeaderLen+40]), net.ParseIP("fd00:1:100::2"); !got.Equal(want) {
		t.Errorf("DA = %v, want %v (untouched)", got, want)
	}
	if got := pktHopLimit(t, out); got != 1 {
		t.Errorf("hop limit = %d, want 1 (untouched)", got)
	}
}

// The last segment is not a forwarding hop: the packet is handed to the
// upper layer, so the hop limit stays as it arrived.
func TestEndpointHopLimit_UntouchedOnTheLastSegment(t *testing.T) {
	h := newXDPTestHelper(t)
	h.createSidFunction("fd00:1:100::2/128", actionEnd)

	ret, out := h.run(endTestPacket(t, 0))
	if ret != XDP_PASS {
		t.Errorf("action = %d, want XDP_PASS", ret)
	}
	if got := pktHopLimit(t, out); got != 64 {
		t.Errorf("hop limit = %d, want 64 (untouched)", got)
	}
}

// End.X shares the same path, so it checks the hop limit the same way.
func TestEndpointHopLimit_EndXStopsOnAnExhaustedHopLimit(t *testing.T) {
	h := newXDPTestHelper(t)
	var nexthop [16]byte
	copy(nexthop[:], net.ParseIP("fe80::1").To16())
	h.createSidFunctionWithNexthop("fd00:1:100::2/128", actionEndX, nexthop)

	ret, out := h.run(endTestPacket(t, 1))
	if ret != XDP_PASS {
		t.Fatalf("action = %d, want XDP_PASS (FIB miss on lo)", ret)
	}
	if got := pktHopLimit(t, out); got != 64 {
		t.Errorf("hop limit = %d, want 64 (the kernel spends the hop)", got)
	}

	pkt := endTestPacket(t, 1)
	setPktHopLimit(t, pkt, 1)
	ret, _ = h.run(pkt)
	if ret != XDP_DROP {
		t.Errorf("action = %d, want XDP_DROP on an exhausted hop limit", ret)
	}
}

// End.AN runs process_end through its own slot, so it is in scope too.
func TestEndpointHopLimit_EndANStopsOnAnExhaustedHopLimit(t *testing.T) {
	h := newXDPTestHelper(t)
	h.createSidFunction("fd00:1:100::2/128", uint8(vinberov1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_AN))

	pkt := endTestPacket(t, 1)
	setPktHopLimit(t, pkt, 1)
	ret, _ := h.run(pkt)
	if ret != XDP_DROP {
		t.Errorf("action = %d, want XDP_DROP on an exhausted hop limit", ret)
	}
}
