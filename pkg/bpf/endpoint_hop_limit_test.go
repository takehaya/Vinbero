package bpf

import (
	"net"
	"testing"
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

// Advancing the segment list makes this node a hop on the path, so RFC 8986
// S12 spends a hop limit on it.
func TestEndpointHopLimit_DecrementedWhenTheSegmentListAdvances(t *testing.T) {
	h := newXDPTestHelper(t)
	h.createSidFunction("fd00:1:100::2/128", actionEnd)

	_, out := h.run(endTestPacket(t, 1))
	if got := pktHopLimit(t, out); got != 63 {
		t.Errorf("hop limit = %d, want 63", got)
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

// End.X shares the same path, and its cross-connect is just as much a hop.
func TestEndpointHopLimit_EndXAlsoSpendsAHop(t *testing.T) {
	h := newXDPTestHelper(t)
	var nexthop [16]byte
	copy(nexthop[:], net.ParseIP("fe80::1").To16())
	h.createSidFunctionWithNexthop("fd00:1:100::2/128", actionEndX, nexthop)

	_, out := h.run(endTestPacket(t, 1))
	if got := pktHopLimit(t, out); got != 63 {
		t.Errorf("hop limit = %d, want 63", got)
	}

	pkt := endTestPacket(t, 1)
	setPktHopLimit(t, pkt, 1)
	ret, _ := h.run(pkt)
	if ret != XDP_DROP {
		t.Errorf("action = %d, want XDP_DROP on an exhausted hop limit", ret)
	}
}
