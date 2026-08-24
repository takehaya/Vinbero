package bpf

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	vinberov1 "github.com/takehaya/vinbero/api/vinbero/v1"
)

// uN / uA (NEXT-C-SID, RFC 9800) data-plane tests.
const (
	actionEndUn = uint8(vinberov1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_UN)
	actionEndUa = uint8(vinberov1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_UA)

	usidBlockLenBytes = uint8(4) // F3216
)

func (h *xdpTestHelper) createSidFunctionUsid(prefix string, action uint8, flavor uint8, nexthop [16]byte, blockLenBytes uint8) {
	h.t.Helper()
	entry := &SidFunctionEntry{Action: action, Flavor: flavor}
	aux := NewSidAuxUsid(nexthop, blockLenBytes)
	if err := h.mapOps.CreateSidFunction(prefix, entry, aux, OwnerRPC); err != nil {
		h.t.Fatalf("Failed to create SID function entry: %v", err)
	}
}

// buildUsidIPv6Packet builds an SRH-less IPv6/ICMPv6 packet with an explicit
// hop limit.
func buildUsidIPv6Packet(srcIP, dstIP net.IP, hopLimit uint8) ([]byte, error) {
	eth := newTestEthernet(layers.EthernetTypeIPv6)
	ip6 := &layers.IPv6{
		Version: 6, SrcIP: srcIP, DstIP: dstIP,
		NextHeader: layers.IPProtocolICMPv6, HopLimit: hopLimit,
	}
	icmp, icmpEcho := newTestICMPv6Echo()
	_ = icmp.SetNetworkLayerForChecksum(ip6)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip6, icmp, icmpEcho, gopacket.Payload(newTestPayload(64))); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func outPktDA(t *testing.T, pkt []byte) net.IP {
	t.Helper()
	if len(pkt) < ethHeaderLen+ipv6HeaderLen {
		t.Fatalf("output packet too short: %d", len(pkt))
	}
	return net.IP(pkt[ethHeaderLen+24 : ethHeaderLen+40])
}

func outPktHopLimit(t *testing.T, pkt []byte) uint8 {
	t.Helper()
	return pkt[ethHeaderLen+7]
}

// The uN locator is fd00:aaaa:bbbb::/48: block fd00:aaaa (4 bytes), node
// uSID bbbb. In BPF_PROG_TEST_RUN the FIB lookup on loopback resolves to
// nothing forwardable, so the fail-closed shift path reports XDP_DROP; the
// mutated packet is still returned and carries the shift result.
func TestXDPProgEndUn(t *testing.T) {
	h := newXDPTestHelper(t)
	h.createSidFunctionUsid("fd00:aaaa:bbbb::/48", actionEndUn, 0, [16]byte{}, usidBlockLenBytes)

	src := net.ParseIP("fd00:1:1::1")

	t.Run("shift with SRH", func(t *testing.T) {
		segs := []net.IP{net.ParseIP("fd00:aaaa:bbbb:cccc::")}
		pkt, err := buildSRv6Packet(src, net.ParseIP("fd00:aaaa:bbbb:cccc::"), segs, 1)
		if err != nil {
			t.Fatal(err)
		}
		ret, out := h.run(pkt)
		if ret != XDP_DROP {
			t.Errorf("expected fail-closed XDP_DROP, got %d", ret)
		}
		if got, want := outPktDA(t, out), net.ParseIP("fd00:aaaa:cccc::"); !got.Equal(want) {
			t.Errorf("DA = %v, want %v (shifted)", got, want)
		}
		if hl := outPktHopLimit(t, out); hl != 63 {
			t.Errorf("hop limit = %d, want 63", hl)
		}
		// The SRH must be untouched on the shift path.
		if out[ethHeaderLen+ipv6HeaderLen+3] != 1 {
			t.Errorf("SRH segments_left mutated: %d", out[ethHeaderLen+ipv6HeaderLen+3])
		}
	})

	t.Run("shift without SRH", func(t *testing.T) {
		pkt, err := buildUsidIPv6Packet(src, net.ParseIP("fd00:aaaa:bbbb:cccc:dddd::"), 64)
		if err != nil {
			t.Fatal(err)
		}
		ret, out := h.run(pkt)
		if ret != XDP_DROP {
			t.Errorf("expected fail-closed XDP_DROP, got %d", ret)
		}
		if got, want := outPktDA(t, out), net.ParseIP("fd00:aaaa:cccc:dddd::"); !got.Equal(want) {
			t.Errorf("DA = %v, want %v (shifted)", got, want)
		}
	})

	t.Run("hop limit exhausted drops before shift", func(t *testing.T) {
		pkt, err := buildUsidIPv6Packet(src, net.ParseIP("fd00:aaaa:bbbb:cccc::"), 1)
		if err != nil {
			t.Fatal(err)
		}
		ret, out := h.run(pkt)
		if ret != XDP_DROP {
			t.Errorf("expected XDP_DROP, got %d", ret)
		}
		if got, want := outPktDA(t, out), net.ParseIP("fd00:aaaa:bbbb:cccc::"); !got.Equal(want) {
			t.Errorf("DA = %v, want %v (unshifted)", got, want)
		}
	})

	t.Run("consecutive own-node uSIDs shift in place", func(t *testing.T) {
		// bbbb appears twice: the first shift lands back on this node's uN
		// prefix and the loop must consume it without a FIB bounce.
		pkt, err := buildUsidIPv6Packet(src, net.ParseIP("fd00:aaaa:bbbb:bbbb:cccc::"), 64)
		if err != nil {
			t.Fatal(err)
		}
		ret, out := h.run(pkt)
		if ret != XDP_DROP {
			t.Errorf("expected fail-closed XDP_DROP, got %d", ret)
		}
		if got, want := outPktDA(t, out), net.ParseIP("fd00:aaaa:cccc::"); !got.Equal(want) {
			t.Errorf("DA = %v, want %v (double shift)", got, want)
		}
		if hl := outPktHopLimit(t, out); hl != 62 {
			t.Errorf("hop limit = %d, want 62 (two logical uN hops)", hl)
		}
	})

	t.Run("argument zero with SRH falls through to End", func(t *testing.T) {
		segs := []net.IP{net.ParseIP("fd00:9:9::1"), net.ParseIP("fd00:aaaa:bbbb::")}
		pkt, err := buildSRv6Packet(src, net.ParseIP("fd00:aaaa:bbbb::"), segs, 1)
		if err != nil {
			t.Fatal(err)
		}
		ret, out := h.run(pkt)
		if ret != XDP_PASS {
			t.Errorf("expected XDP_PASS (classic End on lo), got %d", ret)
		}
		verifyDAAndSL(t, out, "fd00:9:9::1", 1)
	})

	t.Run("argument zero without SRH passes to the kernel", func(t *testing.T) {
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

	t.Run("container ending on this node without SRH passes the shifted packet up", func(t *testing.T) {
		// Both uSIDs are this node's, so the loop consumes them and the DA
		// lands on the bare uN SID. There is no SRH left to process, so the
		// packet goes to the kernel for local delivery (RFC 8986 Sec.4.1) --
		// the one place a rewritten DA is handed up, and only because that
		// DA is this node's own SID. Pinned here so the invariant cannot be
		// widened by accident.
		pkt, err := buildUsidIPv6Packet(src, net.ParseIP("fd00:aaaa:bbbb:bbbb::"), 64)
		if err != nil {
			t.Fatal(err)
		}
		ret, out := h.run(pkt)
		if ret != XDP_PASS {
			t.Errorf("expected XDP_PASS, got %d", ret)
		}
		if got, want := outPktDA(t, out), net.ParseIP("fd00:aaaa:bbbb::"); !got.Equal(want) {
			t.Errorf("DA = %v, want %v (shifted down to the bare uN SID)", got, want)
		}
		if hl := outPktHopLimit(t, out); hl != 63 {
			t.Errorf("hop limit = %d, want 63 (one logical uN hop)", hl)
		}
	})

	t.Run("malformed SRH drops on the terminal path", func(t *testing.T) {
		// SL exceeds the segment list: endpoint_init must reject it.
		segs := []net.IP{net.ParseIP("fd00:9:9::1")}
		pkt, err := buildSRv6Packet(src, net.ParseIP("fd00:aaaa:bbbb::"), segs, 5)
		if err != nil {
			t.Fatal(err)
		}
		ret, _ := h.run(pkt)
		if ret != XDP_DROP {
			t.Errorf("expected XDP_DROP, got %d", ret)
		}
	})
}

func TestXDPProgEndUnPSP(t *testing.T) {
	h := newXDPTestHelper(t)
	h.createSidFunctionUsid("fd00:aaaa:eeee::/48", actionEndUn, flavorPSP, [16]byte{}, usidBlockLenBytes)

	// Terminal uSID + SL 1->0 with PSP: the classic End fall-through must
	// strip the SRH.
	segs := []net.IP{net.ParseIP("fd00:9:9::1"), net.ParseIP("fd00:aaaa:eeee::")}
	pkt, err := buildSRv6Packet(net.ParseIP("fd00:1:1::1"), net.ParseIP("fd00:aaaa:eeee::"), segs, 1)
	if err != nil {
		t.Fatal(err)
	}
	ret, out := h.run(pkt)
	if ret != XDP_PASS {
		t.Fatalf("expected XDP_PASS, got %d", ret)
	}
	if got, want := outPktDA(t, out), net.ParseIP("fd00:9:9::1"); !got.Equal(want) {
		t.Errorf("DA = %v, want %v", got, want)
	}
	if nh := out[ethHeaderLen+6]; nh == 43 {
		t.Errorf("SRH still present after PSP (nexthdr=%d)", nh)
	}
}

func TestXDPProgEndUa(t *testing.T) {
	h := newXDPTestHelper(t)
	var nexthop [16]byte
	copy(nexthop[:], net.ParseIP("fe80::1").To16())
	// uA lives at block + node + function (/64), the shape the API enforces.
	h.createSidFunctionUsid("fd00:aaaa:ffff:cccc::/64", actionEndUa, 0, nexthop, usidBlockLenBytes)

	t.Run("shift consumes node+function and forwards toward the aux nexthop", func(t *testing.T) {
		pkt, err := buildUsidIPv6Packet(net.ParseIP("fd00:1:1::1"), net.ParseIP("fd00:aaaa:ffff:cccc:dddd::"), 64)
		if err != nil {
			t.Fatal(err)
		}
		ret, out := h.run(pkt)
		if ret != XDP_DROP {
			t.Errorf("expected fail-closed XDP_DROP, got %d", ret)
		}
		// uA's Argument starts after /64, so one shift consumes 32 bits.
		if got, want := outPktDA(t, out), net.ParseIP("fd00:aaaa:dddd::"); !got.Equal(want) {
			t.Errorf("DA = %v, want %v (shifted)", got, want)
		}
	})

	t.Run("consecutive same uA shifts once per execution", func(t *testing.T) {
		// Container [uA, uA]: this execution must do exactly one shift and
		// forward over the adjacency; the second uA is consumed on re-entry,
		// not looped locally.
		pkt, err := buildUsidIPv6Packet(net.ParseIP("fd00:1:1::1"), net.ParseIP("fd00:aaaa:ffff:cccc:ffff:cccc::"), 64)
		if err != nil {
			t.Fatal(err)
		}
		ret, out := h.run(pkt)
		if ret != XDP_DROP {
			t.Errorf("expected fail-closed XDP_DROP, got %d", ret)
		}
		if got, want := outPktDA(t, out), net.ParseIP("fd00:aaaa:ffff:cccc::"); !got.Equal(want) {
			t.Errorf("DA = %v, want %v (single shift)", got, want)
		}
		if hl := outPktHopLimit(t, out); hl != 63 {
			t.Errorf("hop limit = %d, want 63 (exactly one uA execution)", hl)
		}
	})

	t.Run("argument zero falls through to classic End.X", func(t *testing.T) {
		segs := []net.IP{net.ParseIP("fd00:9:9::1"), net.ParseIP("fd00:aaaa:ffff:cccc::")}
		pkt, err := buildSRv6Packet(net.ParseIP("fd00:1:1::1"), net.ParseIP("fd00:aaaa:ffff:cccc::"), segs, 1)
		if err != nil {
			t.Fatal(err)
		}
		ret, out := h.run(pkt)
		if ret != XDP_PASS {
			t.Errorf("expected XDP_PASS (End.X FIB miss on lo), got %d", ret)
		}
		verifyDAAndSL(t, out, "fd00:9:9::1", 1)
	})
}

func TestXDPProgEndUnFullContainer(t *testing.T) {
	h := newXDPTestHelper(t)
	h.createSidFunctionUsid("fd00:aaaa:bbbb::/48", actionEndUn, 0, [16]byte{}, usidBlockLenBytes)

	// All 6 uSID slots carry this node: 5 shifts empty the Argument and the
	// packet must fall through to classic End, not drop at the loop bound.
	segs := []net.IP{net.ParseIP("fd00:9:9::1"), net.ParseIP("fd00:aaaa:bbbb:bbbb:bbbb:bbbb:bbbb:bbbb")}
	pkt, err := buildSRv6Packet(net.ParseIP("fd00:1:1::1"), net.ParseIP("fd00:aaaa:bbbb:bbbb:bbbb:bbbb:bbbb:bbbb"), segs, 1)
	if err != nil {
		t.Fatal(err)
	}
	ret, out := h.run(pkt)
	if ret != XDP_PASS {
		t.Fatalf("expected XDP_PASS (classic End fall-through), got %d", ret)
	}
	verifyDAAndSL(t, out, "fd00:9:9::1", 1)
	if hl := outPktHopLimit(t, out); hl != 59 {
		t.Errorf("hop limit = %d, want 59 (five logical uN hops)", hl)
	}
}

func TestXDPProgEndUnShiftIntoOtherEntryRedispatches(t *testing.T) {
	h := newXDPTestHelper(t)
	// Two distinct uN entries (separate aux slots): a container [uN-A, uN-B]
	// on the same node must hand off from A's execution to B's, carrying
	// B's entry/aux context through a fresh tail call.
	h.createSidFunctionUsid("fd00:aaaa:bbbb::/48", actionEndUn, 0, [16]byte{}, usidBlockLenBytes)
	h.createSidFunctionUsid("fd00:aaaa:cccc::/48", actionEndUn, 0, [16]byte{}, usidBlockLenBytes)

	pkt, err := buildUsidIPv6Packet(net.ParseIP("fd00:1:1::1"), net.ParseIP("fd00:aaaa:bbbb:cccc:dddd::"), 64)
	if err != nil {
		t.Fatal(err)
	}
	ret, out := h.run(pkt)
	if ret != XDP_DROP {
		t.Errorf("expected fail-closed XDP_DROP after both shifts, got %d", ret)
	}
	if got, want := outPktDA(t, out), net.ParseIP("fd00:aaaa:dddd::"); !got.Equal(want) {
		t.Errorf("DA = %v, want %v (shift at uN-A, re-dispatch, shift at uN-B)", got, want)
	}
	if hl := outPktHopLimit(t, out); hl != 62 {
		t.Errorf("hop limit = %d, want 62 (two logical uN hops)", hl)
	}
}

func TestXDPProgEndUnBadBlockLen(t *testing.T) {
	h := newXDPTestHelper(t)
	// Only the F3216 block length is supported; anything else fails closed.
	h.createSidFunctionUsid("fd00:aaaa:1111::/48", actionEndUn, 0, [16]byte{}, 8)

	pkt, err := buildUsidIPv6Packet(net.ParseIP("fd00:1:1::1"), net.ParseIP("fd00:aaaa:1111:cccc::"), 64)
	if err != nil {
		t.Fatal(err)
	}
	ret, out := h.run(pkt)
	if ret != XDP_DROP {
		t.Errorf("expected XDP_DROP, got %d", ret)
	}
	// XDP_DROP alone proves nothing here: the shift path fails closed with
	// the same verdict once the FIB lookup misses. The guard is what keeps
	// the packet untouched, so assert that instead.
	if got, want := outPktDA(t, out), net.ParseIP("fd00:aaaa:1111:cccc::"); !got.Equal(want) {
		t.Errorf("DA = %v, want %v (unshifted: the block length guard runs before any shift)", got, want)
	}
	if hl := outPktHopLimit(t, out); hl != 64 {
		t.Errorf("hop limit = %d, want 64 (no logical uN hop was executed)", hl)
	}
}

// A re-dispatch hands the target entry's own context to the target slot.
// Two same-shaped uN entries cannot show that -- shifting in place would
// produce the same DA and hop limit -- so the second entry carries a block
// length the data plane rejects. Its guard runs only if the tail call
// really executed with entry B's aux, which stops the packet after exactly
// one shift.
func TestXDPProgEndUnRedispatchCarriesTargetContext(t *testing.T) {
	h := newXDPTestHelper(t)
	h.createSidFunctionUsid("fd00:aaaa:bbbb::/48", actionEndUn, 0, [16]byte{}, usidBlockLenBytes)
	h.createSidFunctionUsid("fd00:aaaa:cccc::/48", actionEndUn, 0, [16]byte{}, 8)

	pkt, err := buildUsidIPv6Packet(net.ParseIP("fd00:1:1::1"), net.ParseIP("fd00:aaaa:bbbb:cccc:dddd::"), 64)
	if err != nil {
		t.Fatal(err)
	}
	ret, out := h.run(pkt)
	if ret != XDP_DROP {
		t.Errorf("expected XDP_DROP from uN-B's block length guard, got %d", ret)
	}
	// One shift (at uN-A) only. Reaching fd00:aaaa:dddd:: would mean the
	// loop kept shifting in place under A's context instead of dispatching
	// to B.
	if got, want := outPktDA(t, out), net.ParseIP("fd00:aaaa:cccc:dddd::"); !got.Equal(want) {
		t.Errorf("DA = %v, want %v (one shift at uN-A, then uN-B's guard)", got, want)
	}
	if hl := outPktHopLimit(t, out); hl != 63 {
		t.Errorf("hop limit = %d, want 63 (one logical uN hop)", hl)
	}
}
