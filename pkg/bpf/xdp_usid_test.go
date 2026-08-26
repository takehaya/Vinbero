package bpf

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	vinberov1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/vishvananda/netlink"
)

// uN / uA (NEXT-C-SID, RFC 9800) data-plane tests.
const (
	actionEndUn = uint8(vinberov1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_UN)
	actionEndUa = uint8(vinberov1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_UA)
	actionEndUt = uint8(vinberov1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_UT)

	usidBlockLenBytes = uint8(4) // F3216
)

func (h *xdpTestHelper) createSidFunctionUsidVrf(prefix string, flavor uint8, vrfIfindex uint32, blockLenBytes uint8) {
	h.t.Helper()
	entry := &SidFunctionEntry{Action: actionEndUt, Flavor: flavor}
	aux := NewSidAuxUsidVrf(vrfIfindex, blockLenBytes)
	if err := h.mapOps.CreateSidFunction(prefix, entry, aux, OwnerRPC); err != nil {
		h.t.Fatalf("Failed to create SID function entry: %v", err)
	}
}

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

// USD on a no-SRH (H.Encaps.Red single-container) packet: when the
// container ends on this node and the flavor is USD, the outer IPv6 is
// stripped and the inner packet is forwarded. The FIB never resolves under
// BPF_PROG_TEST_RUN, so the verdict is the fail-closed XDP_DROP; the decap
// itself is asserted on the returned packet.
func TestXDPProgEndUnUSDNoSrh(t *testing.T) {
	h := newXDPTestHelper(t)
	h.createSidFunctionUsid("fd00:aaaa:dddd::/48", actionEndUn, flavorUSD, [16]byte{}, usidBlockLenBytes)

	t.Run("bare uN SID with inner IPv4 decaps", func(t *testing.T) {
		pkt, err := buildEncapsulatedPacketNoSRH(
			net.ParseIP("fd00:1:1::1"), net.ParseIP("fd00:aaaa:dddd::"),
			net.ParseIP("10.0.0.1").To4(), net.ParseIP("192.0.2.100").To4(), innerTypeIPv4)
		if err != nil {
			t.Fatal(err)
		}
		ret, out := h.run(pkt)
		// Whether the post-decap FIB resolves depends on the host's routing
		// table, so the verdict is XDP_REDIRECT or the fail-closed XDP_DROP;
		// XDP_PASS would mean the USD branch never ran.
		if ret == XDP_PASS {
			t.Errorf("expected XDP_REDIRECT or XDP_DROP, got XDP_PASS")
		}
		if !verifyEtherType(t, out, 0x0800) {
			t.Errorf("expected decapped IPv4 packet")
		}
	})

	t.Run("bare uN SID with inner IPv6 decaps", func(t *testing.T) {
		pkt, err := buildEncapsulatedPacketNoSRH(
			net.ParseIP("fd00:1:1::1"), net.ParseIP("fd00:aaaa:dddd::"),
			net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2"), innerTypeIPv6)
		if err != nil {
			t.Fatal(err)
		}
		ret, out := h.run(pkt)
		if ret == XDP_PASS {
			t.Errorf("expected XDP_REDIRECT or XDP_DROP, got XDP_PASS")
		}
		if !verifyEtherType(t, out, 0x86DD) {
			t.Errorf("expected decapped IPv6 packet")
		}
		if got, want := outPktDA(t, out), net.ParseIP("2001:db8::2"); !got.Equal(want) {
			t.Errorf("inner DA = %v, want %v (outer stripped)", got, want)
		}
	})

	t.Run("container ending here after a shift decaps", func(t *testing.T) {
		// [uN, uN] of this node: the loop consumes the Argument down to the
		// bare SID, then the USD terminal decaps.
		pkt, err := buildEncapsulatedPacketNoSRH(
			net.ParseIP("fd00:1:1::1"), net.ParseIP("fd00:aaaa:dddd:dddd::"),
			net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2"), innerTypeIPv6)
		if err != nil {
			t.Fatal(err)
		}
		ret, out := h.run(pkt)
		if ret == XDP_PASS {
			t.Errorf("expected XDP_REDIRECT or XDP_DROP, got XDP_PASS")
		}
		if got, want := outPktDA(t, out), net.ParseIP("2001:db8::2"); !got.Equal(want) {
			t.Errorf("inner DA = %v, want %v (shifted, then decapped)", got, want)
		}
	})

	t.Run("non-tunnel payload passes up untouched", func(t *testing.T) {
		// USD has nothing to decap for a plain ICMPv6 payload: same
		// upper-layer delivery as flavor NONE.
		pkt, err := buildUsidIPv6Packet(net.ParseIP("fd00:1:1::1"), net.ParseIP("fd00:aaaa:dddd::"), 64)
		if err != nil {
			t.Fatal(err)
		}
		ret, out := h.run(pkt)
		if ret != XDP_PASS {
			t.Errorf("expected XDP_PASS, got %d", ret)
		}
		if got, want := outPktDA(t, out), net.ParseIP("fd00:aaaa:dddd::"); !got.Equal(want) {
			t.Errorf("DA = %v, want %v (untouched)", got, want)
		}
	})
}

// uT (RFC 9800 Sec.4.1.3): uN with the FIB lookup bound to the aux VRF.
// The aux here carries the loopback ifindex, so these tests cover the
// shared shift/terminal machinery running under the uT slot with its
// aliased aux; the uT-specific fail-closed NO_NEIGH branch needs a real
// VRF and is pinned by TestXDPProgEndUtNoNeighFailsClosed below.
func TestXDPProgEndUt(t *testing.T) {
	h := newXDPTestHelper(t)
	h.createSidFunctionUsidVrf("fd00:aaaa:cccc::/48", 0, 1, usidBlockLenBytes)

	src := net.ParseIP("fd00:1:1::1")

	t.Run("shift without SRH", func(t *testing.T) {
		pkt, err := buildUsidIPv6Packet(src, net.ParseIP("fd00:aaaa:cccc:dddd::"), 64)
		if err != nil {
			t.Fatal(err)
		}
		ret, out := h.run(pkt)
		if ret != XDP_DROP {
			t.Errorf("expected fail-closed XDP_DROP, got %d", ret)
		}
		if got, want := outPktDA(t, out), net.ParseIP("fd00:aaaa:dddd::"); !got.Equal(want) {
			t.Errorf("DA = %v, want %v (shifted)", got, want)
		}
		if hl := outPktHopLimit(t, out); hl != 63 {
			t.Errorf("hop limit = %d, want 63", hl)
		}
	})

	t.Run("consecutive own-node uSIDs shift in place", func(t *testing.T) {
		pkt, err := buildUsidIPv6Packet(src, net.ParseIP("fd00:aaaa:cccc:cccc:dddd::"), 64)
		if err != nil {
			t.Fatal(err)
		}
		ret, out := h.run(pkt)
		if ret != XDP_DROP {
			t.Errorf("expected fail-closed XDP_DROP, got %d", ret)
		}
		if got, want := outPktDA(t, out), net.ParseIP("fd00:aaaa:dddd::"); !got.Equal(want) {
			t.Errorf("DA = %v, want %v (double shift)", got, want)
		}
	})

	t.Run("argument zero with SRH falls through to End.T", func(t *testing.T) {
		segs := []net.IP{net.ParseIP("fd00:9:9::1"), net.ParseIP("fd00:aaaa:cccc::")}
		pkt, err := buildSRv6Packet(src, net.ParseIP("fd00:aaaa:cccc::"), segs, 1)
		if err != nil {
			t.Fatal(err)
		}
		ret, out := h.run(pkt)
		if ret != XDP_PASS {
			t.Errorf("expected XDP_PASS (End.T FIB miss on lo), got %d", ret)
		}
		verifyDAAndSL(t, out, "fd00:9:9::1", 1)
	})

	t.Run("argument zero without SRH passes to the kernel", func(t *testing.T) {
		pkt, err := buildUsidIPv6Packet(src, net.ParseIP("fd00:aaaa:cccc::"), 64)
		if err != nil {
			t.Fatal(err)
		}
		ret, out := h.run(pkt)
		if ret != XDP_PASS {
			t.Errorf("expected XDP_PASS, got %d", ret)
		}
		if got, want := outPktDA(t, out), net.ParseIP("fd00:aaaa:cccc::"); !got.Equal(want) {
			t.Errorf("DA = %v, want %v (untouched)", got, want)
		}
	})

	t.Run("USD decap on a no-SRH terminal", func(t *testing.T) {
		h.createSidFunctionUsidVrf("fd00:aaaa:2222::/48", flavorUSD, 1, usidBlockLenBytes)
		pkt, err := buildEncapsulatedPacketNoSRH(
			src, net.ParseIP("fd00:aaaa:2222::"),
			net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2"), innerTypeIPv6)
		if err != nil {
			t.Fatal(err)
		}
		ret, out := h.run(pkt)
		if ret == XDP_PASS {
			t.Errorf("expected XDP_REDIRECT or XDP_DROP, got XDP_PASS")
		}
		if got, want := outPktDA(t, out), net.ParseIP("2001:db8::2"); !got.Equal(want) {
			t.Errorf("inner DA = %v, want %v (outer stripped)", got, want)
		}
	})

	t.Run("bad block length fails closed before any shift", func(t *testing.T) {
		h.createSidFunctionUsidVrf("fd00:aaaa:1111::/48", 0, 1, 8)
		pkt, err := buildUsidIPv6Packet(src, net.ParseIP("fd00:aaaa:1111:cccc::"), 64)
		if err != nil {
			t.Fatal(err)
		}
		ret, out := h.run(pkt)
		if ret != XDP_DROP {
			t.Errorf("expected XDP_DROP, got %d", ret)
		}
		if got, want := outPktDA(t, out), net.ParseIP("fd00:aaaa:1111:cccc::"); !got.Equal(want) {
			t.Errorf("DA = %v, want %v (unshifted)", got, want)
		}
	})
}

// uT is fail-closed on NO_NEIGH, unlike uN: the kernel cannot repeat a
// VRF-scoped lookup for a packet that arrived on a non-VRF interface. The
// other uT tests cannot see this branch (their aux points at loopback, so
// fib_ifindex == ingress and the uN hand-off condition holds); here a real
// VRF holds a route through an unresolvable gateway on a dummy device, so
// the lookup answers NO_NEIGH in a non-ingress context and the packet must
// drop. Deleting the ingress condition in usid_forward turns this into an
// XDP_PASS and fails the test.
func TestXDPProgEndUtNoNeighFailsClosed(t *testing.T) {
	h := newXDPTestHelper(t)

	vrf := &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: "utnn-vrf0"}, Table: 1042}
	if err := netlink.LinkAdd(vrf); err != nil {
		t.Skipf("cannot create VRF device: %v", err)
	}
	defer func() { _ = netlink.LinkDel(vrf) }()
	if err := netlink.LinkSetUp(vrf); err != nil {
		t.Fatalf("vrf up: %v", err)
	}
	dummy := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "utnn-dum0", MasterIndex: vrf.Attrs().Index}}
	if err := netlink.LinkAdd(dummy); err != nil {
		t.Fatalf("dummy add: %v", err)
	}
	defer func() { _ = netlink.LinkDel(dummy) }()
	if err := netlink.LinkSetUp(dummy); err != nil {
		t.Fatalf("dummy up: %v", err)
	}
	addr, _ := netlink.ParseAddr("fd00:feed::1/64")
	if err := netlink.AddrAdd(dummy, addr); err != nil {
		t.Fatalf("addr add: %v", err)
	}
	_, dst, _ := net.ParseCIDR("fd00:aaaa:dddd::/48")
	route := &netlink.Route{
		LinkIndex: dummy.Attrs().Index,
		Dst:       dst,
		Gw:        net.ParseIP("fd00:feed::2"), // never resolves on a dummy
		Table:     1042,
	}
	if err := netlink.RouteAdd(route); err != nil {
		t.Fatalf("route add: %v", err)
	}

	h.createSidFunctionUsidVrf("fd00:aaaa:cccc::/48", 0, uint32(vrf.Attrs().Index), usidBlockLenBytes)

	pkt, err := buildUsidIPv6Packet(net.ParseIP("fd00:1:1::1"), net.ParseIP("fd00:aaaa:cccc:dddd::"), 64)
	if err != nil {
		t.Fatal(err)
	}
	ret, out := h.run(pkt)
	if ret != XDP_DROP {
		t.Errorf("expected fail-closed XDP_DROP on NO_NEIGH in the VRF, got %d", ret)
	}
	if got, want := outPktDA(t, out), net.ParseIP("fd00:aaaa:dddd::"); !got.Equal(want) {
		t.Errorf("DA = %v, want %v (shifted before the lookup)", got, want)
	}

	t.Run("SRH advance stays fail-closed too", func(t *testing.T) {
		// The classic End.T fall-through advances to the next segment and
		// looks it up in the VRF; NO_NEIGH there must not escape to the
		// kernel either (endpoint_fib_redirect_core's ingress condition).
		segs := []net.IP{net.ParseIP("fd00:aaaa:dddd::1"), net.ParseIP("fd00:aaaa:cccc::")}
		pkt, err := buildSRv6Packet(net.ParseIP("fd00:1:1::1"), net.ParseIP("fd00:aaaa:cccc::"), segs, 1)
		if err != nil {
			t.Fatal(err)
		}
		ret, out := h.run(pkt)
		if ret != XDP_DROP {
			t.Errorf("expected fail-closed XDP_DROP, got %d", ret)
		}
		if got, want := outPktDA(t, out), net.ParseIP("fd00:aaaa:dddd::1"); !got.Equal(want) {
			t.Errorf("DA = %v, want %v (advanced before the lookup)", got, want)
		}
	})

	t.Run("SRH USD decap looks up in the VRF", func(t *testing.T) {
		// SL=0 USD on a uT: the inner FIB lookup runs in the bound VRF
		// (endpoint_handle_usd now takes the fib ifindex); the VRF route's
		// unresolvable gateway keeps it fail-closed.
		h.createSidFunctionUsidVrf("fd00:aaaa:eeee::/48", flavorUSD, uint32(vrf.Attrs().Index), usidBlockLenBytes)
		_, innerDst, _ := net.ParseCIDR("2001:db8:42::/48")
		if err := netlink.RouteAdd(&netlink.Route{
			LinkIndex: dummy.Attrs().Index,
			Dst:       innerDst,
			Gw:        net.ParseIP("fd00:feed::2"),
			Table:     1042,
		}); err != nil {
			t.Fatalf("route add: %v", err)
		}
		segs := []net.IP{net.ParseIP("fd00:aaaa:eeee::")}
		pkt, err := buildEncapsulatedPacket(
			net.ParseIP("fd00:1:1::1"), net.ParseIP("fd00:aaaa:eeee::"), segs, 0,
			net.ParseIP("2001:db8:41::1"), net.ParseIP("2001:db8:42::1"), innerTypeIPv6)
		if err != nil {
			t.Fatal(err)
		}
		ret, out := h.run(pkt)
		if ret != XDP_DROP {
			t.Errorf("expected fail-closed XDP_DROP, got %d", ret)
		}
		if got, want := outPktDA(t, out), net.ParseIP("2001:db8:42::1"); !got.Equal(want) {
			t.Errorf("inner DA = %v, want %v (decapped)", got, want)
		}
	})
}

// Flavor NONE keeps the pre-USD behavior on tunnelled no-SRH terminals:
// the packet goes to the kernel with the outer header intact. Pinned so the
// USD branch cannot widen to flavorless entries by accident.
func TestXDPProgEndUnNoSrhTunnelledFlavorNonePassesUp(t *testing.T) {
	h := newXDPTestHelper(t)
	h.createSidFunctionUsid("fd00:aaaa:bbbb::/48", actionEndUn, 0, [16]byte{}, usidBlockLenBytes)

	pkt, err := buildEncapsulatedPacketNoSRH(
		net.ParseIP("fd00:1:1::1"), net.ParseIP("fd00:aaaa:bbbb::"),
		net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2"), innerTypeIPv6)
	if err != nil {
		t.Fatal(err)
	}
	ret, out := h.run(pkt)
	if ret != XDP_PASS {
		t.Errorf("expected XDP_PASS, got %d", ret)
	}
	if got, want := outPktDA(t, out), net.ParseIP("fd00:aaaa:bbbb::"); !got.Equal(want) {
		t.Errorf("DA = %v, want %v (outer header intact)", got, want)
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

	t.Run("argument zero without SRH passes to the kernel", func(t *testing.T) {
		// The bare uA SID with no SRH is classic End.X with no segment
		// list: local delivery, and nothing in the packet may change.
		pkt, err := buildUsidIPv6Packet(net.ParseIP("fd00:1:1::1"), net.ParseIP("fd00:aaaa:ffff:cccc::"), 64)
		if err != nil {
			t.Fatal(err)
		}
		ret, out := h.run(pkt)
		if ret != XDP_PASS {
			t.Errorf("expected XDP_PASS, got %d", ret)
		}
		if got, want := outPktDA(t, out), net.ParseIP("fd00:aaaa:ffff:cccc::"); !got.Equal(want) {
			t.Errorf("DA = %v, want %v (untouched)", got, want)
		}
		if hl := outPktHopLimit(t, out); hl != 64 {
			t.Errorf("hop limit = %d, want 64 (no uA hop was executed)", hl)
		}
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
	// Five shifts, five hops. The classic End the packet falls through to
	// is a sixth hop and takes one more, but it hands the packet to the
	// kernel here (the FIB never resolves under BPF_PROG_TEST_RUN) and
	// gives that one back for the kernel to spend. On a real redirect the
	// packet would leave with 58.
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

// A shift that lands on a local SID whose behavior needs an SRH must not be
// re-dispatched when the packet has none: most endpoint slots parse whatever
// follows the IPv6 header as a Routing header, so an ICMPv6 payload would be
// read as an SRH. The kernel owns that address, so the packet goes up
// instead.
func TestXDPProgEndUnNoSrhShiftIntoSrhOnlyEntryPassesUp(t *testing.T) {
	h := newXDPTestHelper(t)
	h.createSidFunctionUsid("fd00:aaaa:bbbb::/48", actionEndUn, 0, [16]byte{}, usidBlockLenBytes)
	h.createSidFunction("fd00:aaaa:cccc::/128", uint8(vinberov1.Srv6LocalAction_SRV6_LOCAL_ACTION_END))

	pkt, err := buildUsidIPv6Packet(net.ParseIP("fd00:1:1::1"), net.ParseIP("fd00:aaaa:bbbb:cccc::"), 64)
	if err != nil {
		t.Fatal(err)
	}
	ret, out := h.run(pkt)
	if ret != XDP_PASS {
		t.Errorf("expected XDP_PASS (local delivery), got %d", ret)
	}
	if got, want := outPktDA(t, out), net.ParseIP("fd00:aaaa:cccc::"); !got.Equal(want) {
		t.Errorf("DA = %v, want %v (shifted once)", got, want)
	}
	if hl := outPktHopLimit(t, out); hl != 63 {
		t.Errorf("hop limit = %d, want 63 (one logical uN hop)", hl)
	}
}
