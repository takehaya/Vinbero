package bpf

import (
	"net"
	"os"
	"testing"

	"github.com/vishvananda/netlink"
)

// End.T with REPLACE-CSID (RFC 9800 Sec.4.2): stored as END_REPLACE with
// the VRF ifindex aliased into the aux leading word, so the C-SID walk is
// End(REP)'s and only the FIB context differs. These run on the loopback
// test-run ifindex (1); binding a distinct (non-existent) VRF ifindex must
// fail closed on the unresolvable table rather than fall back to ingress.
func (h *xdpTestHelper) createSidFunctionTReplace(prefix string, flavor uint8, vrfIfindex uint32, csidLen uint8) {
	h.t.Helper()
	entry := &SidFunctionEntry{Action: actionEndReplace, Flavor: flavor}
	aux := NewSidAuxReplaceVrf(vrfIfindex, replBlockBytes, csidLen)
	if err := h.mapOps.CreateSidFunction(prefix, entry, aux, OwnerRPC); err != nil {
		h.t.Fatalf("Failed to create SID function entry: %v", err)
	}
}

func TestXDPProgEndTReplace(t *testing.T) {
	h := newXDPTestHelper(t)
	// VRF ifindex 4093 does not exist: any packet that reaches the VRF FIB
	// lookup must drop, never pass to the kernel or resolve via ingress.
	h.createSidFunctionTReplace("fd00:aabb:ccdd:1111:2222::/80", 0, 4093, 4)

	src := net.ParseIP("fd00:1:1::1")

	t.Run("walk within a container advances and fails closed", func(t *testing.T) {
		segs := []net.IP{
			mkContainer32(0, 0, 0, 0),
			mkContainer32(0x510500aa, 0x510500bb, 0x510500cc, 0x510500dd),
		}
		pkt, err := buildSRv6Packet(src, replDA(0x11112222, 2), segs, 1)
		if err != nil {
			t.Fatal(err)
		}
		ret, out := h.run(pkt)
		if ret != XDP_DROP {
			t.Errorf("expected fail-closed XDP_DROP (VRF unresolvable), got %d", ret)
		}
		// The walk itself is End(REP)'s: C-SID replaced, index decremented.
		if got, want := outPktDA(t, out), replDA(0x510500bb, 1); !got.Equal(want) {
			t.Errorf("DA = %v, want %v (advanced)", got, want)
		}
		if hl := outPktHopLimit(t, out); hl != 63 {
			t.Errorf("hop limit = %d, want 63", hl)
		}
	})

	t.Run("terminal S02 still reaches the kernel", func(t *testing.T) {
		// idx=0 with SL=0 terminates: upper-layer processing, not a VRF
		// lookup, so the unresolvable VRF must not turn this into a drop.
		segs := []net.IP{mkContainer32(0, 0, 0, 0)}
		pkt, err := buildSRv6Packet(src, replDA(0x11112222, 0), segs, 0)
		if err != nil {
			t.Fatal(err)
		}
		ret, _ := h.run(pkt)
		if ret != XDP_PASS {
			t.Errorf("expected XDP_PASS at the terminal SID, got %d", ret)
		}
	})
}

// A plain End(REP) aux has a zero leading word: the VRF aliasing must not
// change its behavior (regression guard for the shared core edit).
func TestXDPProgEndReplacePlainAuxUnaffected(t *testing.T) {
	h := newXDPTestHelper(t)
	h.createSidFunctionReplace("fd00:aabb:ccdd:1111:2222::/80", actionEndReplace, 0, [16]byte{}, 4)
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
		t.Errorf("expected fail-closed XDP_DROP (FIB miss), got %d", ret)
	}
	if got, want := outPktDA(t, out), replDA(0x510500bb, 1); !got.Equal(want) {
		t.Errorf("DA = %v, want %v", got, want)
	}
}

// The VRF binding must actually change the FIB outcome, not just share
// End(REP)'s drop: with an on-link route for the block in the ingress
// table, End(REP)'s advance gets NO_NEIGH and hands the packet to the
// kernel (XDP_PASS), while the same advance bound to an unresolvable VRF
// stays fail-closed (the kernel cannot repeat a VRF-scoped lookup for a
// packet that arrived on a non-VRF interface).
func TestXDPProgEndTReplaceVrfChangesOutcome(t *testing.T) {
	// bpf_fib_lookup answers FWD_DISABLED unless IPv6 forwarding is on
	// (same as adjacencyEnv); both toggles are restored on cleanup.
	for _, fwd := range []string{
		"/proc/sys/net/ipv6/conf/all/forwarding",
		"/proc/sys/net/ipv6/conf/default/forwarding",
	} {
		if prev, err := os.ReadFile(fwd); err == nil {
			if err := os.WriteFile(fwd, []byte("1"), 0); err != nil {
				t.Skipf("cannot enable IPv6 forwarding: %v", err)
			}
			fwd, prev := fwd, prev
			t.Cleanup(func() { _ = os.WriteFile(fwd, prev, 0) })
		}
	}

	// An on-link route out a veth with NO neighbour entry: the ingress
	// lookup resolves the route but not the L2 nexthop, which is exactly
	// NO_NEIGH. Explicit MACs keep udev's MACAddressPolicy away (see
	// adjacencyEnv).
	macA, _ := net.ParseMAC("02:ad:00:00:01:0a")
	macB, _ := net.ParseMAC("02:ad:00:00:01:0b")
	veth := &netlink.Veth{
		LinkAttrs:        netlink.LinkAttrs{Name: "trep-a", HardwareAddr: macA},
		PeerName:         "trep-b",
		PeerHardwareAddr: macB,
	}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Skipf("cannot create veth pair (needs a writable netns): %v", err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(veth) })
	for _, name := range []string{"trep-a", "trep-b"} {
		link, err := netlink.LinkByName(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := netlink.LinkSetUp(link); err != nil {
			t.Fatalf("%s up: %v", name, err)
		}
	}
	linkA, err := netlink.LinkByName("trep-a")
	if err != nil {
		t.Fatalf("trep-a: %v", err)
	}
	_, dst, _ := net.ParseCIDR("fd00:aabb:ccdd::/48")
	if err := netlink.RouteAdd(&netlink.Route{LinkIndex: linkA.Attrs().Index, Dst: dst}); err != nil {
		t.Fatalf("route add: %v", err)
	}

	segs := []net.IP{
		mkContainer32(0, 0, 0, 0),
		mkContainer32(0x510500aa, 0x510500bb, 0x510500cc, 0x510500dd),
	}
	src := net.ParseIP("fd00:1:1::1")

	t.Run("plain End(REP) reaches NO_NEIGH and passes up", func(t *testing.T) {
		h := newXDPTestHelper(t)
		h.createSidFunctionReplace("fd00:aabb:ccdd:1111:2222::/80", actionEndReplace, 0, [16]byte{}, 4)
		pkt, err := buildSRv6Packet(src, replDA(0x11112222, 2), segs, 1)
		if err != nil {
			t.Fatal(err)
		}
		ret, _ := h.run(pkt)
		if ret != XDP_PASS {
			t.Errorf("expected XDP_PASS (NO_NEIGH handed to the kernel), got %d", ret)
		}
	})

	t.Run("the same advance bound to a VRF fails closed", func(t *testing.T) {
		h := newXDPTestHelper(t)
		h.createSidFunctionTReplace("fd00:aabb:ccdd:1111:2222::/80", 0, 4093, 4)
		pkt, err := buildSRv6Packet(src, replDA(0x11112222, 2), segs, 1)
		if err != nil {
			t.Fatal(err)
		}
		ret, _ := h.run(pkt)
		if ret != XDP_DROP {
			t.Errorf("expected fail-closed XDP_DROP (VRF-scoped lookup), got %d", ret)
		}
	})

	// USP at the S02 terminal strips the SRH and FIB-forwards the exposed
	// DA: like classic End.T, the lookup context is the bound VRF.
	uspSegs := []net.IP{mkContainer32(0, 0, 0, 0)}
	t.Run("plain End(REP) USP forwards in the ingress context", func(t *testing.T) {
		h := newXDPTestHelper(t)
		h.createSidFunctionReplace("fd00:aabb:ccdd:1111:2222::/80", actionEndReplace, flavorUSP, [16]byte{}, 4)
		pkt, err := buildSRv6Packet(src, replDA(0x11112222, 0), uspSegs, 0)
		if err != nil {
			t.Fatal(err)
		}
		ret, _ := h.run(pkt)
		if ret != XDP_PASS {
			t.Errorf("expected XDP_PASS (NO_NEIGH handed to the kernel), got %d", ret)
		}
	})
	t.Run("End.T(REP) USP forwards in the VRF context", func(t *testing.T) {
		h := newXDPTestHelper(t)
		h.createSidFunctionTReplace("fd00:aabb:ccdd:1111:2222::/80", flavorUSP, 4093, 4)
		pkt, err := buildSRv6Packet(src, replDA(0x11112222, 0), uspSegs, 0)
		if err != nil {
			t.Fatal(err)
		}
		ret, _ := h.run(pkt)
		if ret != XDP_DROP {
			t.Errorf("expected fail-closed XDP_DROP (VRF-scoped USP lookup), got %d", ret)
		}
	})

	// USD at the S02 terminal decaps the tunnelled payload and FIB-forwards
	// the inner DA -- again in the bound VRF for End.T(REP). USD never
	// hands a decapped packet to the kernel (PASS is converted to DROP),
	// so the distinguisher is a RESOLVED ingress route: the ingress
	// context redirects, the VRF-scoped lookup stays fail-closed.
	_, innerDst, _ := net.ParseCIDR("2001:db8:42::/48")
	if err := netlink.RouteAdd(&netlink.Route{LinkIndex: linkA.Attrs().Index, Dst: innerDst}); err != nil {
		t.Fatalf("inner route add: %v", err)
	}
	innerMAC, _ := net.ParseMAC("02:ad:00:00:01:0c")
	if err := netlink.NeighAdd(&netlink.Neigh{
		LinkIndex:    linkA.Attrs().Index,
		Family:       netlink.FAMILY_V6,
		State:        netlink.NUD_PERMANENT,
		IP:           net.ParseIP("2001:db8:42::1"),
		HardwareAddr: innerMAC,
	}); err != nil {
		t.Fatalf("inner neigh add: %v", err)
	}
	mkUSD := func(t *testing.T) []byte {
		t.Helper()
		pkt, err := buildEncapsulatedPacket(
			src, replDA(0x11112222, 0), uspSegs, 0,
			net.ParseIP("2001:db8:41::1"), net.ParseIP("2001:db8:42::1"), innerTypeIPv6)
		if err != nil {
			t.Fatal(err)
		}
		return pkt
	}
	t.Run("plain End(REP) USD decaps and redirects in the ingress context", func(t *testing.T) {
		h := newXDPTestHelper(t)
		h.createSidFunctionReplace("fd00:aabb:ccdd:1111:2222::/80", actionEndReplace, flavorUSD, [16]byte{}, 4)
		ret, out := h.run(mkUSD(t))
		if ret != XDP_REDIRECT {
			t.Errorf("expected XDP_REDIRECT (resolved ingress route), got %d", ret)
		}
		if got, want := outPktDA(t, out), net.ParseIP("2001:db8:42::1"); !got.Equal(want) {
			t.Errorf("inner DA = %v, want %v (decapped)", got, want)
		}
	})
	t.Run("End.T(REP) USD decaps and looks up in the VRF", func(t *testing.T) {
		h := newXDPTestHelper(t)
		h.createSidFunctionTReplace("fd00:aabb:ccdd:1111:2222::/80", flavorUSD, 4093, 4)
		ret, out := h.run(mkUSD(t))
		if ret != XDP_DROP {
			t.Errorf("expected fail-closed XDP_DROP (VRF-scoped USD lookup), got %d", ret)
		}
		if got, want := outPktDA(t, out), net.ParseIP("2001:db8:42::1"); !got.Equal(want) {
			t.Errorf("inner DA = %v, want %v (decapped before the lookup)", got, want)
		}
	})
}
