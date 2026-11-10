package bpf

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// EncapDestinations reads the first segment of every kind of encapsulation
// from the maps, whoever wrote them: IPv4 and IPv6 headends, an MUP session,
// an ECMP path, an SR policy's first transport SID, an L2 headend circuit, a
// BD peer and an End.B6.Encaps policy. A MUP gate (no segments) adds none.
func TestEncapDestinations(t *testing.T) {
	h := newXDPTestHelper(t)
	src, _ := ParseIPv6("fc00:e01::1")
	seg := func(s string) ([10][16]byte, uint8) {
		segs, n, err := ParseSegments([]string{s, "fc00:eff::1"})
		if err != nil {
			t.Fatal(err)
		}
		return segs, n
	}
	want := []string{}
	add := func(s string) ([10][16]byte, uint8) { want = append(want, s); return seg(s) }

	s, n := add("fc00:d01::1")
	h.createHeadendEntry("10.1.0.0/24", src, [16]byte{}, s, n, true)
	s, n = add("fc00:d02::1")
	h.createHeadendEntry("2001:db8:1::/64", src, [16]byte{}, s, n, false)
	s, n = add("fc00:d03::1")
	h.createMupUplinkSession("192.0.2.1", 7, 32, src, s, n, MupArgsOffsetNone)
	h.createMupUplinkGate("192.0.2.1/32")
	s, n = add("fc00:d04::1")
	if err := h.mapOps.PutEcmpGroup(9, []EcmpPath{{Entry: &HeadendEntry{Mode: modeHEncaps, NumSegments: n, SrcAddr: src, Segments: s}, Weight: 1}}, OwnerRPC); err != nil {
		t.Fatalf("PutEcmpGroup: %v", err)
	}
	want = append(want, "fc00:d05::1")
	if err := h.mapOps.UpsertSRPolicy(5, []netip.Addr{netip.MustParseAddr("fc00:d05::1"), netip.MustParseAddr("fc00:d05::2")}); err != nil {
		t.Fatalf("UpsertSRPolicy: %v", err)
	}
	s, n = add("fc00:d06::1")
	h.createHeadendL2Entry(1, 30, src, s, n, 0)
	s, n = add("fc00:d07::1")
	if err := h.mapOps.CreateBdPeer(100, 1, &HeadendEntry{Mode: modeHEncaps, NumSegments: n, SrcAddr: src, Segments: s, BdId: 100}, [ESILen]byte{}, [IPv6AddrLen]byte{}, false); err != nil {
		t.Fatalf("CreateBdPeer: %v", err)
	}
	s, n = add("fc00:d08::1")
	h.createSidFunctionB6("fc00:b6::1/128", actionEndB6Encaps, modeHEncaps, src, s, n)

	got, err := h.mapOps.EncapDestinations()
	if err != nil {
		t.Fatalf("EncapDestinations: %v", err)
	}
	var gotS []string
	for _, a := range got {
		gotS = append(gotS, a.String())
	}
	slices.Sort(want)
	if !slices.Equal(gotS, want) {
		t.Errorf("destinations = %v, want %v", gotS, want)
	}
}

// encapNeighEnv is a namespace pair: this test's namespace (the PE) reaches
// the underlay gateway over a veth whose peer sits in its own namespace and
// answers Neighbor Solicitations for two addresses, gw1 and gw2. The SIDs
// (fc00:e00::/32) are routed via gw1 in the main table. The PE's tenant
// port is enslaved to a VRF whose table ends in an unreachable default. No
// neighbour entry for either gateway is installed.
type encapNeighEnv struct {
	tenant   uint32
	uplink   int
	peerMAC  net.HardwareAddr
	gw1, gw2 net.IP
}

func newEncapNeighEnv(t *testing.T) *encapNeighEnv {
	t.Helper()
	inNewNetns(t)
	pe, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := netns.New() // switches this thread to the new namespace
	if err != nil {
		t.Skipf("cannot create the peer namespace: %v", err)
	}
	if err := netns.Set(pe); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close(); _ = pe.Close() })

	if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "eneigh-up"}, PeerName: "eneigh-gw"}); err != nil {
		t.Fatalf("add veth: %v", err)
	}
	gwLink, err := netlink.LinkByName("eneigh-gw")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetNsFd(gwLink, int(peer)); err != nil {
		t.Fatalf("move the peer: %v", err)
	}
	ph, err := netlink.NewHandleAt(peer)
	if err != nil {
		t.Fatal(err)
	}
	defer ph.Close()
	gwLink, err = ph.LinkByName("eneigh-gw")
	if err != nil {
		t.Fatal(err)
	}
	e := &encapNeighEnv{gw1: net.ParseIP("fd00:e::2"), gw2: net.ParseIP("fd00:e::3"), peerMAC: gwLink.Attrs().HardwareAddr}
	for _, a := range []string{"fd00:e::2/64", "fd00:e::3/64"} {
		addr, _ := netlink.ParseAddr(a)
		addr.Flags = unix.IFA_F_NODAD
		if err := ph.AddrAdd(gwLink, addr); err != nil {
			t.Fatalf("peer address %s: %v", a, err)
		}
	}
	if err := ph.LinkSetUp(gwLink); err != nil {
		t.Fatal(err)
	}

	up, err := netlink.LinkByName("eneigh-up")
	if err != nil {
		t.Fatal(err)
	}
	addr, _ := netlink.ParseAddr("fd00:e::1/64")
	addr.Flags = unix.IFA_F_NODAD
	if err := netlink.AddrAdd(up, addr); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(up); err != nil {
		t.Fatal(err)
	}
	e.uplink = up.Attrs().Index
	e.routeSIDsVia(t, e.gw1)

	if err := netlink.LinkAdd(&netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: "eneigh-vrf"}, Table: 100}); err != nil {
		if errors.Is(err, unix.EOPNOTSUPP) {
			t.Skipf("kernel lacks the vrf module: %v", err)
		}
		t.Fatal(err)
	}
	vrf, _ := netlink.LinkByName("eneigh-vrf")
	if err := netlink.LinkSetUp(vrf); err != nil {
		t.Fatal(err)
	}
	for _, cidr := range []string{"0.0.0.0/0", "::/0"} {
		_, dst, _ := net.ParseCIDR(cidr)
		if err := netlink.RouteAdd(&netlink.Route{Table: 100, Type: unix.RTN_UNREACHABLE, Dst: dst, Priority: 4278198272}); err != nil {
			t.Fatal(err)
		}
	}
	e.tenant = uint32(linkUp(t, "eneigh-ten", "fd00:f::1/64"))
	ten, _ := netlink.LinkByName("eneigh-ten")
	if err := netlink.LinkSetMaster(ten, vrf); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(ten); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *encapNeighEnv) routeSIDsVia(t *testing.T, gw net.IP) {
	t.Helper()
	_, sids, _ := net.ParseCIDR("fc00:e00::/32")
	if err := netlink.RouteReplace(&netlink.Route{Dst: sids, Gw: gw, LinkIndex: e.uplink}); err != nil {
		t.Fatalf("route the SIDs via %s: %v", gw, err)
	}
}

func (e *encapNeighEnv) hasNeigh(ip net.IP) bool {
	neighs, _ := netlink.NeighList(e.uplink, netlink.FAMILY_V6)
	for _, n := range neighs {
		if n.IP.Equal(ip) {
			return true
		}
	}
	return false
}

// A tenant encapsulation from an enslaved AC, with a static underlay route
// and no neighbour entry for its gateway, cannot recover by itself: XDP
// hands the packet to the kernel, which drops it at the VRF table's
// unreachable default, so the gateway is never solicited. Once the keeper
// has synced, the kernel resolves the gateway with no other traffic, and the
// encapsulation is redirected to it. After the route moves to another
// gateway, a sync makes that one resolve too.
func TestEncapNeighKeeperResolvesTenantNexthop(t *testing.T) {
	h := newXDPTestHelper(t)
	e := newEncapNeighEnv(t)

	src, _ := ParseIPv6("fc00:e01::1")
	segments, numSegments, _ := ParseSegments([]string{"fc00:e00::1"})
	h.createHeadendEntry("10.99.0.0/24", src, [16]byte{}, segments, numSegments, true)
	if err := h.mapOps.SetIngressPolicy(true, false, 0); err != nil {
		t.Fatal(err)
	}
	if err := h.mapOps.SetIngressVrf(map[IngressACKey]uint32{{Ifindex: e.tenant}: 1}); err != nil {
		t.Fatal(err)
	}
	pkt, err := buildSimpleIPv4Packet(net.ParseIP("10.98.0.1"), net.ParseIP("10.99.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	redirected := func() bool {
		ret, out := h.runOnIfindex(slices.Clone(pkt), e.tenant)
		return ret == XDP_REDIRECT && slices.Equal(out[0:6], []byte(e.peerMAC))
	}
	converges := func(what string) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for !redirected() {
			if time.Now().After(deadline) {
				t.Fatalf("%s: the encapsulation is not redirected to the gateway after 10s", what)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}

	// Nothing solicits the gateway on its own.
	for range 5 {
		if ret, _ := h.runOnIfindex(slices.Clone(pkt), e.tenant); ret != XDP_PASS {
			t.Fatalf("before the keeper: ret %d, want XDP_PASS (no neighbour)", ret)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if e.hasNeigh(e.gw1) {
		t.Fatalf("a neighbour entry for %s appeared without the keeper", e.gw1)
	}

	k := NewEncapNeighKeeper(h.mapOps, nil, nil, zap.NewNop())
	targets, err := k.Sync()
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(targets) != 1 || targets[0].Ifindex != uint32(e.uplink) || !targets[0].IP.Equal(e.gw1) {
		t.Fatalf("keeper covers %+v, want gw1 on the uplink", targets)
	}
	converges("gateway 1")

	e.routeSIDsVia(t, e.gw2)
	if _, err := k.Sync(); err != nil {
		t.Fatalf("Sync after the route change: %v", err)
	}
	converges("gateway 2")
	if !e.hasNeigh(e.gw2) {
		t.Errorf("no neighbour entry for %s after the route change", e.gw2)
	}
}

// Sync covers every next hop of every destination, keeps going past a
// destination it cannot resolve or a next hop it cannot keep, and logs each
// failure once however often it repeats. Unprivileged: all inputs are fakes.
func TestEncapNeighKeeperSync(t *testing.T) {
	gw := func(s string) net.IP { return net.ParseIP(s) }
	k := &EncapNeighKeeper{
		dests: func() ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("fc00::1"), netip.MustParseAddr("fc00::2"), netip.MustParseAddr("fc00::3")}, nil
		},
		resolve: func(dst net.IP) ([]NeighTarget, error) {
			switch dst.String() {
			case "fc00::1":
				return []NeighTarget{{2, gw("fe80::1")}, {3, gw("fe80::2")}}, nil
			case "fc00::2":
				return []NeighTarget{{2, gw("fe80::1")}}, nil // shared with fc00::1
			}
			return nil, errors.New("no route")
		},
		logger: zap.NewNop(),
		kept:   map[string]NeighTarget{},
		failed: map[string]string{},
	}
	var calls []string
	k.keep = func(ifindex uint32, ip net.IP) error {
		calls = append(calls, NeighTarget{ifindex, ip}.key())
		if ifindex == 3 {
			return os.ErrPermission
		}
		return nil
	}
	for range 2 {
		got, err := k.Sync()
		if err == nil {
			t.Error("Sync with an unresolvable destination and a failing keep: want an error")
		}
		if len(got) != 2 {
			t.Errorf("targets = %+v, want both next hops", got)
		}
	}
	slices.Sort(calls)
	if !slices.Equal(calls, []string{"2/fe80::1", "2/fe80::1", "3/fe80::2", "3/fe80::2"}) {
		t.Errorf("keep calls = %v, want each next hop once per sync", calls)
	}
	if len(k.failed) != 2 {
		t.Errorf("failures recorded = %v, want the resolve and the keep", k.failed)
	}
	if !k.isKept(2, gw("fe80::1")) || k.isKept(4, gw("fe80::1")) {
		t.Error("isKept does not match the synced next hops")
	}
}
