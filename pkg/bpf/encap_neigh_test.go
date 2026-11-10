package bpf

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/takehaya/vinbero/pkg/config"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
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

// neighCount is the number of global unicast neighbour entries on the
// uplink (the kernel's own multicast and link-local entries left out).
func (e *encapNeighEnv) neighCount() int {
	neighs, _ := netlink.NeighList(e.uplink, netlink.FAMILY_V6)
	n := 0
	for _, x := range neighs {
		if x.IP.IsGlobalUnicast() {
			n++
		}
	}
	return n
}

// A tenant encapsulation from an enslaved AC, with a static underlay route
// and no neighbour entry for its gateway, cannot recover by itself: XDP
// hands the packet to the kernel, which drops it at the VRF table's
// unreachable default, so the gateway is never solicited. Once the keeper
// has swept, the kernel resolves the gateway with no other traffic, and the
// encapsulation is redirected to it. After the route moves to another
// gateway, a pass makes that one resolve and gives the first one back;
// flipping the route back and forth does not grow the neighbour table.
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

	k := NewEncapNeighKeeper(h.mapOps, zap.NewNop())
	targets, err := k.Sweep()
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(targets) != 1 || targets[0].Ifindex != uint32(e.uplink) || !targets[0].IP.Equal(e.gw1) {
		t.Fatalf("keeper covers %+v, want gw1 on the uplink", targets)
	}
	converges("gateway 1")

	reroute := func(gw net.IP) {
		t.Helper()
		e.routeSIDsVia(t, gw)
		k.setFlag(true, false)
		if err := k.pass(); err != nil {
			t.Fatalf("pass after the route change: %v", err)
		}
	}
	reroute(e.gw2)
	converges("gateway 2")
	if e.hasNeigh(e.gw1) {
		t.Errorf("the managed entry for %s is still there after no destination uses it", e.gw1)
	}
	for i := range 20 {
		if i%2 == 0 {
			reroute(e.gw1)
		} else {
			reroute(e.gw2)
		}
	}
	if n := e.neighCount(); n > 1 {
		neighs, _ := netlink.NeighList(e.uplink, netlink.FAMILY_V6)
		t.Errorf("%d neighbour entries on the uplink after 20 route changes, want 1: %+v", n, neighs)
	}
	converges("gateway 2 after the churn")
}

// The keeper keeps both next hops the data plane can use: the main table's
// (a tenant AC's direct lookup) and the one the ip rules select (the global
// VRF's lookup), here a rule ahead of main that sends the SIDs to table 200.
// A destination behind a blackhole route has no next hop, which is not an
// error.
func TestEncapNeighKeeperMainAndRuleNexthops(t *testing.T) {
	h := newXDPTestHelper(t)
	e := newEncapNeighEnv(t)
	_, sids, _ := net.ParseCIDR("fc00:e00::/32")
	if err := netlink.RouteAdd(&netlink.Route{Dst: sids, Gw: e.gw2, LinkIndex: e.uplink, Table: 200}); err != nil {
		t.Fatal(err)
	}
	rule := netlink.NewRule()
	rule.Family = netlink.FAMILY_V6
	rule.Dst = sids
	rule.Table = 200
	rule.Priority = 100
	if err := netlink.RuleAdd(rule); err != nil {
		t.Fatalf("RuleAdd: %v", err)
	}
	_, hole, _ := net.ParseCIDR("fc00:dead::/32")
	if err := netlink.RouteAdd(&netlink.Route{Dst: hole, Type: unix.RTN_BLACKHOLE}); err != nil {
		t.Fatal(err)
	}

	src, _ := ParseIPv6("fc00:e01::1")
	for i, sid := range []string{"fc00:e00::1", "fc00:dead::1"} {
		segs, n, _ := ParseSegments([]string{sid})
		h.createHeadendEntry(fmt.Sprintf("10.9%d.0.0/24", i), src, [16]byte{}, segs, n, true)
	}
	core, logs := observer.New(zap.WarnLevel)
	k := NewEncapNeighKeeper(h.mapOps, zap.New(core))
	targets, err := k.Sweep()
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	var ips []string
	for _, tg := range targets {
		ips = append(ips, tg.IP.String())
	}
	slices.Sort(ips)
	if !slices.Equal(ips, []string{e.gw1.String(), e.gw2.String()}) {
		t.Errorf("next hops = %v, want the main table's %s and the rule's %s", ips, e.gw1, e.gw2)
	}
	if logs.Len() != 0 {
		t.Errorf("warnings for a normal configuration: %v", logs.All())
	}
}

// ===== Unprivileged: the keeper's logic with fakes =====

type fakeNeighTable struct {
	entries map[string]netlink.Neigh // "ifindex/ip"
	lists   int
	sets    []string
	dels    []string
}

func (f *fakeNeighTable) ops() neighOps {
	return neighOps{
		list: func(ifindex, family int) ([]netlink.Neigh, error) {
			f.lists++
			var out []netlink.Neigh
			for _, n := range f.entries {
				if n.LinkIndex == ifindex {
					out = append(out, n)
				}
			}
			return out, nil
		},
		setManaged: func(ifindex uint32, ip net.IP) error {
			key := neighKey(ifindex, ip)
			f.sets = append(f.sets, key)
			f.entries[key] = netlink.Neigh{LinkIndex: int(ifindex), IP: ip, FlagsExt: netlink.NTF_EXT_MANAGED, Flags: netlink.NTF_EXT_LEARNED}
			return nil
		},
		del: func(n netlink.Neigh) error {
			key := neighKey(uint32(n.LinkIndex), n.IP)
			f.dels = append(f.dels, key)
			delete(f.entries, key)
			return nil
		},
	}
}

func route(cidr string, gw string, link int) netlink.Route {
	_, dst, _ := net.ParseCIDR(cidr)
	r := netlink.Route{Dst: dst, LinkIndex: link, Type: unix.RTN_UNICAST}
	if gw != "" {
		r.Gw = net.ParseIP(gw)
	}
	return r
}

// newFakeKeeper is a keeper over a fixed main table, a rule lookup that
// finds nothing, and a fake neighbour table. walk is what the maps hold.
func newFakeKeeper(t *testing.T, main *[]netlink.Route, walk *[]netip.Addr, nt *fakeNeighTable, lg *zap.Logger) (*EncapNeighKeeper, *int) {
	t.Helper()
	ruleGets := 0
	k := NewEncapNeighKeeper(nil, lg)
	k.walk = func() ([]netip.Addr, error) { return slices.Clone(*walk), nil }
	k.res = resolver{
		dumpMain: func() ([]netlink.Route, error) { return *main, nil },
		ruleGet: func(net.IP) ([]netlink.Route, error) {
			ruleGets++
			return nil, unix.ENETUNREACH
		},
	}
	k.neigh = nt.ops()
	return k, &ruleGets
}

// A write resolves only its new destinations; the neighbour table is read
// once per device and family per pass however many next hops it holds; a
// next hop no destination uses any more is given back, and only if the
// keeper made it: static entries, entries already managed by someone else
// and BUM next hops stay.
func TestEncapNeighKeeperIncremental(t *testing.T) {
	main := []netlink.Route{
		route("fc00:1::/32", "fe80::1", 2),
		route("fc00:2::/32", "fe80::2", 2),
		route("fc00:3::/32", "fe80::3", 2),
		route("fc00:4::/32", "fe80::4", 3),
		route("fc00:5::/32", "fe80::5", 3),
	}
	walk := []netip.Addr{netip.MustParseAddr("fc00:1::1"), netip.MustParseAddr("fc00:2::1")}
	nt := &fakeNeighTable{entries: map[string]netlink.Neigh{
		neighKey(3, net.ParseIP("fe80::4")): {LinkIndex: 3, IP: net.ParseIP("fe80::4"), State: netlink.NUD_PERMANENT},
		neighKey(3, net.ParseIP("fe80::5")): {LinkIndex: 3, IP: net.ParseIP("fe80::5"), FlagsExt: netlink.NTF_EXT_MANAGED},
	}}
	k, ruleGets := newFakeKeeper(t, &main, &walk, nt, zap.NewNop())

	if _, err := k.Sweep(); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if nt.lists != 1 || len(nt.sets) != 2 {
		t.Errorf("sweep: %d neighbour lists, %d sets; want 1 list (one device) and 2 sets", nt.lists, len(nt.sets))
	}

	// A write of a known destination and three new ones: only the new
	// ones are resolved.
	*ruleGets = 0
	nt.lists = 0
	k.Notify([]netip.Addr{netip.MustParseAddr("fc00:1::1"), netip.MustParseAddr("fc00:3::1"),
		netip.MustParseAddr("fc00:4::1"), netip.MustParseAddr("fc00:5::1")})
	if err := k.pass(); err != nil {
		t.Fatalf("pass: %v", err)
	}
	if *ruleGets != 3 {
		t.Errorf("rule lookups = %d, want 3 (the new destinations only)", *ruleGets)
	}
	if nt.lists != 2 {
		t.Errorf("neighbour lists = %d, want 2 (one per device)", nt.lists)
	}
	if !slices.Contains(nt.sets, neighKey(2, net.ParseIP("fe80::3"))) || len(nt.sets) != 3 {
		t.Errorf("sets = %v, want fe80::3 added and the static / foreign-managed ones left", nt.sets)
	}

	// The maps no longer hold fc00:2, fc00:4 and fc00:5: fe80::2 (the
	// keeper's) goes, the static fe80::4 and the foreign fe80::5 stay. A BUM
	// next hop stays too.
	bumNeighClaims.Store(neighKey(2, net.ParseIP("fe80::3")), struct{}{})
	t.Cleanup(func() { bumNeighClaims.Delete(neighKey(2, net.ParseIP("fe80::3"))) })
	walk = []netip.Addr{netip.MustParseAddr("fc00:1::1")}
	for range sweepsBeforeRelease {
		if _, err := k.Sweep(); err != nil {
			t.Fatalf("Sweep: %v", err)
		}
	}
	if !slices.Equal(nt.dels, []string{neighKey(2, net.ParseIP("fe80::2"))}) {
		t.Errorf("released = %v, want only the keeper's fe80::2", nt.dels)
	}
	for _, keep := range []string{"3/fe80::4", "3/fe80::5", "2/fe80::3", "2/fe80::1"} {
		if _, ok := nt.entries[keep]; !ok {
			t.Errorf("%s was removed", keep)
		}
	}
}

// The main table index picks the longest prefix and, among equal prefixes,
// the lowest metric. A reject route and a nexthop-object route have no next
// hop; the latter is warned about once, however many passes see it, and a
// reject route is not warned about at all.
func TestEncapNeighKeeperResolution(t *testing.T) {
	low := route("fc00:1::/32", "fe80::2", 2)
	low.Priority = 10
	high := route("fc00:1::/32", "fe80::3", 2)
	high.Priority = 20
	hole := route("fc00:2::/32", "", 0)
	hole.Type = unix.RTN_BLACKHOLE
	nh := route("fc00:3::/32", "", 0) // RTA_NH_ID only
	multi := route("fc00:4::/32", "", 0)
	multi.MultiPath = []*netlink.NexthopInfo{{LinkIndex: 2, Gw: net.ParseIP("fe80::7")}, {LinkIndex: 3, Gw: net.ParseIP("fe80::8")}}
	main := []netlink.Route{route("fc00::/16", "fe80::1", 2), high, low, hole, nh, multi, route("fc00:5::/32", "", 4)}
	walk := []netip.Addr{
		netip.MustParseAddr("fc00:1::1"), netip.MustParseAddr("fc00:2::1"), netip.MustParseAddr("fc00:3::1"),
		netip.MustParseAddr("fc00:4::1"), netip.MustParseAddr("fc00:5::1"), netip.MustParseAddr("fc00:6::1"),
	}
	core, logs := observer.New(zap.WarnLevel)
	nt := &fakeNeighTable{entries: map[string]netlink.Neigh{}}
	k, _ := newFakeKeeper(t, &main, &walk, nt, zap.New(core))
	for range 3 {
		if _, err := k.Sweep(); err != nil {
			t.Fatalf("Sweep: %v", err)
		}
	}
	got := map[string][]string{}
	for d, ts := range k.dests {
		for _, tg := range ts {
			got[d.String()] = append(got[d.String()], tg.key())
		}
		slices.Sort(got[d.String()])
	}
	want := map[string][]string{
		"fc00:1::1": {"2/fe80::2"},
		"fc00:4::1": {"2/fe80::7", "3/fe80::8"},
		"fc00:5::1": {"4/fc00:5::1"},
		"fc00:6::1": {"2/fe80::1"},
	}
	for d, w := range want {
		if !slices.Equal(got[d], w) {
			t.Errorf("%s: next hops %v, want %v", d, got[d], w)
		}
	}
	for _, d := range []string{"fc00:2::1", "fc00:3::1"} {
		if len(got[d]) != 0 {
			t.Errorf("%s: next hops %v, want none", d, got[d])
		}
	}
	if n := logs.FilterMessageSnippet("nexthop_compat_mode").Len(); n != 1 {
		t.Errorf("nexthop-object warnings = %d, want 1", n)
	}
	if logs.Len() != 1 {
		t.Errorf("warnings = %v, want only the nexthop-object one", logs.All())
	}
}

// Every function in this package that writes an encapsulation map hands the
// written destinations to the keeper (encapWrote), or is listed here with
// the reason it does not. A new writer that forgets fails this test.
func TestEncapMapWritersNotify(t *testing.T) {
	encapMaps := map[string]bool{
		"HeadendV4Map": true, "HeadendV6Map": true, "MupUplinkV4Map": true, "MupUplinkV6Map": true,
		"EcmpPathMap": true, "SrPolicyMap": true, "HeadendL2Map": true, "BdPeerMap": true,
		"ServiceIngressMap": true, "SidAuxMap": true,
	}
	exempt := map[string]string{
		"releaseSupersededBuiltinAux": "zeroes a freed aux slot",
		"deleteSidFunctionInternal":   "zeroes the aux of a deleted SID",
		"PutPluginAux":                "plugin-defined aux; End.B6 policies are built-in aux",
		"FreePluginAux":               "zeroes a freed aux slot",
	}
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") || strings.HasPrefix(path, "bpf_bpfe") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			writes, notifies := "", false
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch fun := call.Fun.(type) {
				case *ast.SelectorExpr:
					if fun.Sel.Name == "encapWrote" {
						notifies = true
					}
					if inner, ok := fun.X.(*ast.SelectorExpr); ok && encapMaps[inner.Sel.Name] {
						switch fun.Sel.Name {
						case "Put", "Update", "BatchUpdate":
							writes = inner.Sel.Name
						}
					}
				case *ast.Ident:
					if fun.Name == "putMainAndOwner" || fun.Name == "putControlEntry" {
						if len(call.Args) > 0 {
							if sel, ok := call.Args[0].(*ast.SelectorExpr); ok && encapMaps[sel.Sel.Name] {
								writes = sel.Sel.Name
							}
						}
					}
				}
				return true
			})
			if writes == "" {
				continue
			}
			checked++
			if _, ok := exempt[fn.Name.Name]; ok {
				continue
			}
			if !notifies {
				t.Errorf("%s: %s writes %s but does not call encapWrote", fset.Position(fn.Pos()), fn.Name.Name, writes)
			}
		}
	}
	if checked < 10 {
		t.Errorf("found %d writers, the scan is not seeing them", checked)
	}
}

// The resweep's map walk on a large table: about 100k IPv4 headend entries
// over 100 SIDs. Opt-in (VINBERO_ENCAP_SCALE=1), as it needs a large map and
// root; it reports the time of the walk and of a full sweep.
func TestEncapSweepScale(t *testing.T) {
	if os.Getenv("VINBERO_ENCAP_SCALE") == "" {
		t.Skip("set VINBERO_ENCAP_SCALE=1 to run")
	}
	const n = 100_000
	cfg := &config.Config{}
	cfg.Setting.Entries.Headendv4.Capacity = n + 1024
	objs, err := ReadCollection(nil, cfg)
	if err != nil {
		t.Fatalf("ReadCollection: %v", err)
	}
	defer func() { _ = objs.Close() }()
	m := NewMapOperations(objs)
	src, _ := ParseIPv6("fc00:e01::1")
	for i := range n {
		segs, nseg, _ := ParseSegments([]string{fmt.Sprintf("fc00:%x::1", 0x100+i%100)})
		prefix := fmt.Sprintf("10.%d.%d.0/24", i/256%256, i%256)
		if i >= 65536 {
			prefix = fmt.Sprintf("11.%d.%d.0/24", (i-65536)/256%256, i%256)
		}
		if err := m.CreateHeadendV4(prefix, &HeadendEntry{Mode: modeHEncaps, NumSegments: nseg, SrcAddr: src, Segments: segs}, OwnerRPC); err != nil {
			t.Fatalf("CreateHeadendV4 %d: %v", i, err)
		}
	}
	start := time.Now()
	dsts, err := m.EncapDestinations()
	walk := time.Since(start)
	if err != nil || len(dsts) != 100 {
		t.Fatalf("EncapDestinations = %d, %v; want 100", len(dsts), err)
	}
	inNewNetns(t)
	k := NewEncapNeighKeeper(m, zap.NewNop())
	start = time.Now()
	if _, err := k.Sweep(); err != nil {
		t.Logf("Sweep: %v", err)
	}
	sweep := time.Since(start)
	t.Logf("walk of %d headend entries: %v; full sweep (walk, resolution of %d destinations, neighbours): %v; resweep interval %v",
		n, walk, len(dsts), sweep, encapNeighResweep)
	if sweep > encapNeighResweep/10 {
		t.Errorf("a sweep takes %v, not small against the %v interval", sweep, encapNeighResweep)
	}
}

// When the route subscription ends (an ENOBUFS overflow), the keeper
// subscribes again, re-resolves its destinations, and keeps reacting to the
// new subscription's events. Unprivileged: the subscriptions are fakes.
func TestEncapNeighKeeperResubscribes(t *testing.T) {
	resubscribeDelay = 10 * time.Millisecond
	t.Cleanup(func() { resubscribeDelay = time.Second })
	main := []netlink.Route{route("fc00:1::/32", "fe80::1", 2)}
	walk := []netip.Addr{netip.MustParseAddr("fc00:1::1")}
	nt := &fakeNeighTable{entries: map[string]netlink.Neigh{}}
	k, ruleGets := newFakeKeeper(t, &main, &walk, nt, zap.NewNop())
	var mu sync.Mutex
	gets := func() int { mu.Lock(); defer mu.Unlock(); return *ruleGets }
	k.res.ruleGet = func(net.IP) ([]netlink.Route, error) {
		mu.Lock()
		*ruleGets++
		mu.Unlock()
		return nil, unix.ENETUNREACH
	}
	if _, err := k.Sweep(); err != nil {
		t.Fatal(err)
	}
	newSub := func() *routeSub {
		return &routeSub{routes: make(chan netlink.RouteUpdate, 1), nexthops: make(chan struct{}, 1), done: make(chan struct{})}
	}
	subs := make(chan *routeSub, 4)
	k.subRoutes = func() (*routeSub, error) {
		s := newSub()
		subs <- s
		return s, nil
	}
	first := newSub()
	neighs := &neighSub{updates: make(chan netlink.NeighUpdate), done: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go k.watch(ctx, first, neighs)

	waitFor := func(what string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s", what)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	base := gets()
	close(first.routes) // the subscription ended
	var second *routeSub
	select {
	case second = <-subs:
	case <-time.After(5 * time.Second):
		t.Fatal("the keeper did not subscribe again")
	}
	waitFor("a re-resolution after the resubscribe", func() bool { return gets() > base })
	select {
	case <-first.done:
	default:
		t.Error("the ended subscription was not closed")
	}
	base = gets()
	second.routes <- netlink.RouteUpdate{}
	waitFor("a re-resolution after an event on the new subscription", func() bool { return gets() > base })
}

// Pruning is conservative. A walk that failed part-way removes nothing; a
// destination written while a walk runs counts as seen by it; a destination
// complete walks miss is dropped only at the second miss in a row, and a
// write in between resets the count; a write after the walk that drops a
// destination, before its next hop is given back, keeps it.
func TestEncapNeighKeeperConservativePrune(t *testing.T) {
	a, b := netip.MustParseAddr("fc00:1::1"), netip.MustParseAddr("fc00:2::1")
	main := []netlink.Route{route("fc00:1::/32", "fe80::1", 2), route("fc00:2::/32", "fe80::2", 2)}
	walk := []netip.Addr{a, b}
	nt := &fakeNeighTable{entries: map[string]netlink.Neigh{}}
	k, _ := newFakeKeeper(t, &main, &walk, nt, zap.NewNop())
	if _, err := k.Sweep(); err != nil {
		t.Fatal(err)
	}
	bKey := neighKey(2, net.ParseIP("fe80::2"))
	kept := func(what string) {
		t.Helper()
		if _, ok := k.dests[b]; !ok {
			t.Fatalf("%s: fc00:2::1 was dropped", what)
		}
		if len(nt.dels) != 0 {
			t.Fatalf("%s: neighbours deleted: %v", what, nt.dels)
		}
	}

	// An aborted walk that returned only a.
	k.walk = func() ([]netip.Addr, error) { return []netip.Addr{a}, errors.New("iteration aborted") }
	for range 3 {
		_, _ = k.Sweep()
	}
	kept("incomplete walks")

	// Complete walks that miss b, but b is written during each of them.
	k.walk = func() ([]netip.Addr, error) {
		k.Notify([]netip.Addr{b})
		return []netip.Addr{a}, nil
	}
	for range 3 {
		if _, err := k.Sweep(); err != nil {
			t.Fatal(err)
		}
	}
	kept("walks during which b was written")

	// One complete miss, then a write, then one more miss: still kept.
	k.walk = func() ([]netip.Addr, error) { return []netip.Addr{a}, nil }
	if _, err := k.Sweep(); err != nil {
		t.Fatal(err)
	}
	k.Notify([]netip.Addr{b})
	if err := k.pass(); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Sweep(); err != nil {
		t.Fatal(err)
	}
	kept("a miss, a write, a miss")

	// The second miss in a row, but b is written after the walk, while the
	// sweep resolves, before the release: kept, and back in the set.
	k.res.dumpMain = func() ([]netlink.Route, error) {
		k.Notify([]netip.Addr{b})
		return main, nil
	}
	if _, err := k.Sweep(); err != nil {
		t.Fatal(err)
	}
	kept("a miss, then a miss with a write before the release")
	if ts := k.dests[b]; len(ts) != 1 || ts[0].key() != bKey {
		t.Fatalf("fc00:2::1 next hops = %v, want %s", ts, bKey)
	}
	k.res.dumpMain = func() ([]netlink.Route, error) { return main, nil }

	// Two complete misses in a row: dropped and given back. A writer that
	// notifies b between the release check and the delete cannot get in: it
	// waits for the delete, and the next pass resolves b again as new.
	var writer sync.WaitGroup
	k.beforeReleaseDel = func(tg NeighTarget) {
		if tg.key() != bKey {
			return
		}
		if k.pmu.TryLock() {
			k.pmu.Unlock()
			t.Error("a writer can notify between the release check and the delete")
		}
		writer.Add(1)
		go func() {
			defer writer.Done()
			k.Notify([]netip.Addr{b})
		}()
	}
	for range sweepsBeforeRelease {
		if _, err := k.Sweep(); err != nil {
			t.Fatal(err)
		}
	}
	writer.Wait()
	if _, ok := k.dests[b]; ok {
		t.Fatal("fc00:2::1 kept after two complete misses in a row")
	}
	if !slices.Equal(nt.dels, []string{bKey}) {
		t.Errorf("released = %v, want %s", nt.dels, bKey)
	}
	sets := len(nt.sets)
	if err := k.pass(); err != nil {
		t.Fatal(err)
	}
	if _, ok := k.dests[b]; !ok || len(nt.sets) != sets+1 || nt.sets[sets] != bKey {
		t.Errorf("after the write that waited for the delete: in set %v, sets %v; want fc00:2::1 resolved again and %s managed", ok, nt.sets[sets:], bKey)
	}
}

// A release whose neighbour list or delete fails stays owned and is retried
// by a later pass until the entry is gone.
func TestEncapNeighKeeperRetriesRelease(t *testing.T) {
	d := netip.MustParseAddr("fc00:1::1")
	main := []netlink.Route{route("fc00:1::/32", "fe80::1", 2)}
	walk := []netip.Addr{d}
	nt := &fakeNeighTable{entries: map[string]netlink.Neigh{}}
	k, _ := newFakeKeeper(t, &main, &walk, nt, zap.NewNop())
	if _, err := k.Sweep(); err != nil {
		t.Fatal(err)
	}
	oldKey := neighKey(2, net.ParseIP("fe80::1"))
	ops := nt.ops()
	failList, failDel := true, true
	k.neigh.list = func(ifindex, family int) ([]netlink.Neigh, error) {
		if failList && ifindex == 2 {
			return nil, errors.New("dump interrupted")
		}
		return ops.list(ifindex, family)
	}
	k.neigh.del = func(n netlink.Neigh) error {
		if failDel {
			return unix.EBUSY
		}
		return ops.del(n)
	}
	// The next hop moves to another device: fe80::1 on 2 is no longer used.
	main = []netlink.Route{route("fc00:1::/32", "fe80::9", 3)}
	reroute := func() {
		t.Helper()
		k.setFlag(true, false)
		_ = k.pass()
	}
	reroute()
	if _, ok := k.owned[oldKey]; !ok {
		t.Fatal("ownership dropped although the neighbour list failed")
	}
	failList = false
	reroute()
	if _, ok := k.owned[oldKey]; !ok {
		t.Fatal("ownership dropped although the delete failed")
	}
	if _, ok := nt.entries[oldKey]; !ok {
		t.Fatal("the entry is gone although the delete failed")
	}
	failDel = false
	reroute()
	if _, ok := k.owned[oldKey]; ok {
		t.Error("still owned after the delete succeeded")
	}
	if _, ok := nt.entries[oldKey]; ok {
		t.Error("the entry was not removed on the retry")
	}
}
