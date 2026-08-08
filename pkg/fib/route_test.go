package fib

import (
	"net"
	"net/netip"
	"runtime"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

func TestIPNetToPrefix(t *testing.T) {
	// A 4-in-6 net.IP must render as a plain IPv4 prefix.
	v4 := &net.IPNet{IP: net.ParseIP("10.0.0.0"), Mask: net.CIDRMask(24, 32)}
	if p, ok := IPNetToPrefix(v4); !ok || p.String() != "10.0.0.0/24" || !p.Addr().Is4() {
		t.Errorf("IPNetToPrefix(10.0.0.0/24) = %q ok=%v is4=%v", p, ok, p.Addr().Is4())
	}
	_, v6, _ := net.ParseCIDR("2001:db8::/64")
	if p, ok := IPNetToPrefix(v6); !ok || p.String() != "2001:db8::/64" {
		t.Errorf("IPNetToPrefix(2001:db8::/64) = %q ok=%v", p, ok)
	}
}

// withTestNetns moves the calling goroutine's OS thread into a fresh
// network namespace with one up dummy interface, so route mutations
// never touch the host's real routing table. Requires CAP_NET_ADMIN
// (run via `go test -exec sudo`).
func withTestNetns(t *testing.T) {
	t.Helper()
	runtime.LockOSThread()
	orig, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatalf("netns.Get: %v", err)
	}
	ns, err := netns.New() // creates the namespace and enters it
	if err != nil {
		_ = orig.Close()
		runtime.UnlockOSThread()
		t.Fatalf("netns.New (needs root / CAP_NET_ADMIN): %v", err)
	}
	t.Cleanup(func() {
		_ = netns.Set(orig)
		_ = orig.Close()
		_ = ns.Close()
		runtime.UnlockOSThread()
	})

	// A dummy interface with an address gives routes a valid on-link
	// nexthop scope.
	dummy := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "fibtest0"}}
	if err := netlink.LinkAdd(dummy); err != nil {
		t.Fatalf("LinkAdd dummy: %v", err)
	}
	if err := netlink.LinkSetUp(dummy); err != nil {
		t.Fatalf("LinkSetUp: %v", err)
	}
	addr, err := netlink.ParseAddr("fd00:f1b::1/64")
	if err != nil {
		t.Fatalf("ParseAddr: %v", err)
	}
	if err := netlink.AddrAdd(dummy, addr); err != nil {
		t.Fatalf("AddrAdd: %v", err)
	}
}

func TestKernelInjector_AddListDelete(t *testing.T) {
	withTestNetns(t)
	inj := NewKernelInjector()
	r := Route{
		Prefix:   netip.MustParsePrefix("fd00:dead::/64"),
		NextHops: []NextHop{{Gw: netip.MustParseAddr("fd00:f1b::2")}},
	}
	if err := inj.Add(r); err != nil {
		t.Fatalf("Add: %v", err)
	}
	routes, err := inj.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("List = %d routes, want 1", len(routes))
	}
	if routes[0].Prefix != r.Prefix {
		t.Errorf("listed prefix = %s, want %s", routes[0].Prefix, r.Prefix)
	}
	if len(routes[0].NextHops) != 1 || routes[0].NextHops[0].Gw != r.NextHops[0].Gw {
		t.Errorf("listed nexthops = %v, want %v", routes[0].NextHops, r.NextHops)
	}

	if err := inj.Delete(r.Prefix); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	routes, err = inj.List()
	if err != nil {
		t.Fatalf("List after delete: %v", err)
	}
	if len(routes) != 0 {
		t.Errorf("after Delete, List = %d routes, want 0", len(routes))
	}
}

func TestKernelInjector_AddIsIdempotent(t *testing.T) {
	withTestNetns(t)
	inj := NewKernelInjector()
	r := Route{
		Prefix:   netip.MustParsePrefix("fd00:beef::/64"),
		NextHops: []NextHop{{Gw: netip.MustParseAddr("fd00:f1b::2")}},
	}
	if err := inj.Add(r); err != nil {
		t.Fatalf("first Add: %v", err)
	}
	if err := inj.Add(r); err != nil {
		t.Errorf("second Add (must be idempotent via RouteReplace): %v", err)
	}
}

func TestKernelInjector_DeleteAbsentIsNoop(t *testing.T) {
	withTestNetns(t)
	inj := NewKernelInjector()
	if err := inj.Delete(netip.MustParsePrefix("fd00:0:0:99::/64")); err != nil {
		t.Errorf("Delete of an absent prefix should be a no-op, got %v", err)
	}
}

// TestKernelInjector_ListFiltersByProtocol confirms List only returns
// Vinbero's RTPROT_BGP routes, not entries other daemons own.
func TestKernelInjector_ListFiltersByProtocol(t *testing.T) {
	withTestNetns(t)
	link, err := netlink.LinkByName("fibtest0")
	if err != nil {
		t.Fatalf("LinkByName: %v", err)
	}
	// A non-BGP (static) route installed directly: List must skip it.
	staticDst := &net.IPNet{IP: net.ParseIP("fd00:cafe::"), Mask: net.CIDRMask(64, 128)}
	if err := netlink.RouteAdd(&netlink.Route{
		Dst:       staticDst,
		LinkIndex: link.Attrs().Index,
		Protocol:  netlink.RouteProtocol(unix.RTPROT_STATIC),
	}); err != nil {
		t.Fatalf("RouteAdd static: %v", err)
	}

	inj := NewKernelInjector()
	bgpPrefix := netip.MustParsePrefix("fd00:dead::/64")
	if err := inj.Add(Route{Prefix: bgpPrefix, NextHops: []NextHop{{Gw: netip.MustParseAddr("fd00:f1b::2")}}}); err != nil {
		t.Fatalf("Add BGP route: %v", err)
	}

	routes, err := inj.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("List = %d routes, want 1 (BGP-only, static excluded)", len(routes))
	}
	if routes[0].Prefix != bgpPrefix {
		t.Errorf("listed prefix = %s, want %s", routes[0].Prefix, bgpPrefix)
	}
}

// TestWeightToHops pins the conversion at the netlink boundary. The kernel
// carries rtnh_hops, which is one less than the weight it documents, so
// passing a weight straight through would silently give every next hop one
// extra share.
func TestWeightToHops(t *testing.T) {
	cases := []struct{ weight, hops int }{
		{0, 0}, // unset reads as an equal share
		{1, 0},
		{2, 1},
		{16, 15},
		{-3, 0}, // nonsense weight must not underflow into a huge share
	}
	for _, c := range cases {
		if got := weightToHops(c.weight); got != c.hops {
			t.Errorf("weightToHops(%d) = %d, want %d", c.weight, got, c.hops)
		}
	}
}

// A prefix reachable through several PEs must reach the kernel as a real
// multipath route and come back describing the same next hops, weights
// included. The weight is where this is easy to get wrong: it round trips
// through rtnh_hops, which is one less.
func TestKernelInjector_MultipathRoundTrip(t *testing.T) {
	withTestNetns(t)
	inj := NewKernelInjector()

	prefix := netip.MustParsePrefix("2001:db8:abcd::/64")
	want := Route{
		Prefix: prefix,
		NextHops: []NextHop{
			{Gw: netip.MustParseAddr("fd00:f1b::2"), Weight: 1},
			{Gw: netip.MustParseAddr("fd00:f1b::3"), Weight: 3},
		},
	}
	if err := inj.Add(want); err != nil {
		t.Fatalf("Add multipath: %v", err)
	}

	routes, err := inj.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var got *Route
	for i := range routes {
		if routes[i].Prefix == prefix {
			got = &routes[i]
			break
		}
	}
	if got == nil {
		t.Fatalf("multipath route not listed; got %v", routes)
	}
	if len(got.NextHops) != 2 {
		t.Fatalf("read back %d next hops, want 2: %+v", len(got.NextHops), got.NextHops)
	}
	byGw := map[string]int{}
	for _, nh := range got.NextHops {
		byGw[nh.Gw.String()] = nh.Weight
	}
	for _, w := range want.NextHops {
		if got := byGw[w.Gw.String()]; got != w.Weight {
			t.Errorf("next hop %s weight = %d, want %d (rtnh_hops conversion)",
				w.Gw, got, w.Weight)
		}
	}

	if err := inj.Delete(prefix); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

// One next hop must stay a plain gateway route. The kernel normalizes a
// one-element multipath to that form anyway, so encoding it as multipath
// would make the route stop comparing equal to itself after a round trip.
func TestKernelInjector_SingleNextHopIsNotMultipath(t *testing.T) {
	r := Route{
		Prefix:   netip.MustParsePrefix("2001:db8:1::/64"),
		NextHops: []NextHop{{Gw: netip.MustParseAddr("fd00:f1b::2")}},
	}
	nl, err := toNetlinkRoute(r)
	if err != nil {
		t.Fatalf("toNetlinkRoute: %v", err)
	}
	if len(nl.MultiPath) != 0 {
		t.Errorf("single next hop encoded as multipath: %v", nl.MultiPath)
	}
	if nl.Gw == nil {
		t.Error("single next hop must set Gw")
	}
}
