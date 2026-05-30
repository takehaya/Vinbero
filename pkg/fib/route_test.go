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
		Prefix:  netip.MustParsePrefix("fd00:dead::/64"),
		NextHop: netip.MustParseAddr("fd00:f1b::2"),
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
	if routes[0].NextHop != r.NextHop {
		t.Errorf("listed nexthop = %s, want %s", routes[0].NextHop, r.NextHop)
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
		Prefix:  netip.MustParsePrefix("fd00:beef::/64"),
		NextHop: netip.MustParseAddr("fd00:f1b::2"),
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
	if err := inj.Add(Route{Prefix: bgpPrefix, NextHop: netip.MustParseAddr("fd00:f1b::2")}); err != nil {
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
