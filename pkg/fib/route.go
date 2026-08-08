// Package fib installs and removes routes in the kernel forwarding
// information base on behalf of BGP-learned prefixes. Vinbero's XDP data
// plane resolves next hops with bpf_fib_lookup, which reads the kernel
// FIB -- so an IPv6 unicast route received over BGP must be pushed into
// the kernel routing table for the data plane to use it.
//
// Every route written here is tagged with RTPROT_BGP, so an operator can
// list exactly Vinbero's BGP-driven entries with `ip route show proto
// bgp` and List() can filter to them without disturbing routes owned by
// other daemons.
package fib

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// routeProtocol marks every FIB entry Vinbero installs as BGP-originated.
const routeProtocol = netlink.RouteProtocol(unix.RTPROT_BGP)

// NextHop is one way out for a prefix. At least one of Gw and Ifindex must
// be set: with neither there is nothing for the kernel to resolve the hop
// against. (A route with no next hop at all is a different thing and is
// expressed by leaving Route.NextHops empty.)
//
// Weight is the natural 1-based share the kernel documents, NOT the
// rtnh_hops value carried on the wire, which is one less. The conversion
// happens at the netlink boundary so nothing above it has to remember that
// a weight of 1 is encoded as 0. Any weight at or below 1 is read as an
// equal share: a zero weight would mean a next hop that takes no traffic,
// which no caller means by leaving the field unset, and clamping a negative
// one is safer than letting it underflow into an enormous share.
type NextHop struct {
	Gw      netip.Addr // zero value => on-link via Ifindex, which is then required
	Ifindex int        // 0 = let the kernel resolve it from Gw, which is then required
	Weight  int        // <= 1 = an equal share
}

// validate rejects a next hop the kernel could not resolve. Catching it here
// turns a caller's mistake into an error naming the hop, rather than an
// opaque netlink failure or, worse, a route that installs and blackholes.
func (nh NextHop) validate(i int) error {
	if !nh.Gw.IsValid() && nh.Ifindex == 0 {
		return fmt.Errorf("fib: next hop %d has neither a gateway nor an interface", i)
	}
	return nil
}

// Route is a kernel FIB entry Vinbero manages for a BGP-learned prefix.
type Route struct {
	Prefix netip.Prefix
	// NextHops is empty for a directly connected route, one element for an
	// ordinary route, and several for a multipath one. A single next hop is
	// deliberately encoded as a plain gateway rather than a one-element
	// multipath: that is the form the kernel hands back, so encoding it any
	// other way would make a route stop comparing equal to itself after a
	// round trip.
	NextHops []NextHop
	Table    int // 0 = main table
	Metric   int // route priority; 0 = kernel default
}

// weightToHops converts a natural 1-based weight to the rtnh_hops value the
// kernel expects.
func weightToHops(weight int) int {
	if weight <= 1 {
		return 0
	}
	return weight - 1
}

// Injector installs and removes routes in the kernel FIB. Implementations
// must be safe for concurrent use.
type Injector interface {
	// Add installs r, replacing any existing Vinbero-owned route for the
	// same prefix. It is idempotent: re-adding an identical route is a
	// no-op from the caller's perspective.
	Add(r Route) error
	// Delete removes the route for prefix. Deleting a prefix that is not
	// present is not an error.
	Delete(prefix netip.Prefix) error
	// List returns every route currently tagged RTPROT_BGP.
	List() ([]Route, error)
}

// KernelInjector is the production Injector backed by netlink.
type KernelInjector struct{}

var _ Injector = (*KernelInjector)(nil)

// NewKernelInjector returns an Injector that writes to the live kernel
// routing table.
func NewKernelInjector() *KernelInjector { return &KernelInjector{} }

func (*KernelInjector) Add(r Route) error {
	nlRoute, err := toNetlinkRoute(r)
	if err != nil {
		return err
	}
	// RouteReplace is add-or-update: re-installing the same prefix
	// refreshes it in place instead of failing with EEXIST.
	if err := netlink.RouteReplace(nlRoute); err != nil {
		return fmt.Errorf("fib: add route %s: %w", r.Prefix, err)
	}
	return nil
}

func (*KernelInjector) Delete(prefix netip.Prefix) error {
	dst, err := prefixToIPNet(prefix)
	if err != nil {
		return err
	}
	route := &netlink.Route{Dst: dst, Protocol: routeProtocol}
	if err := netlink.RouteDel(route); err != nil {
		// ESRCH: the route is already gone. Treat Delete as idempotent
		// so a double-withdraw or a restart mid-teardown is harmless.
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return fmt.Errorf("fib: delete route %s: %w", prefix, err)
	}
	return nil
}

func (*KernelInjector) List() ([]Route, error) {
	filter := &netlink.Route{Protocol: routeProtocol}
	nlRoutes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, filter, netlink.RT_FILTER_PROTOCOL)
	if err != nil {
		return nil, fmt.Errorf("fib: list routes: %w", err)
	}
	out := make([]Route, 0, len(nlRoutes))
	for i := range nlRoutes {
		if r, ok := fromNetlinkRoute(&nlRoutes[i]); ok {
			out = append(out, r)
		}
	}
	return out, nil
}

func toNetlinkRoute(r Route) (*netlink.Route, error) {
	dst, err := prefixToIPNet(r.Prefix)
	if err != nil {
		return nil, err
	}
	nl := &netlink.Route{
		Dst:      dst,
		Protocol: routeProtocol,
		Table:    r.Table,
		Priority: r.Metric,
	}
	switch len(r.NextHops) {
	case 0:
	case 1:
		nh := r.NextHops[0]
		if err := nh.validate(0); err != nil {
			return nil, err
		}
		if nh.Gw.IsValid() {
			nl.Gw = net.IP(nh.Gw.AsSlice())
		}
		nl.LinkIndex = nh.Ifindex
	default:
		nl.MultiPath = make([]*netlink.NexthopInfo, 0, len(r.NextHops))
		for i, nh := range r.NextHops {
			if err := nh.validate(i); err != nil {
				return nil, err
			}
			info := &netlink.NexthopInfo{
				LinkIndex: nh.Ifindex,
				Hops:      weightToHops(nh.Weight),
			}
			if nh.Gw.IsValid() {
				info.Gw = net.IP(nh.Gw.AsSlice())
			}
			nl.MultiPath = append(nl.MultiPath, info)
		}
	}
	return nl, nil
}

func fromNetlinkRoute(nl *netlink.Route) (Route, bool) {
	// A nil Dst is the default route (0.0.0.0/0 or ::/0); Vinbero never
	// installs one, so skip rather than surfacing it.
	if nl.Dst == nil {
		return Route{}, false
	}
	prefix, ok := IPNetToPrefix(nl.Dst)
	if !ok {
		return Route{}, false
	}
	r := Route{Prefix: prefix, Table: nl.Table, Metric: nl.Priority}
	if len(nl.MultiPath) > 0 {
		for _, info := range nl.MultiPath {
			nh := NextHop{Ifindex: info.LinkIndex, Weight: info.Hops + 1}
			if gw, ok := netip.AddrFromSlice(info.Gw); ok && len(info.Gw) > 0 {
				nh.Gw = gw.Unmap()
			}
			r.NextHops = append(r.NextHops, nh)
		}
		return r, true
	}
	if len(nl.Gw) > 0 || nl.LinkIndex > 0 {
		nh := NextHop{Ifindex: nl.LinkIndex, Weight: 1}
		if gw, ok := netip.AddrFromSlice(nl.Gw); ok && len(nl.Gw) > 0 {
			nh.Gw = gw.Unmap()
		}
		r.NextHops = []NextHop{nh}
	}
	return r, true
}

func prefixToIPNet(p netip.Prefix) (*net.IPNet, error) {
	if !p.IsValid() {
		return nil, fmt.Errorf("fib: invalid prefix %q", p)
	}
	addr := p.Masked().Addr()
	return &net.IPNet{
		IP:   net.IP(addr.AsSlice()),
		Mask: net.CIDRMask(p.Bits(), addr.BitLen()),
	}, nil
}

// IPNetToPrefix converts a kernel route destination (*net.IPNet) to a
// netip.Prefix, normalizing a 4-in-6 address to a plain IPv4 prefix. ok is
// false when the address cannot be represented as a netip.Addr.
func IPNetToPrefix(n *net.IPNet) (netip.Prefix, bool) {
	addr, ok := netip.AddrFromSlice(n.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	ones, _ := n.Mask.Size()
	return netip.PrefixFrom(addr.Unmap(), ones), true
}
