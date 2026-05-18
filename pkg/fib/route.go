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

// Route is a kernel FIB entry Vinbero manages for a BGP-learned prefix.
type Route struct {
	Prefix  netip.Prefix
	NextHop netip.Addr // zero value => no gateway (directly connected)
	Table   int        // 0 = main table
	Metric  int        // route priority; 0 = kernel default
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
	if r.NextHop.IsValid() {
		nl.Gw = net.IP(r.NextHop.AsSlice())
	}
	return nl, nil
}

func fromNetlinkRoute(nl *netlink.Route) (Route, bool) {
	// A nil Dst is the default route (0.0.0.0/0 or ::/0); Vinbero never
	// installs one, so skip rather than surfacing it.
	if nl.Dst == nil {
		return Route{}, false
	}
	prefix, ok := ipNetToPrefix(nl.Dst)
	if !ok {
		return Route{}, false
	}
	r := Route{Prefix: prefix, Table: nl.Table, Metric: nl.Priority}
	if len(nl.Gw) > 0 {
		if nh, ok := netip.AddrFromSlice(nl.Gw); ok {
			r.NextHop = nh.Unmap()
		}
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

func ipNetToPrefix(n *net.IPNet) (netip.Prefix, bool) {
	addr, ok := netip.AddrFromSlice(n.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	ones, _ := n.Mask.Size()
	return netip.PrefixFrom(addr.Unmap(), ones), true
}
