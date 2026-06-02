package server

import (
	"fmt"
	"net/netip"
)

// parseAdvertiseNextHop validates a BGP next hop for an advertised route and
// returns the parsed address. SRv6 VPN / SR Policy / MUP transport is IPv6-only,
// so the next hop must be a specific, routable IPv6 address: empty, IPv4,
// v4-in-6, and the unspecified address (::) are all rejected. :: in particular
// would originate a blackhole next hop no PE can forward toward, reachable over
// the unauthenticated RPC surface. Shared by the SR Policy and MUP advertise
// paths so they enforce the next hop identically.
func parseAdvertiseNextHop(nextHop string) (netip.Addr, error) {
	nh, err := netip.ParseAddr(nextHop)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("next_hop %q is not a valid IP address", nextHop)
	}
	if !nh.Is6() || nh.Is4In6() || nh.IsUnspecified() {
		return netip.Addr{}, fmt.Errorf("next_hop %q must be a routable IPv6 address", nextHop)
	}
	return nh, nil
}
