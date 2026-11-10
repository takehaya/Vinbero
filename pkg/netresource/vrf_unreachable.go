package netresource

import (
	"errors"
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// unreachableDefaultMetric is the metric of a VRF table's unreachable
// default: near the top of the metric range, the value the Linux VRF
// documentation uses, so every other route in the table is preferred.
const unreachableDefaultMetric = 4278198272

// unreachableDefaults are the IPv4 and IPv6 unreachable defaults for a VRF
// table. A lookup in the table that matches nothing else ends on them (the
// packet is dropped with an ICMP unreachable) instead of the l3mdev rule
// missing and the kernel going on to the main table. They carry RTPROT_BOOT,
// the protocol of a plain `ip route add`, which the route watcher never
// redistributes.
func unreachableDefaults(tableID uint32) []*netlink.Route {
	return []*netlink.Route{
		{
			Table: int(tableID), Type: unix.RTN_UNREACHABLE, Priority: unreachableDefaultMetric,
			Protocol: unix.RTPROT_BOOT, Dst: &net.IPNet{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)},
		},
		{
			Table: int(tableID), Type: unix.RTN_UNREACHABLE, Priority: unreachableDefaultMetric,
			Protocol: unix.RTPROT_BOOT, Dst: &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
		},
	}
}

// ensureUnreachableDefault adds the unreachable defaults to the table. The
// add never replaces a route: a default the operator put in the table at a
// better metric is a different route and stays the one lookups use, and a
// route already at this metric (the operator's own unreachable default, or
// one added before a restart) is kept as it is.
func ensureUnreachableDefault(tableID uint32) error {
	for _, r := range unreachableDefaults(tableID) {
		if err := netlink.RouteAdd(r); err != nil && !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("add unreachable default %s to table %d: %w", r.Dst, tableID, err)
		}
	}
	return nil
}

// removeUnreachableDefault removes the unreachable defaults from the table.
// They outlive the VRF device (routes that use no device of the VRF stay in
// the table), so a delete removes them itself. One already gone is not an
// error.
func removeUnreachableDefault(tableID uint32) error {
	for _, r := range unreachableDefaults(tableID) {
		if err := netlink.RouteDel(r); err != nil && !errors.Is(err, unix.ESRCH) {
			return fmt.Errorf("remove unreachable default %s from table %d: %w", r.Dst, tableID, err)
		}
	}
	return nil
}
