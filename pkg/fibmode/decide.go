// Package fibmode decides when the global VRF's (vrf 0) FIB lookups of the
// data plane can run as a direct lookup instead of the kernel's full one,
// and keeps that decision in step with the network namespace
// (internal.bpf.fib_lookup_global "auto").
//
// A full lookup (bpf_fib_lookup with flags 0) goes through the ip rules of
// the namespace. Once a namespace has had any rule added, the kernel walks
// the rule list for every such lookup, which a direct lookup
// (BPF_FIB_LOOKUP_DIRECT, no table ID) does not: it reads one table, the
// VRF table when the lookup's device is a VRF device or a port enslaved to
// one, the main table otherwise. The two give the same answer for a
// destination when the rule walk is bound to end in that same table with the
// same result. Decide checks that the namespace is in such a state:
//
//   - Every rule is one the kernel puts there itself: matches all packets,
//     action "lookup", table local, main or (IPv4) default, or the l3mdev
//     rule a VRF device adds. At least one rule reads the main table, and
//     every l3mdev rule comes before it. A rule with anything else, or with
//     an attribute this package does not know, makes the family's
//     lookups full ones.
//   - The local table holds host routes only, besides 127.0.0.0/8 and
//     ff00::/8. The data plane checks the destination against these
//     (fib_local_v4/v6_map) and takes the full lookup for any of them, so a
//     destination the direct lookup handles is in no local route, wherever
//     the local rule sits.
//   - The IPv4 default table (253) is empty, so the default rule never
//     changes an answer.
//   - When a VRF device exists, an l3mdev rule exists, and each VRF table
//     ends in an unreachable, blackhole or prohibit default with no source,
//     TOS or nexthop object, and (IPv4) holds no throw route. The rule walk of a lookup on
//     a VRF device or an enslaved port then always stops in the VRF table,
//     which is the table the direct lookup reads.
//
// Under these conditions the rule walk of a destination outside the local
// table reads, at most, empty or missing tables and then the one table the
// direct lookup reads, with the same flow (fib_table_lookup and
// fib6_table_lookup get the same inputs in both), so verdict, next hop,
// output device, neighbour result and multipath choice are the same.
package fibmode

import (
	"fmt"
	"net/netip"
	"sort"

	"golang.org/x/sys/unix"
)

// Kernel table IDs.
const (
	tableDefault = 253
	tableMain    = 254
	tableLocal   = 255
)

// MaxLocal is the size of each family's local-address map in the data
// plane (FIB_LOCAL_MAX_ENTRIES). A local table with more host routes keeps
// the family on the full lookup.
const MaxLocal = 8192

// Rule is one ip rule as the kernel dumps it, reduced to what the decision
// needs.
type Rule struct {
	Family   int
	Priority uint32
	Table    uint32
	L3mdev   bool
	// NotPlain says why the rule is not one that matches every packet with
	// action "lookup" and nothing else ("" when it is). A rule with an
	// attribute or header field this package does not know is not plain.
	NotPlain string
}

// Route is a route of the local, default or a VRF table, reduced to what
// the decision needs.
type Route struct {
	Family int
	Table  uint32
	Type   uint8 // RTN_*
	Dst    netip.Prefix
	// Src is set for an IPv6 route with a source prefix, Tos for an IPv4
	// route with a TOS: such a route covers only part of the flows.
	Src bool
	Tos uint8
	// NH is set for a route through a nexthop object. Its type in a dump
	// says what the nexthop does now (a blackhole nexthop makes the route
	// RTN_BLACKHOLE, whatever its own type), and deleting or replacing the
	// nexthop changes the route without a route event.
	NH bool
}

// VRF is a VRF device of the namespace.
type VRF struct {
	Name  string
	Index int
	Table uint32
}

// Snapshot is the state of a namespace Decide reads: the ip rules of both
// families, the VRF devices, and the routes of the local table, the IPv4
// default table and the VRF tables.
type Snapshot struct {
	Rules  []Rule
	VRFs   []VRF
	Routes []Route
}

// Family is the decision for one address family.
type Family struct {
	// Direct is true when the family's vrf 0 lookups can be direct ones.
	Direct bool
	// Why says why not, when Direct is false.
	Why string
	// Local is the host routes of the local table, which the data plane
	// keeps on the full lookup. Set when Direct is true.
	Local []netip.Addr
}

// Decision is the outcome of Decide for both families.
type Decision struct {
	V4, V6 Family
}

// Decide decides for each family whether the vrf 0 lookups can run as
// direct lookups in the namespace described by s.
func Decide(s *Snapshot) Decision {
	return Decision{V4: decideFamily(s, unix.AF_INET), V6: decideFamily(s, unix.AF_INET6)}
}

func decideFamily(s *Snapshot, family int) Family {
	if why := checkRules(s, family); why != "" {
		return Family{Why: why}
	}
	local, why := localHosts(s, family)
	if why != "" {
		return Family{Why: why}
	}
	if family == unix.AF_INET {
		for _, r := range s.Routes {
			if r.Family == family && r.Table == tableDefault {
				return Family{Why: fmt.Sprintf("the default table (253) has a route (%s)", r.Dst)}
			}
		}
	}
	if why := checkVRFTables(s, family); why != "" {
		return Family{Why: why}
	}
	return Family{Direct: true, Local: local}
}

func checkRules(s *Snapshot, family int) string {
	var main, l3mdev []uint32
	for _, r := range s.Rules {
		if r.Family != family {
			continue
		}
		if r.NotPlain != "" {
			return fmt.Sprintf("ip rule %d: %s", r.Priority, r.NotPlain)
		}
		switch {
		case r.L3mdev:
			l3mdev = append(l3mdev, r.Priority)
		case r.Table == tableMain:
			main = append(main, r.Priority)
		case r.Table == tableLocal:
		case r.Table == tableDefault && family == unix.AF_INET:
		default:
			return fmt.Sprintf("ip rule %d looks up table %d", r.Priority, r.Table)
		}
	}
	if len(main) == 0 {
		return "no ip rule looks up the main table"
	}
	first := main[0]
	for _, p := range main {
		first = min(first, p)
	}
	for _, p := range l3mdev {
		if p >= first {
			return fmt.Sprintf("the l3mdev rule %d comes after the main table's rule %d", p, first)
		}
	}
	if len(s.VRFs) > 0 && len(l3mdev) == 0 {
		return fmt.Sprintf("VRF device %s exists but no l3mdev rule does", s.VRFs[0].Name)
	}
	return ""
}

// wellKnownLocal is the part of the local table the data plane checks by
// itself, without the map: 127.0.0.0/8 and ff00::/8.
func wellKnownLocal(p netip.Prefix) bool {
	if p.Addr().Is4() {
		return p.Bits() >= 8 && netip.MustParsePrefix("127.0.0.0/8").Contains(p.Addr())
	}
	return p.Bits() >= 8 && netip.MustParsePrefix("ff00::/8").Contains(p.Addr())
}

func localHosts(s *Snapshot, family int) ([]netip.Addr, string) {
	seen := map[netip.Addr]struct{}{}
	for _, r := range s.Routes {
		if r.Family != family || r.Table != tableLocal {
			continue
		}
		switch {
		case r.Dst.IsSingleIP():
			seen[r.Dst.Addr()] = struct{}{}
		case wellKnownLocal(r.Dst):
		default:
			return nil, fmt.Sprintf("the local table has a route to %s, not to one address", r.Dst)
		}
	}
	if len(seen) > MaxLocal {
		return nil, fmt.Sprintf("the local table has %d host routes, more than %d", len(seen), MaxLocal)
	}
	out := make([]netip.Addr, 0, len(seen))
	for a := range seen {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out, ""
}

// rejectType reports whether t is a route type that ends a lookup with an
// error whatever the flow (unreachable, blackhole, prohibit).
func rejectType(t uint8) bool {
	return t == unix.RTN_UNREACHABLE || t == unix.RTN_BLACKHOLE || t == unix.RTN_PROHIBIT
}

func checkVRFTables(s *Snapshot, family int) string {
	for _, v := range s.VRFs {
		closed := false
		for _, r := range s.Routes {
			if r.Family != family || r.Table != v.Table {
				continue
			}
			if family == unix.AF_INET && (r.Type == unix.RTN_THROW || r.NH && r.Type == unix.RTN_BLACKHOLE) {
				// A throw route through a blackhole nexthop dumps as a
				// blackhole route, so such a route may be a throw.
				return fmt.Sprintf("VRF %s (table %d) has a throw route, or a route through a blackhole nexthop (%s)", v.Name, v.Table, r.Dst)
			}
			if r.Dst.Bits() == 0 && rejectType(r.Type) && !r.Src && r.Tos == 0 && !r.NH {
				closed = true
			}
		}
		if !closed {
			return fmt.Sprintf("VRF %s (table %d) does not end in an unreachable default", v.Name, v.Table)
		}
	}
	return ""
}
