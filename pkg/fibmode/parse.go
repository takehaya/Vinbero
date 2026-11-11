package fibmode

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// fibRuleHdrLen is sizeof(struct fib_rule_hdr): family, dst_len, src_len,
// tos, table, res1, res2, action, then a u32 of flags.
const fibRuleHdrLen = 12

// parseRule reads one RTM_NEWRULE/RTM_DELRULE payload. It is read here
// rather than with the netlink library so that an attribute the library
// would drop is seen: anything not known to leave the rule matching every
// packet makes the rule not plain.
func parseRule(m []byte) (Rule, error) {
	if len(m) < fibRuleHdrLen {
		return Rule{}, fmt.Errorf("rule message of %d bytes", len(m))
	}
	r := Rule{Family: int(m[0]), Table: uint32(m[4])}
	dstLen, srcLen, tos, action := m[1], m[2], m[3], m[7]
	flags := binary.NativeEndian.Uint32(m[8:12])
	var not []string
	if dstLen != 0 || srcLen != 0 {
		not = append(not, "has a source or destination prefix")
	}
	if tos != 0 {
		not = append(not, "has a TOS selector")
	}
	if action != unix.FR_ACT_TO_TBL {
		not = append(not, fmt.Sprintf("action %d is not a table lookup", action))
	}
	if flags != 0 {
		not = append(not, fmt.Sprintf("flags %#x", flags))
	}
	attrs, err := nl.ParseRouteAttr(m[fibRuleHdrLen:])
	if err != nil {
		return Rule{}, fmt.Errorf("rule attributes: %w", err)
	}
	for _, a := range attrs {
		switch a.Attr.Type {
		case unix.FRA_PRIORITY:
			if len(a.Value) >= 4 {
				r.Priority = binary.NativeEndian.Uint32(a.Value)
			}
		case unix.FRA_TABLE:
			if len(a.Value) >= 4 {
				r.Table = binary.NativeEndian.Uint32(a.Value)
			}
		case unix.FRA_PROTOCOL, unix.FRA_PAD:
			// Who added the rule; padding.
		case unix.FRA_SUPPRESS_PREFIXLEN:
			if len(a.Value) < 4 || binary.NativeEndian.Uint32(a.Value) != 0xffffffff {
				not = append(not, "suppresses results by prefix length")
			}
		case unix.FRA_L3MDEV:
			if len(a.Value) >= 1 && a.Value[0] != 0 {
				r.L3mdev = true
			}
		default:
			not = append(not, fmt.Sprintf("has selector or attribute %d", a.Attr.Type))
		}
	}
	if len(not) > 0 {
		r.NotPlain = not[0]
	}
	return r, nil
}

// rtaNHID is RTA_NH_ID (include/uapi/linux/rtnetlink.h), the attribute of a
// route through a nexthop object; x/sys/unix does not name it.
const rtaNHID = unix.RTA_DPORT + 1

// rtMsgLen is sizeof(struct rtmsg).
const rtMsgLen = 12

// parseRoute reads the parts of one RTM_NEWROUTE/RTM_DELROUTE payload the
// decision needs. ok is false for a cached (cloned) route, which is not in
// any table.
func parseRoute(m []byte) (r Route, ok bool, err error) {
	if len(m) < rtMsgLen {
		return Route{}, false, fmt.Errorf("route message of %d bytes", len(m))
	}
	family, dstLen, srcLen, tos, table, typ := int(m[0]), int(m[1]), m[2], m[3], uint32(m[4]), m[7]
	flags := binary.NativeEndian.Uint32(m[8:12])
	if flags&unix.RTM_F_CLONED != 0 {
		return Route{}, false, nil
	}
	attrs, err := nl.ParseRouteAttr(m[rtMsgLen:])
	if err != nil {
		return Route{}, false, fmt.Errorf("route attributes: %w", err)
	}
	var dst []byte
	nh := false
	for _, a := range attrs {
		switch a.Attr.Type {
		case unix.RTA_TABLE:
			if len(a.Value) >= 4 {
				table = binary.NativeEndian.Uint32(a.Value)
			}
		case unix.RTA_DST:
			dst = a.Value
		case rtaNHID:
			nh = true
		}
	}
	var addr netip.Addr
	switch family {
	case unix.AF_INET:
		addr = netip.IPv4Unspecified()
		if len(dst) == 4 {
			addr = netip.AddrFrom4([4]byte(dst))
		}
	case unix.AF_INET6:
		addr = netip.IPv6Unspecified()
		if len(dst) == 16 {
			addr = netip.AddrFrom16([16]byte(dst))
		}
	default:
		return Route{}, false, nil
	}
	p, err := addr.Prefix(dstLen)
	if err != nil {
		return Route{}, false, fmt.Errorf("route prefix /%d: %w", dstLen, err)
	}
	return Route{Family: family, Table: table, Type: typ, Dst: p, Src: srcLen != 0, Tos: tos, NH: nh}, true, nil
}
