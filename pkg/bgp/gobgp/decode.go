package gobgp

import (
	"net/netip"

	"github.com/osrg/gobgp/v4/pkg/apiutil"
	gobgppkt "github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/takehaya/vinbero/pkg/bgp"
)

// decodeVPNRoute builds the Vinbero VPNRoute view of a received VPNv4 /
// VPNv6 path: RD + prefix from the NLRI, the SRv6 service SID from the
// BGP Prefix-SID attribute (RFC 9252), route targets from extended
// communities, and the next hop from MP_REACH_NLRI.
func decodeVPNRoute(p *apiutil.Path, fam bgp.Family) *bgp.VPNRoute {
	vr := &bgp.VPNRoute{Family: fam}
	if vpn, ok := p.Nlri.(*gobgppkt.LabeledVPNIPAddrPrefix); ok {
		vr.Prefix = vpn.Prefix.String()
		if vpn.RD != nil {
			vr.RD = vpn.RD.String()
		}
	} else if p.Nlri != nil {
		// Unexpected NLRI shape: keep the generic rendering rather than
		// dropping the route silently so the anomaly is still visible.
		vr.Prefix = p.Nlri.String()
	}
	vr.SRv6SID = decodeSRv6SID(p.Attrs)
	vr.RTs = decodeRouteTargets(p.Attrs)
	vr.NextHop = decodeNextHop(p.Attrs)
	return vr
}

// decodeSRv6SID walks the BGP Prefix-SID attribute (RFC 9252) and
// returns the first SRv6 service SID, rendered as an IPv6 string. An
// empty result means the path carried no SRv6 SID.
func decodeSRv6SID(attrs []gobgppkt.PathAttributeInterface) string {
	for _, a := range attrs {
		psid, ok := a.(*gobgppkt.PathAttributePrefixSID)
		if !ok {
			continue
		}
		for _, tlv := range psid.TLVs {
			svc, ok := tlv.(*gobgppkt.SRv6ServiceTLV)
			if !ok {
				continue
			}
			for _, st := range svc.SubTLVs {
				info, ok := st.(*gobgppkt.SRv6InformationSubTLV)
				if !ok {
					continue
				}
				if sid, ok := netip.AddrFromSlice(info.SID); ok {
					return sid.String()
				}
			}
		}
	}
	return ""
}

// decodeRouteTargets returns every route-target extended community on
// the path, each rendered "as:admin" (e.g. "65000:100"). Non-RT
// communities (Site-of-Origin etc.) share the same wire types and are
// distinguished by sub-type.
func decodeRouteTargets(attrs []gobgppkt.PathAttributeInterface) []string {
	var rts []string
	for _, a := range attrs {
		ec, ok := a.(*gobgppkt.PathAttributeExtendedCommunities)
		if !ok {
			continue
		}
		for _, c := range ec.Value {
			if _, sub := c.GetTypes(); sub == gobgppkt.EC_SUBTYPE_ROUTE_TARGET {
				rts = append(rts, c.String())
			}
		}
	}
	return rts
}

// decodeNextHop returns the path's next hop. VPN families carry it in
// MP_REACH_NLRI; plain IPv4 unicast uses the legacy NEXT_HOP attribute.
func decodeNextHop(attrs []gobgppkt.PathAttributeInterface) string {
	for _, a := range attrs {
		switch attr := a.(type) {
		case *gobgppkt.PathAttributeMpReachNLRI:
			if attr.Nexthop.IsValid() {
				return attr.Nexthop.String()
			}
		case *gobgppkt.PathAttributeNextHop:
			if attr.Value.IsValid() {
				return attr.Value.String()
			}
		}
	}
	return ""
}

// nlriString renders an NLRI, tolerating a nil interface value.
func nlriString(n gobgppkt.NLRI) string {
	if n == nil {
		return ""
	}
	return n.String()
}
