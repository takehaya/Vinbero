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
	var label uint32
	if vpn, ok := p.Nlri.(*gobgppkt.LabeledVPNIPAddrPrefix); ok {
		vr.Prefix = vpn.Prefix.String()
		if vpn.RD != nil {
			vr.RD = vpn.RD.String()
		}
		// RFC 9252 transposition may carry part of the SRv6 SID in the
		// VPN label; decodeSRv6SID folds it back into the SID.
		if len(vpn.Labels.Labels) > 0 {
			label = vpn.Labels.Labels[0]
		}
	} else if p.Nlri != nil {
		// Unexpected NLRI shape: keep the generic rendering rather than
		// dropping the route silently so the anomaly is still visible.
		vr.Prefix = p.Nlri.String()
	}
	vr.SRv6SID = decodeSRv6SID(p.Attrs, label)
	vr.RTs = decodeRouteTargets(p.Attrs)
	vr.NextHop = decodeNextHop(p.Attrs)
	vr.Color = decodeColor(p.Attrs)
	return vr
}

// decodeColor returns the value of the Color Extended Community (RFC 9012
// §4.3) on the path, or 0 when none is present. When several are present
// the highest color value wins. CO bits (Color-Only steering) are not
// interpreted in Phase 1e-c -- CO=00 is assumed.
func decodeColor(attrs []gobgppkt.PathAttributeInterface) uint32 {
	var color uint32
	for _, a := range attrs {
		ec, ok := a.(*gobgppkt.PathAttributeExtendedCommunities)
		if !ok {
			continue
		}
		for _, c := range ec.Value {
			if col, ok := c.(*gobgppkt.ColorExtended); ok && col.Color > color {
				color = col.Color
			}
		}
	}
	return color
}

// decodeSRv6SID walks the BGP Prefix-SID attribute (RFC 9252) and
// returns the first SRv6 service SID as an IPv6 string. When the SID
// Structure Sub-Sub-TLV signals transposition, the transposed bits are
// folded back in from the VPN label (RFC 9252 §4); label is the route's
// MPLS label. An empty result means the path carried no SRv6 SID.
func decodeSRv6SID(attrs []gobgppkt.PathAttributeInterface, label uint32) string {
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
				if !ok || len(info.SID) != 16 {
					continue
				}
				sid := info.SID
				if length, offset, ok := transpositionParams(info); ok {
					folded := make([]byte, 16)
					copy(folded, info.SID)
					if !foldTransposedLabel(folded, label, length, offset) {
						// Transposition is signalled but the SID
						// Structure Sub-Sub-TLV is malformed: the real
						// SID cannot be rebuilt, so skip it rather than
						// install a wrong encap target.
						continue
					}
					sid = folded
				}
				if addr, ok := netip.AddrFromSlice(sid); ok {
					return addr.String()
				}
			}
		}
	}
	return ""
}

// transpositionParams returns the transposition length and offset from
// an SRv6 Information Sub-TLV's SID Structure Sub-Sub-TLV (RFC 9252
// §3.2.1). ok is false when there is no structure TLV or it signals no
// transposition.
func transpositionParams(info *gobgppkt.SRv6InformationSubTLV) (length, offset uint8, ok bool) {
	for _, ss := range info.SubSubTLVs {
		st, isStruct := ss.(*gobgppkt.SRv6SIDStructureSubSubTLV)
		if !isStruct {
			continue
		}
		if st.TranspositionLength == 0 {
			return 0, 0, false
		}
		return st.TranspositionLength, st.TranspositionOffset, true
	}
	return 0, 0, false
}

// foldTransposedLabel reconstructs an SRv6 SID whose bits were
// transposed into the VPN MPLS label (RFC 9252 §4): the high-order
// `length` bits of the 20-bit label are OR-ed into sid at bit `offset`
// counted from the SID's most significant bit. The on-wire SID has that
// bit range zeroed, so OR-folding is sufficient. It returns false,
// leaving sid untouched, when the parameters -- both attacker-controlled
// off the wire -- cannot describe a valid transposition into the SID.
func foldTransposedLabel(sid []byte, label uint32, length, offset uint8) bool {
	const mplsLabelBits = 20
	if length == 0 || length > mplsLabelBits || int(offset)+int(length) > 8*len(sid) {
		return false
	}
	val := (label & (1<<mplsLabelBits - 1)) >> (mplsLabelBits - length)
	for i := 0; i < int(length); i++ {
		if (val>>uint(int(length)-1-i))&1 == 0 {
			continue
		}
		pos := int(offset) + i
		sid[pos/8] |= byte(1) << uint(7-pos%8)
	}
	return true
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

// decodeESImportRT returns the ES-Import route target (RFC 7432 §7.6) carried
// on the path, rendered as a MAC string, or "" if absent. RT4 signals Ethernet
// Segment membership with this community (sub-type EC_SUBTYPE_ES_IMPORT), which
// is distinct from the ordinary route targets decodeRouteTargets returns.
func decodeESImportRT(attrs []gobgppkt.PathAttributeInterface) string {
	for _, a := range attrs {
		ec, ok := a.(*gobgppkt.PathAttributeExtendedCommunities)
		if !ok {
			continue
		}
		for _, c := range ec.Value {
			if esi, ok := c.(*gobgppkt.ESImportRouteTarget); ok {
				return esi.ESImport.String()
			}
		}
	}
	return ""
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
