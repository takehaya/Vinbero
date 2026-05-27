package gobgp

import (
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	gobgppkt "github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/takehaya/vinbero/pkg/bgp"
)

// decodeEVPNRoute builds Vinbero's EVPNRoute view of a received EVPN NLRI
// (AFI 25 / SAFI 70). RT2 (MAC/IP), RT3 (Inclusive Multicast), and RT4
// (Ethernet Segment) are decoded; other route types return nil, which the
// Applier treats as a no-op.
func decodeEVPNRoute(p *apiutil.Path) *bgp.EVPNRoute {
	nlri, ok := p.Nlri.(*gobgppkt.EVPNNLRI)
	if !ok {
		return nil
	}
	switch rt := nlri.RouteTypeData.(type) {
	case *gobgppkt.EVPNMacIPAdvertisementRoute:
		return decodeEVPNMacIP(p, rt)
	case *gobgppkt.EVPNMulticastEthernetTagRoute:
		return decodeEVPNMulticast(p, rt)
	case *gobgppkt.EVPNEthernetSegmentRoute:
		return decodeEVPNEthernetSegment(p, rt)
	default:
		return nil
	}
}

// decodeEVPNEthernetSegment decodes an RT4 Ethernet Segment route (RFC 7432
// §7.6). RT4 carries no SRv6 SID; it signals ES membership with the ES-Import
// route target. The ESI and the originating router IP (the next hop) identify
// which PE attaches to the segment, the inputs to DF election.
func decodeEVPNEthernetSegment(p *apiutil.Path, rt *gobgppkt.EVPNEthernetSegmentRoute) *bgp.EVPNRoute {
	r := &bgp.EVPNRoute{
		Type:       bgp.EVPNRouteTypeEthernetSegment,
		ESI:        esiToArray(rt.ESI),
		ESImportRT: decodeESImportRT(p.Attrs),
		NextHop:    decodeNextHop(p.Attrs),
	}
	if rt.RD != nil {
		r.RD = rt.RD.String()
	}
	return r
}

// decodeEVPNMacIP decodes an RT2 MAC/IP Advertisement. The End.DT2U
// service SID rides in the BGP Prefix-SID attribute's SRv6 L2 Service TLV
// (RFC 9252 §6.2); decodeSRv6SID handles both L2 and L3 TLVs and folds in
// any RFC 9252 transposition carried in the NLRI's first label.
func decodeEVPNMacIP(p *apiutil.Path, rt *gobgppkt.EVPNMacIPAdvertisementRoute) *bgp.EVPNRoute {
	r := &bgp.EVPNRoute{
		Type:        bgp.EVPNRouteTypeMACIP,
		EthernetTag: rt.ETag,
		ESI:         esiToArray(rt.ESI),
		RTs:         decodeRouteTargets(p.Attrs),
		NextHop:     decodeNextHop(p.Attrs),
	}
	if rt.RD != nil {
		r.RD = rt.RD.String()
	}
	if len(rt.MacAddress) == 6 {
		r.MAC = rt.MacAddress.String()
	}
	if rt.IPAddress.IsValid() && !rt.IPAddress.IsUnspecified() {
		r.IPAddr = rt.IPAddress.String()
	}
	var label uint32
	if len(rt.Labels) > 0 {
		label = rt.Labels[0]
	}
	r.SRv6SID = decodeSRv6SID(p.Attrs, label)
	return r
}

// decodeEVPNMulticast decodes an RT3 Inclusive Multicast Ethernet Tag route
// (RFC 7432 §7.3). The End.DT2M flood SID rides in the Prefix-SID L2 Service
// TLV (RFC 9252 §6.3); any transposition offset is carried in the PMSI Tunnel
// label rather than an NLRI label. RD / Ethernet Tag identify the flood peer;
// the originating router IP arrives as the next hop.
func decodeEVPNMulticast(p *apiutil.Path, rt *gobgppkt.EVPNMulticastEthernetTagRoute) *bgp.EVPNRoute {
	r := &bgp.EVPNRoute{
		Type:        bgp.EVPNRouteTypeInclusiveMulticast,
		EthernetTag: rt.ETag,
		RTs:         decodeRouteTargets(p.Attrs),
		NextHop:     decodeNextHop(p.Attrs),
	}
	if rt.RD != nil {
		r.RD = rt.RD.String()
	}
	r.SRv6SID = decodeSRv6SID(p.Attrs, pmsiLabel(p.Attrs))
	return r
}

// pmsiLabel returns the transposition label from the PMSI Tunnel attribute
// (Ingress Replication), or 0 when absent. RFC 9252 §6.3 places the RT3
// transposition offset here, mirroring RT2's NLRI label.
func pmsiLabel(attrs []gobgppkt.PathAttributeInterface) uint32 {
	for _, a := range attrs {
		if p, ok := a.(*gobgppkt.PathAttributePmsiTunnel); ok {
			return p.Label
		}
	}
	return 0
}

// esiToArray renders a gobgp ESI as the RFC 7432 10-byte identifier:
// one Type octet followed by the 9-octet value (matching the wire
// serialization).
func esiToArray(esi gobgppkt.EthernetSegmentIdentifier) [10]byte {
	var out [10]byte
	out[0] = byte(esi.Type)
	copy(out[1:], esi.Value)
	return out
}
