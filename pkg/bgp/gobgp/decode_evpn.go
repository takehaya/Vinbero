package gobgp

import (
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	gobgppkt "github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/takehaya/vinbero/pkg/bgp"
)

// decodeEVPNRoute builds Vinbero's EVPNRoute view of a received EVPN NLRI
// (AFI 25 / SAFI 70). RT1 (Ethernet A-D), RT2 (MAC/IP), RT3 (Inclusive
// Multicast) and RT4 (Ethernet Segment) are decoded; RT5 (IP Prefix) is not,
// and returns nil, which the Applier treats as a no-op. Decoding a type is
// not the same as acting on it: RT1 currently reaches the Applier and falls
// through, since aliasing and mass withdraw are not implemented yet.
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
	case *gobgppkt.EVPNEthernetAutoDiscoveryRoute:
		return decodeEVPNEthernetAD(p, rt)
	case *gobgppkt.EVPNEthernetSegmentRoute:
		return decodeEVPNEthernetSegment(p, rt)
	default:
		return nil
	}
}

// decodeEVPNEthernetAD decodes an RT1 Ethernet A-D route (RFC 7432 §7.1).
//
// One NLRI type carries two different statements, told apart by the Ethernet
// Tag. Per-ES (tag = MAX-ET) is about the segment as a whole: it advertises
// reachability of the ES and its withdrawal is the mass-withdraw signal that
// lets peers converge off a failed link without waiting for every MAC to be
// withdrawn one by one (RFC 7432 §8.2). Per-EVI (any other tag) is about one
// broadcast domain, and its SRv6 SID is what makes aliasing possible: it
// gives a peer somewhere to send traffic for MACs it has only learned from
// another PE on the same segment.
//
// The Single-Active bit rides on the per-ES route's ESI Label extended
// community and matters because it forbids aliasing: on a single-active
// segment only the DF forwards, so spreading traffic across the PEs
// advertising the ES would black-hole whatever landed on a non-DF.
func decodeEVPNEthernetAD(p *apiutil.Path, rt *gobgppkt.EVPNEthernetAutoDiscoveryRoute) *bgp.EVPNRoute {
	r := &bgp.EVPNRoute{
		Type:        bgp.EVPNRouteTypeEthernetAD,
		ESI:         esiToArray(rt.ESI),
		EthernetTag: rt.ETag,
		RTs:         decodeRouteTargets(p.Attrs),
		NextHop:     decodeNextHop(p.Attrs),
	}
	if rt.RD != nil {
		r.RD = rt.RD.String()
	}
	// Where the transposed Argument bits live differs between the two forms.
	// A per-EVI route transposes into the NLRI's MPLS label like RT2/RT3 do,
	// but a per-ES route sets that label to 0 and carries the bits in the
	// 24-bit label of the ESI Label extended community instead (RFC 9252:
	// "The 24-bit ESI Label field of the ESI Label extended community
	// carries the whole or a portion of the Argument part of the SRv6 SID
	// when the ESI filtering approach is used along with the Transposition
	// Scheme"). Reading the NLRI label for a per-ES route would drop the
	// transposed bits and compose a SID that points somewhere else.
	esiLabel, singleActive, haveESILabel := decodeESILabel(p.Attrs)
	if r.IsPerES() && !haveESILabel {
		// RFC 7432 §8.2.1 makes the ESI Label extended community mandatory on
		// a per-ES route, so its absence is a malformed advertisement rather
		// than a statement of all-active. Fail closed: the only decision that
		// turns on this bit is whether the segment may be aliased, and
		// aliasing a segment whose redundancy mode we do not actually know
		// would black-hole traffic landing on a non-DF.
		singleActive = true
	}
	label := rt.Label
	if r.IsPerES() {
		label = esiLabel
	}
	r.SRv6SID = decodeSRv6SID(p.Attrs, label)
	r.RemoteSrc = decodeRemoteSrc(p.Attrs, label, defaultLocatorPrefixLen)
	r.SingleActive = singleActive
	return r
}

// decodeESILabel reads the ESI Label extended community (RFC 7432 §7.5),
// returning its 24-bit label, the Single-Active bit, and whether the
// community was there at all. Callers need the third value because absence
// is not the same as a cleared bit: the community is mandatory on a per-ES
// route, so a missing one means the advertisement is malformed, not that the
// segment is all-active.
func decodeESILabel(attrs []gobgppkt.PathAttributeInterface) (uint32, bool, bool) {
	for _, a := range attrs {
		ec, ok := a.(*gobgppkt.PathAttributeExtendedCommunities)
		if !ok {
			continue
		}
		for _, c := range ec.Value {
			if esi, ok := c.(*gobgppkt.ESILabelExtended); ok {
				return esi.Label, esi.IsSingleActive, true
			}
		}
	}
	return 0, false, false
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
	r.RemoteSrc = decodeRemoteSrc(p.Attrs, label, defaultLocatorPrefixLen)
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
	label := pmsiLabel(p.Attrs)
	r.SRv6SID = decodeSRv6SID(p.Attrs, label)
	r.RemoteSrc = decodeRemoteSrc(p.Attrs, label, defaultLocatorPrefixLen)
	return r
}

// defaultLocatorPrefixLen is the assumed SRv6 locator length (bits) when a
// received SID carries no SID Structure Sub-Sub-TLV. /48 matches Vinbero's
// own encapSource() convention and the locators used in the interop labs.
const defaultLocatorPrefixLen uint8 = 48

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
