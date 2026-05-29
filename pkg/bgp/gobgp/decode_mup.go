package gobgp

import (
	"encoding/binary"
	"net/netip"

	"github.com/osrg/gobgp/v4/pkg/apiutil"
	gobgppkt "github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/takehaya/vinbero/pkg/bgp"
)

// decodeMUPRoute builds the Vinbero view of a received BGP MUP path (SAFI 85,
// Architecture Type 1 / 3GPP-5G, draft-mpmz-bess-mup-safi). One envelope covers
// all four route types; the type switch fills only the fields that type carries.
// The SRv6 segment SID (interwork/direct locator:function) comes from the
// Prefix-SID attribute's SRv6 Services TLV via the shared decodeSRv6SID, and the
// MUP Extended Community segment identifier (used to resolve a T2ST against its
// Direct Segment) from decodeMUPSegmentID.
//
// Returns nil when the path is not a 3GPP-5G MUP NLRI so the caller skips it.
func decodeMUPRoute(p *apiutil.Path) *bgp.MUPRoute {
	nlri, ok := p.Nlri.(*gobgppkt.MUPNLRI)
	if !ok || nlri.ArchitectureType != gobgppkt.MUP_ARCH_TYPE_3GPP_5G {
		return nil
	}
	r := &bgp.MUPRoute{
		RTs:     decodeRouteTargets(p.Attrs),
		NextHop: decodeNextHop(p.Attrs),
		SRv6SID: decodeSRv6SID(p.Attrs, 0),
	}
	r.SegmentID2, r.SegmentID4 = decodeMUPSegmentID(p.Attrs)

	switch rt := nlri.RouteTypeData.(type) {
	case *gobgppkt.MUPInterworkSegmentDiscoveryRoute:
		r.Type = bgp.MUPRouteTypeISD
		r.RD = rdString(rt.RD)
		r.Prefix = rt.Prefix.String()
	case *gobgppkt.MUPDirectSegmentDiscoveryRoute:
		r.Type = bgp.MUPRouteTypeDSD
		r.RD = rdString(rt.RD)
		r.Address = rt.Address.String()
	case *gobgppkt.MUPType1SessionTransformedRoute:
		r.Type = bgp.MUPRouteTypeT1ST
		r.RD = rdString(rt.RD)
		r.Prefix = rt.Prefix.String()
		// T1ST carries an exact 4-byte TEID (the per-UE downlink tunnel).
		r.TEID = teidToUint32(rt.TEID)
		r.TEIDLen = 32
		r.QFI = rt.QFI
		r.Endpoint = rt.EndpointAddress.String()
		if rt.SourceAddress != nil {
			r.Source = rt.SourceAddress.String()
		}
	case *gobgppkt.MUPType2SessionTransformedRoute:
		r.Type = bgp.MUPRouteTypeT2ST
		r.RD = rdString(rt.RD)
		r.Endpoint = rt.EndpointAddress.String()
		// T2ST carries the TEID as a variable-length prefix: EndpointAddressLength
		// covers the endpoint (32 bits for IPv4, 128 for IPv6) plus the
		// significant TEID bits.
		endpointBits := uint8(32)
		if rt.EndpointAddress.Is6() {
			endpointBits = 128
		}
		// An EndpointAddressLength below the endpoint's own width is malformed per
		// the draft's length semantics. Skip it rather than silently leaving
		// TEIDLen=0, which would install a match-ALL-TEID wildcard for the endpoint
		// (a remote advertiser could broaden a session's scope by understating the
		// length). A length exactly equal to endpointBits is a legitimate
		// "aggregate every TEID" route (TEIDLen=0).
		if rt.EndpointAddressLength < endpointBits {
			return nil
		}
		r.TEID = teidToUint32(rt.TEID)
		r.TEIDLen = rt.EndpointAddressLength - endpointBits
	default:
		return nil
	}
	return r
}

// rdString renders a route distinguisher, tolerating a nil interface value.
func rdString(rd gobgppkt.RouteDistinguisherInterface) string {
	if rd == nil {
		return ""
	}
	return rd.String()
}

// teidToUint32 extracts the 32-bit TEID value from gobgp's netip.Addr
// representation (a 4-byte IPv4-shaped address, MSB-first). A non-4-byte addr
// (never produced by the gobgp MUP decoder) yields 0.
func teidToUint32(a netip.Addr) uint32 {
	if !a.Is4() {
		return 0
	}
	b := a.As4()
	return binary.BigEndian.Uint32(b[:])
}

// decodeMUPSegmentID returns the BGP MUP Extended Community segment identifier
// halves (draft §3.2), or (0, 0) when the community is absent.
func decodeMUPSegmentID(attrs []gobgppkt.PathAttributeInterface) (uint16, uint32) {
	for _, a := range attrs {
		ec, ok := a.(*gobgppkt.PathAttributeExtendedCommunities)
		if !ok {
			continue
		}
		for _, c := range ec.Value {
			if mup, ok := c.(*gobgppkt.MUPExtended); ok {
				return mup.SegmentID2, mup.SegmentID4
			}
		}
	}
	return 0, 0
}
