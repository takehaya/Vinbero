package gobgp

import (
	"net/netip"

	"github.com/osrg/gobgp/v4/pkg/apiutil"
	gobgppkt "github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/takehaya/vinbero/pkg/bgp"
)

// decodeSRPolicy builds the Vinbero view of a received BGP SR Policy
// (SAFI 73) path. The {Color, Endpoint} key and Distinguisher come from
// the NLRI (RFC 9830); a single CandidatePath (preference + transport
// SID list) comes from the SR Policy Tunnel Encapsulation attribute
// (Tunnel Type 15). One NLRI carries exactly one candidate path.
//
// Returns nil when the path is not a well-formed IPv6 SR Policy. On a
// withdrawal the path carries the NLRI but no attributes, so the
// returned candidate has the default preference and an empty segment
// list -- the applier keys the removal off {Color, Endpoint,
// Distinguisher} and ignores the rest.
func decodeSRPolicy(p *apiutil.Path) *bgp.SRPolicy {
	nlri, ok := p.Nlri.(*gobgppkt.SRPolicyNLRI)
	if !ok {
		return nil
	}
	endpoint, ok := netip.AddrFromSlice(nlri.Endpoint)
	if !ok {
		return nil
	}
	preference, segments := decodeSRPolicyTunnel(p.Attrs)
	return &bgp.SRPolicy{
		Color:    nlri.Color,
		Endpoint: endpoint,
		Candidates: []bgp.CandidatePath{{
			Origin:        bgp.OriginBGP,
			Distinguisher: nlri.Distinguisher,
			Preference:    preference,
			SegmentList:   segments,
		}},
	}
}

// decodeSRPolicyTunnel walks the SR Policy tunnel sub-TLVs once and returns
// the candidate path's preference and transport SID list:
//   - Preference sub-TLV (RFC 9830 type 12); RFC 9256 default when absent.
//   - the FIRST Segment List sub-TLV (type 128); additional ones (weighted
//     ECMP) are ignored in Phase 1e-c. Only Type B (SRv6 SID) segments are
//     understood -- Type I/J/K (RFC 9831) carry node/adjacency descriptors
//     needing a SID/topology DB Vinbero lacks, so they are skipped.
func decodeSRPolicyTunnel(attrs []gobgppkt.PathAttributeInterface) (uint32, []netip.Addr) {
	preference := uint32(bgp.SRPolicyDefaultPreference)
	var segments []netip.Addr
	haveSegments := false
	for _, tlv := range srPolicyTunnelSubTLVs(attrs) {
		switch v := tlv.(type) {
		case *gobgppkt.TunnelEncapSubTLVSRPreference:
			preference = v.Preference
		case *gobgppkt.TunnelEncapSubTLVSRSegmentList:
			if haveSegments {
				continue // first Segment List sub-TLV wins
			}
			haveSegments = true
			for _, seg := range v.Segments {
				b, ok := seg.(*gobgppkt.SegmentTypeB)
				if !ok {
					continue // Type I/J/K etc.: unsupported, skip
				}
				if addr, ok := netip.AddrFromSlice(b.SID); ok {
					segments = append(segments, addr)
				}
			}
		}
	}
	return preference, segments
}

// srPolicyTunnelSubTLVs returns the sub-TLVs of the SR Policy tunnel
// (Tunnel Type 15) within the Tunnel Encapsulation attribute, or nil.
func srPolicyTunnelSubTLVs(attrs []gobgppkt.PathAttributeInterface) []gobgppkt.TunnelEncapSubTLVInterface {
	for _, a := range attrs {
		te, ok := a.(*gobgppkt.PathAttributeTunnelEncap)
		if !ok {
			continue
		}
		for _, tlv := range te.Value {
			if tlv.Type == gobgppkt.TUNNEL_TYPE_SR_POLICY {
				return tlv.Value
			}
		}
	}
	return nil
}
