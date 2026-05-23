package gobgp

import (
	"net/netip"

	"github.com/osrg/gobgp/v4/pkg/apiutil"
	gobgppkt "github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/takehaya/vinbero/pkg/bgp"
)

// srPolicyDefaultPreference is the candidate path preference assumed when
// the Preference sub-TLV is absent (RFC 9256 §2.7).
const srPolicyDefaultPreference = 100

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
	return &bgp.SRPolicy{
		Color:    nlri.Color,
		Endpoint: endpoint,
		Candidates: []bgp.CandidatePath{{
			Origin:        bgp.OriginBGP,
			Distinguisher: nlri.Distinguisher,
			Preference:    srPolicyPreference(p.Attrs),
			SegmentList:   srPolicySegments(p.Attrs),
		}},
	}
}

// srPolicyPreference returns the candidate path preference from the
// Preference sub-TLV (RFC 9830 sub-TLV type 12), or the RFC default when
// absent.
func srPolicyPreference(attrs []gobgppkt.PathAttributeInterface) uint32 {
	for _, tlv := range srPolicyTunnelSubTLVs(attrs) {
		if pref, ok := tlv.(*gobgppkt.TunnelEncapSubTLVSRPreference); ok {
			return pref.Preference
		}
	}
	return srPolicyDefaultPreference
}

// srPolicySegments returns the transport SID list from the FIRST Segment
// List sub-TLV (RFC 9830 type 128). Only Type B (SRv6 SID) segments are
// understood; Type I/J/K (RFC 9831) carry node/adjacency descriptors that
// need a SID/topology database Vinbero does not have, so they are skipped.
// Additional Segment List sub-TLVs (weighted ECMP) are ignored in Phase
// 1e-c -- the first list wins.
func srPolicySegments(attrs []gobgppkt.PathAttributeInterface) []netip.Addr {
	for _, tlv := range srPolicyTunnelSubTLVs(attrs) {
		sl, ok := tlv.(*gobgppkt.TunnelEncapSubTLVSRSegmentList)
		if !ok {
			continue
		}
		var segs []netip.Addr
		for _, seg := range sl.Segments {
			b, ok := seg.(*gobgppkt.SegmentTypeB)
			if !ok {
				continue // Type I/J/K etc.: unsupported, skip
			}
			if addr, ok := netip.AddrFromSlice(b.SID); ok {
				segs = append(segs, addr)
			}
		}
		return segs // first Segment List sub-TLV only
	}
	return nil
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
