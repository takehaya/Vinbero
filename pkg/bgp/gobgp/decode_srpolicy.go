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
	// Endpoint must be a 16-byte IPv6 address. gobgp does not width-validate
	// the NLRI endpoint, so a 4-byte (IPv4) endpoint on the IPv6 family would
	// otherwise decode to an Is4() key that can never match the always-IPv6
	// VPN next hop -- the policy would install but silently never steer.
	if len(nlri.Endpoint) != 16 {
		return nil
	}
	endpoint, ok := netip.AddrFromSlice(nlri.Endpoint)
	if !ok || !endpoint.Is6() {
		return nil
	}
	preference, lists := decodeSRPolicyTunnel(p.Attrs)
	cand := bgp.CandidatePath{
		Origin:        bgp.OriginBGP,
		Distinguisher: nlri.Distinguisher,
		Preference:    preference,
		SegmentLists:  lists,
	}
	// SegmentList is the single-list view every current consumer reads: the
	// first usable list, which is also what gets programmed until weighted
	// selection lands in the data plane.
	if len(lists) > 0 {
		cand.SegmentList = lists[0].Segments
	}
	return &bgp.SRPolicy{
		Color:      nlri.Color,
		Endpoint:   endpoint,
		Candidates: []bgp.CandidatePath{cand},
	}
}

// decodeSRPolicyTunnel walks the SR Policy tunnel sub-TLVs once and returns
// the candidate path's preference and its Segment Lists:
//   - Preference sub-TLV (RFC 9830 type 12); RFC 9256 default when absent.
//   - every Segment List sub-TLV (type 128), each with the share from its
//     nested Weight sub-TLV, or SRPolicyDefaultWeight when it carries none.
//     Only Type B (SRv6 SID) segments are understood -- Type I/J/K
//     (RFC 9831) carry node/adjacency descriptors needing a SID/topology DB
//     Vinbero lacks, so they are skipped.
//
// A malformed list is dropped on its own rather than taking the candidate
// with it. That is the opposite of what a single-list decoder should do: with
// one list, discarding it and leaving the candidate ineligible is right,
// because steering onto a lower-preference alternate is safer than steering
// along a path built from a list we could not read. With several, the other
// lists are independent statements about how to reach the same endpoint, and
// dropping them all because one was bad would take down a policy that is
// still perfectly usable. A candidate whose lists are ALL unusable still ends
// up ineligible, which preserves the original behaviour for the single-list
// case.
func decodeSRPolicyTunnel(attrs []gobgppkt.PathAttributeInterface) (uint32, []bgp.WeightedSegmentList) {
	preference := uint32(bgp.SRPolicyDefaultPreference)
	var lists []bgp.WeightedSegmentList
	for _, tlv := range srPolicyTunnelSubTLVs(attrs) {
		switch v := tlv.(type) {
		case *gobgppkt.TunnelEncapSubTLVSRPreference:
			preference = v.Preference
		case *gobgppkt.TunnelEncapSubTLVSRSegmentList:
			weight, ok := segmentListWeight(v)
			if !ok {
				continue
			}
			segments, ok := decodeSegmentList(v)
			if !ok {
				continue
			}
			lists = append(lists, bgp.WeightedSegmentList{
				Segments: segments,
				Weight:   weight,
			})
		}
	}
	return preference, lists
}

// decodeSegmentList extracts one Segment List's transport SIDs. ok is false
// when the list cannot be used as written.
func decodeSegmentList(v *gobgppkt.TunnelEncapSubTLVSRSegmentList) ([]netip.Addr, bool) {
	var segments []netip.Addr
	for _, seg := range v.Segments {
		b, ok := seg.(*gobgppkt.SegmentTypeB)
		if !ok {
			continue // Type I/J/K etc.: unsupported, skip
		}
		addr, ok := netip.AddrFromSlice(b.SID)
		// A transport SID must be an SRv6 (IPv6) SID. A malformed or IPv4
		// SID makes this whole list unusable -- dropping just that SID
		// would steer along a path the advertiser never described.
		if !ok || !addr.Is6() {
			return nil, false
		}
		segments = append(segments, addr)
	}
	// A list that named no usable segment carries no path; treating it as
	// an empty-but-valid list would install a policy that encapsulates to
	// nothing.
	if len(segments) == 0 {
		return nil, false
	}
	return segments, true
}

// segmentListWeight reads a list's share. ok is false when the list must not
// be used.
//
// An absent Weight sub-TLV and an explicit weight of 0 are NOT the same
// thing, and conflating them overrides what the advertiser asked for. RFC
// 9256 sets the default weight to 1 when none is given, but declares a
// segment list invalid when "its weight is 0" -- an explicit 0 withdraws
// that list from the ECMP set. Reading it as 1 would put a list the sender
// disabled back into service, and if it were the first list it would become
// the one actually programmed.
func segmentListWeight(v *gobgppkt.TunnelEncapSubTLVSRSegmentList) (uint32, bool) {
	if v.Weight == nil {
		return bgp.SRPolicyDefaultWeight, true
	}
	if v.Weight.Weight == 0 {
		return 0, false
	}
	return v.Weight.Weight, true
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
