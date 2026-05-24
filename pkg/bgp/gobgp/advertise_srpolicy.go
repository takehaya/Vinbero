package gobgp

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/google/uuid"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	gobgppkt "github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/takehaya/vinbero/pkg/bgp"
)

var _ bgp.SRPolicyController = (*Session)(nil)

// PushPolicy advertises a local SR Policy (SAFI 73) into the BGP RIB. The
// policy carries exactly one candidate path; the gobgp path UUID is
// recorded under the {color, endpoint, distinguisher} key so a later
// WithdrawPolicy removes that exact path.
func (s *Session) PushPolicy(_ context.Context, p bgp.SRPolicy) error {
	srv := s.bgpServer()
	if srv == nil {
		return bgp.ErrSessionNotStarted
	}
	path, err := encodeSRPolicyPath(p)
	if err != nil {
		return err
	}
	return s.addAndTrack(srv, path,
		srPolicyAdvKey(p.Color, p.Endpoint, p.Candidates[0].Distinguisher))
}

// WithdrawPolicy removes a previously advertised SR Policy. Withdrawing one
// that was never advertised is a no-op so callers can withdraw
// idempotently.
func (s *Session) WithdrawPolicy(_ context.Context, key bgp.SRPolicyKey) error {
	srv := s.bgpServer()
	if srv == nil {
		return bgp.ErrSessionNotStarted
	}
	rk := srPolicyAdvKey(key.Color, key.Endpoint, key.Distinguisher)
	s.advMu.Lock()
	id, ok := s.advertised[rk]
	s.advMu.Unlock()
	if !ok {
		return nil
	}
	// Drop the tracking entry only after gobgp confirms the delete, so a
	// failed DeletePath leaves the policy still withdrawable on retry.
	if err := srv.DeletePath(apiutil.DeletePathRequest{UUIDs: []uuid.UUID{id}}); err != nil {
		return fmt.Errorf("withdraw SR Policy {color=%d, endpoint=%s, dist=%d}: %w",
			key.Color, key.Endpoint, key.Distinguisher, err)
	}
	s.advMu.Lock()
	delete(s.advertised, rk)
	s.advMu.Unlock()
	return nil
}

// srPolicyAdvKey synthesizes the advertised-path tracking key for an SR
// Policy. The shared advertised map is keyed by bgp.RouteKey, so the
// {distinguisher, color, endpoint} tuple is encoded into the Prefix field.
func srPolicyAdvKey(color uint32, endpoint netip.Addr, distinguisher uint32) bgp.RouteKey {
	return bgp.RouteKey{
		Family: bgp.FamilySRPolicyIPv6,
		Prefix: fmt.Sprintf("srp:%d:%d:%s", distinguisher, color, endpoint),
	}
}

// encodeSRPolicyPath builds the gobgp Path for an SR Policy advertisement.
// It is the inverse of decodeSRPolicy: the {distinguisher, color, endpoint}
// NLRI plus an SR Policy Tunnel Encapsulation attribute (Tunnel Type 15)
// carrying the Preference (type 12) and a single Segment List (type 128) of
// Type B (SRv6) segments. The next hop rides in MP_REACH_NLRI.
func encodeSRPolicyPath(p bgp.SRPolicy) (*apiutil.Path, error) {
	if len(p.Candidates) != 1 {
		return nil, fmt.Errorf("SR Policy advertisement needs exactly one candidate path, got %d", len(p.Candidates))
	}
	cp := p.Candidates[0]
	if !p.Endpoint.Is6() {
		return nil, fmt.Errorf("SR Policy endpoint must be IPv6: %s", p.Endpoint)
	}
	if len(cp.SegmentList) == 0 {
		return nil, fmt.Errorf("SR Policy advertisement needs at least one transport segment")
	}
	if !p.AdvertiseNextHop.Is6() {
		return nil, fmt.Errorf("SR Policy next hop must be IPv6: %s", p.AdvertiseNextHop)
	}
	nlri, err := gobgppkt.NewSRPolicy(gobgppkt.RF_SR_POLICY_IPv6, gobgppkt.SRPolicyIPv6NLRILen,
		cp.Distinguisher, p.Color, p.Endpoint.AsSlice())
	if err != nil {
		return nil, fmt.Errorf("build SR Policy NLRI: %w", err)
	}

	segments := make([]gobgppkt.TunnelEncapSubTLVInterface, 0, len(cp.SegmentList))
	for _, sid := range cp.SegmentList {
		if !sid.Is6() {
			return nil, fmt.Errorf("SR Policy transport SID must be IPv6: %s", sid)
		}
		segments = append(segments, &gobgppkt.SegmentTypeB{
			TunnelEncapSubTLV: gobgppkt.TunnelEncapSubTLV{Type: gobgppkt.EncapSubTLVType(gobgppkt.TypeB)},
			SID:               sid.AsSlice(),
		})
	}
	subTLVs := []gobgppkt.TunnelEncapSubTLVInterface{
		gobgppkt.NewTunnelEncapSubTLVSRPreference(0, cp.Preference),
		&gobgppkt.TunnelEncapSubTLVSRSegmentList{
			TunnelEncapSubTLV: gobgppkt.TunnelEncapSubTLV{Type: gobgppkt.ENCAP_SUBTLV_TYPE_SRSEGMENT_LIST},
			Segments:          segments,
		},
	}
	tunnel := gobgppkt.NewPathAttributeTunnelEncap([]*gobgppkt.TunnelEncapTLV{{
		Type:  gobgppkt.TUNNEL_TYPE_SR_POLICY,
		Value: subTLVs,
	}})

	mpReach, err := gobgppkt.NewPathAttributeMpReachNLRI(gobgppkt.RF_SR_POLICY_IPv6,
		[]gobgppkt.PathNLRI{{NLRI: nlri}}, p.AdvertiseNextHop)
	if err != nil {
		return nil, fmt.Errorf("build MP_REACH_NLRI: %w", err)
	}
	attrs := []gobgppkt.PathAttributeInterface{
		gobgppkt.NewPathAttributeOrigin(0),
		tunnel,
		mpReach,
	}
	return &apiutil.Path{Family: gobgppkt.RF_SR_POLICY_IPv6, Nlri: nlri, Attrs: attrs}, nil
}
