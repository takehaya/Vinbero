package gobgp

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/google/uuid"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	gobgppkt "github.com/osrg/gobgp/v4/pkg/packet/bgp"
	gobgpsrv "github.com/osrg/gobgp/v4/pkg/server"

	"github.com/takehaya/vinbero/pkg/bgp"
)

// Advertise injects a VPNv4 / VPNv6 route carrying an SRv6 service SID
// into the BGP RIB. The gobgp path UUID is recorded so a later Withdraw
// can remove that exact path.
func (s *Session) Advertise(_ context.Context, r bgp.VPNRoute) error {
	srv := s.bgpServer()
	if srv == nil {
		return bgp.ErrSessionNotStarted
	}
	path, err := encodeVPNPath(r)
	if err != nil {
		return err
	}
	return s.addAndTrack(srv, path, r.Key())
}

// AdvertiseUnicast injects an IPv6 unicast route.
func (s *Session) AdvertiseUnicast(_ context.Context, r bgp.UnicastRoute) error {
	srv := s.bgpServer()
	if srv == nil {
		return bgp.ErrSessionNotStarted
	}
	path, err := encodeUnicastPath(r)
	if err != nil {
		return err
	}
	return s.addAndTrack(srv, path, bgp.RouteKey{Family: bgp.FamilyIPv6Unicast, Prefix: r.Prefix})
}

// ValidateVPNRoute reports whether this route could be encoded, without
// sending it.
//
// It exists for callers that reconcile a set of routes: they withdraw
// before they advertise, so a route that only fails inside the encoder has
// already cost the caller its other routes by the time the failure
// surfaces. Running the same encoder up front gives the same verdict
// without that cost, and without a second copy of its rules that could
// drift from it.
func (s *Session) ValidateVPNRoute(r bgp.VPNRoute) error {
	_, err := encodeVPNPath(r)
	return err
}

// ValidateUnicastRoute is ValidateVPNRoute for IPv6 unicast.
func (s *Session) ValidateUnicastRoute(r bgp.UnicastRoute) error {
	_, err := encodeUnicastPath(r)
	return err
}

// Withdraw removes a previously advertised route. Withdrawing a route
// that was never advertised is a no-op so callers can withdraw
// idempotently.
func (s *Session) Withdraw(_ context.Context, key bgp.RouteKey) error {
	srv := s.bgpServer()
	if srv == nil {
		return bgp.ErrSessionNotStarted
	}
	s.advMu.Lock()
	id, ok := s.advertised[key]
	s.advMu.Unlock()
	if !ok {
		return nil
	}
	// Drop the tracking entry only after gobgp confirms the delete, so a
	// failed DeletePath leaves the route still withdrawable on retry.
	if err := srv.DeletePath(apiutil.DeletePathRequest{UUIDs: []uuid.UUID{id}}); err != nil {
		return fmt.Errorf("withdraw %s: %w", key.Prefix, err)
	}
	s.advMu.Lock()
	delete(s.advertised, key)
	s.advMu.Unlock()
	return nil
}

// addAndTrack adds path to the RIB and records its UUID under key so
// Withdraw can later delete exactly this path. Re-advertising an
// existing key is safe: gobgp supersedes the local path with the same
// NLRI on AddPath, so the prior UUID is already invalid and is simply
// overwritten here -- no orphan path is left in the RIB.
func (s *Session) addAndTrack(srv *gobgpsrv.BgpServer, path *apiutil.Path, key bgp.RouteKey) error {
	resps, err := srv.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{path}})
	if err != nil {
		return fmt.Errorf("advertise %s: %w", key.Prefix, err)
	}
	if len(resps) == 0 {
		return fmt.Errorf("advertise %s: gobgp returned no response", key.Prefix)
	}
	if resps[0].Error != nil {
		return fmt.Errorf("advertise %s: %w", key.Prefix, resps[0].Error)
	}
	s.advMu.Lock()
	s.advertised[key] = resps[0].UUID
	s.advMu.Unlock()
	return nil
}

// vinberoFamilyToAPI maps a Vinbero Family to a gobgp route family. It
// is the inverse of apiFamilyToVinbero.
func vinberoFamilyToAPI(f bgp.Family) (gobgppkt.Family, error) {
	switch f {
	case bgp.FamilyVPNv4:
		return gobgppkt.RF_IPv4_VPN, nil
	case bgp.FamilyVPNv6:
		return gobgppkt.RF_IPv6_VPN, nil
	case bgp.FamilyIPv6Unicast:
		return gobgppkt.RF_IPv6_UC, nil
	case bgp.FamilySRPolicyIPv6:
		return gobgppkt.RF_SR_POLICY_IPv6, nil
	case bgp.FamilyEVPN:
		return gobgppkt.RF_EVPN, nil
	case bgp.FamilyMUPIPv4:
		return gobgppkt.RF_MUP_IPv4, nil
	case bgp.FamilyMUPIPv6:
		return gobgppkt.RF_MUP_IPv6, nil
	default:
		return 0, fmt.Errorf("unsupported BGP family %q", f)
	}
}

// parseRouteTargets parses route-target strings into extended communities.
// Shared by the VPN / EVPN / MUP path encoders.
func parseRouteTargets(rts []string) ([]gobgppkt.ExtendedCommunityInterface, error) {
	ecs := make([]gobgppkt.ExtendedCommunityInterface, 0, len(rts))
	for _, rt := range rts {
		ec, err := gobgppkt.ParseRouteTarget(rt)
		if err != nil {
			return nil, fmt.Errorf("parse RT %q: %w", rt, err)
		}
		ecs = append(ecs, ec)
	}
	return ecs, nil
}

// vpnEndpointBehavior is the SRv6 endpoint behavior advertised with a
// VPN route: End.DT4 for VPNv4, End.DT6 for VPNv6, unless the route names
// one of its own.
//
// The override is for a plugin advertising a behavior it implements
// itself. The codepoint is not validated against the behaviors vinbero
// knows, because an unrecognized one is exactly the point.
func vpnEndpointBehavior(r bgp.VPNRoute) gobgppkt.SRBehavior {
	if r.EndpointBehavior != 0 {
		return gobgppkt.SRBehavior(r.EndpointBehavior)
	}
	if r.Family == bgp.FamilyVPNv6 {
		return gobgppkt.END_DT6
	}
	return gobgppkt.END_DT4
}

// encodeVPNPath builds the gobgp Path for a VPNv4 / VPNv6 advertisement.
// It is the inverse of decodeVPNRoute.
func encodeVPNPath(r bgp.VPNRoute) (*apiutil.Path, error) {
	family, err := vinberoFamilyToAPI(r.Family)
	if err != nil {
		return nil, err
	}
	rd, err := gobgppkt.ParseRouteDistinguisher(r.RD)
	if err != nil {
		return nil, fmt.Errorf("parse RD %q: %w", r.RD, err)
	}
	prefix, err := netip.ParsePrefix(r.Prefix)
	if err != nil {
		return nil, fmt.Errorf("parse prefix %q: %w", r.Prefix, err)
	}
	nlri, err := gobgppkt.NewLabeledVPNIPAddrPrefix(prefix, *gobgppkt.NewMPLSLabelStack(0), rd)
	if err != nil {
		return nil, fmt.Errorf("build VPN NLRI: %w", err)
	}
	attrs := []gobgppkt.PathAttributeInterface{gobgppkt.NewPathAttributeOrigin(0)}
	// Route targets and the Color Extended Community (RFC 9012 §4.3) are both
	// extended communities; carry them in one attribute. Color != 0 marks the
	// route for SR Policy steering on the receiving headend.
	ecs, err := parseRouteTargets(r.RTs)
	if err != nil {
		return nil, err
	}
	if r.Color != 0 {
		ecs = append(ecs, gobgppkt.NewColorExtended(r.Color))
	}
	if len(ecs) > 0 {
		attrs = append(attrs, gobgppkt.NewPathAttributeExtendedCommunities(ecs))
	}
	if r.SRv6SID != "" {
		sid, err := netip.ParseAddr(r.SRv6SID)
		if err != nil {
			return nil, fmt.Errorf("parse SRv6 SID %q: %w", r.SRv6SID, err)
		}
		infoSubTLV := gobgppkt.NewSRv6InformationSubTLV(sid, vpnEndpointBehavior(r))
		svcTLV := gobgppkt.NewSRv6ServiceTLV(gobgppkt.TLVTypeSRv6L3Service, infoSubTLV)
		attrs = append(attrs, gobgppkt.NewPathAttributePrefixSID(svcTLV))
	}
	nh, err := netip.ParseAddr(r.NextHop)
	if err != nil {
		return nil, fmt.Errorf("parse nexthop %q: %w", r.NextHop, err)
	}
	mpReach, err := gobgppkt.NewPathAttributeMpReachNLRI(family, []gobgppkt.PathNLRI{{NLRI: nlri}}, nh)
	if err != nil {
		return nil, fmt.Errorf("build MP_REACH_NLRI: %w", err)
	}
	attrs = append(attrs, mpReach)
	return &apiutil.Path{Family: family, Nlri: nlri, Attrs: attrs}, nil
}

// encodeUnicastPath builds the gobgp Path for an IPv6 unicast
// advertisement.
func encodeUnicastPath(r bgp.UnicastRoute) (*apiutil.Path, error) {
	prefix, err := netip.ParsePrefix(r.Prefix)
	if err != nil {
		return nil, fmt.Errorf("parse prefix %q: %w", r.Prefix, err)
	}
	nlri, err := gobgppkt.NewIPAddrPrefix(prefix)
	if err != nil {
		return nil, fmt.Errorf("build IPv6 NLRI: %w", err)
	}
	nh, err := netip.ParseAddr(r.NextHop)
	if err != nil {
		return nil, fmt.Errorf("parse nexthop %q: %w", r.NextHop, err)
	}
	mpReach, err := gobgppkt.NewPathAttributeMpReachNLRI(
		gobgppkt.RF_IPv6_UC, []gobgppkt.PathNLRI{{NLRI: nlri}}, nh)
	if err != nil {
		return nil, fmt.Errorf("build MP_REACH_NLRI: %w", err)
	}
	return &apiutil.Path{
		Family: gobgppkt.RF_IPv6_UC,
		Nlri:   nlri,
		Attrs:  []gobgppkt.PathAttributeInterface{gobgppkt.NewPathAttributeOrigin(0), mpReach},
	}, nil
}
