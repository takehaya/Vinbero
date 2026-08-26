package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/locator"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

// BgpRouteServer is the Connect RPC handler for BgpRouteService. It is a
// thin adapter over bgp.RouteAdvertiser (VPN / unicast),
// bgp.SRPolicyController (SR Policy), bgp.EVPNController, and
// bgp.MUPController. Each is nil when vinberod runs without --bgp-enabled;
// every RPC then fails with FailedPrecondition.
//
// vrfBindings is consulted by BgpAdvertiseMup to auto-fill an empty RTs
// list from the binding whose RD matches the route. Nil disables auto-fill.
type BgpRouteServer struct {
	advertiser  bgp.RouteAdvertiser
	srPolicy    bgp.SRPolicyController
	evpn        bgp.EVPNController
	mup         bgp.MUPController
	vrfBindings *vrfbgp.Manager
	locators    *locator.Manager
}

func NewBgpRouteServer(advertiser bgp.RouteAdvertiser, srPolicy bgp.SRPolicyController, evpn bgp.EVPNController, mup bgp.MUPController, vrfBindings *vrfbgp.Manager, locators *locator.Manager) *BgpRouteServer {
	return &BgpRouteServer{advertiser: advertiser, srPolicy: srPolicy, evpn: evpn, mup: mup, vrfBindings: vrfBindings, locators: locators}
}

// errBGPDisabled is returned (as FailedPrecondition) when an advertise /
// withdraw RPC arrives but BGP is not enabled.
var errBGPDisabled = errors.New("BGP is not enabled; start vinberod with --bgp-enabled")

func (s *BgpRouteServer) BgpAdvertiseVpn(
	ctx context.Context,
	req *connect.Request[v1.BgpAdvertiseVpnRequest],
) (*connect.Response[v1.BgpAdvertiseVpnResponse], error) {
	if s.advertiser == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errBGPDisabled)
	}
	resp := &v1.BgpAdvertiseVpnResponse{
		Advertised: make([]*v1.BgpVpnRoute, 0),
		Errors:     make([]*v1.OperationError, 0),
	}
	for _, r := range req.Msg.Routes {
		fam, err := bgp.ParseFamily(r.GetFamily())
		if err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{TriggerPrefix: r.GetPrefix(), Reason: err.Error()})
			continue
		}
		vr := bgp.VPNRoute{
			Family:  fam,
			Prefix:  r.GetPrefix(),
			RD:      r.GetRd(),
			RTs:     r.GetRouteTargets(),
			SRv6SID: r.GetSrv6Sid(),
			NextHop: r.GetNextHop(),
			Color:   r.GetColor(),
		}
		// Same convention as the MUP advertise path: the SID Structure
		// comes from the locator that contains the SID, when one is
		// registered (a uSID locator yields 32/16/16/0).
		vr.SIDStructure = sidStructureFromLocators(vr.SRv6SID, s.locators)
		// End.DT4 / End.DT6 service SIDs carry no argument; the locator's
		// argument space is layout, not the behavior's width (RFC 9252
		// §3.2.1.1). MUP keeps the locator value -- its behaviors do use
		// arguments.
		vr.SIDStructure.ArgumentLen = 0
		err = s.advertiser.Advertise(ctx, vr)
		if err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{TriggerPrefix: r.GetPrefix(), Reason: err.Error()})
			continue
		}
		resp.Advertised = append(resp.Advertised, r)
	}
	return connect.NewResponse(resp), nil
}

func (s *BgpRouteServer) BgpAdvertiseUnicast(
	ctx context.Context,
	req *connect.Request[v1.BgpAdvertiseUnicastRequest],
) (*connect.Response[v1.BgpAdvertiseUnicastResponse], error) {
	if s.advertiser == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errBGPDisabled)
	}
	resp := &v1.BgpAdvertiseUnicastResponse{
		Advertised: make([]*v1.BgpUnicastRoute, 0),
		Errors:     make([]*v1.OperationError, 0),
	}
	for _, r := range req.Msg.Routes {
		err := s.advertiser.AdvertiseUnicast(ctx, bgp.UnicastRoute{
			Prefix:  r.GetPrefix(),
			NextHop: r.GetNextHop(),
		})
		if err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{TriggerPrefix: r.GetPrefix(), Reason: err.Error()})
			continue
		}
		resp.Advertised = append(resp.Advertised, r)
	}
	return connect.NewResponse(resp), nil
}

func (s *BgpRouteServer) BgpWithdraw(
	ctx context.Context,
	req *connect.Request[v1.BgpWithdrawRequest],
) (*connect.Response[v1.BgpWithdrawResponse], error) {
	if s.advertiser == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errBGPDisabled)
	}
	resp := &v1.BgpWithdrawResponse{
		Withdrawn: make([]*v1.BgpRouteKey, 0),
		Errors:    make([]*v1.OperationError, 0),
	}
	for _, k := range req.Msg.Keys {
		fam, err := bgp.ParseFamily(k.GetFamily())
		if err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{TriggerPrefix: k.GetPrefix(), Reason: err.Error()})
			continue
		}
		err = s.advertiser.Withdraw(ctx, bgp.RouteKey{Family: fam, Prefix: k.GetPrefix(), RD: k.GetRd()})
		if err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{TriggerPrefix: k.GetPrefix(), Reason: err.Error()})
			continue
		}
		resp.Withdrawn = append(resp.Withdrawn, k)
	}
	return connect.NewResponse(resp), nil
}

func (s *BgpRouteServer) BgpAdvertiseSrPolicy(
	ctx context.Context,
	req *connect.Request[v1.BgpAdvertiseSrPolicyRequest],
) (*connect.Response[v1.BgpAdvertiseSrPolicyResponse], error) {
	if s.srPolicy == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errBGPDisabled)
	}
	resp := &v1.BgpAdvertiseSrPolicyResponse{
		Advertised: make([]*v1.BgpSrPolicy, 0),
		Errors:     make([]*v1.OperationError, 0),
	}
	for _, p := range req.Msg.Policies {
		policy, err := protoToAdvertiseSRPolicy(p)
		if err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{TriggerPrefix: srPolicyKeyTrigger(p.GetColor(), p.GetEndpoint(), p.GetDistinguisher()), Reason: err.Error()})
			continue
		}
		if err := s.srPolicy.PushPolicy(ctx, policy); err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{TriggerPrefix: srPolicyKeyTrigger(p.GetColor(), p.GetEndpoint(), p.GetDistinguisher()), Reason: err.Error()})
			continue
		}
		resp.Advertised = append(resp.Advertised, p)
	}
	return connect.NewResponse(resp), nil
}

func (s *BgpRouteServer) BgpWithdrawSrPolicy(
	ctx context.Context,
	req *connect.Request[v1.BgpWithdrawSrPolicyRequest],
) (*connect.Response[v1.BgpWithdrawSrPolicyResponse], error) {
	if s.srPolicy == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errBGPDisabled)
	}
	resp := &v1.BgpWithdrawSrPolicyResponse{
		Withdrawn: make([]*v1.BgpSrPolicyKey, 0),
		Errors:    make([]*v1.OperationError, 0),
	}
	for _, k := range req.Msg.Keys {
		endpoint, err := netip.ParseAddr(k.GetEndpoint())
		if err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{TriggerPrefix: srPolicyKeyTrigger(k.GetColor(), k.GetEndpoint(), k.GetDistinguisher()), Reason: err.Error()})
			continue
		}
		// Match the Advertise/Create constraint: SR Policy endpoints are
		// IPv6, so an IPv4 endpoint can never identify a real policy. Reject
		// it instead of reporting a no-op withdraw as success.
		if !endpoint.Is6() {
			resp.Errors = append(resp.Errors, &v1.OperationError{TriggerPrefix: srPolicyKeyTrigger(k.GetColor(), k.GetEndpoint(), k.GetDistinguisher()), Reason: "endpoint must be IPv6"})
			continue
		}
		if err := s.srPolicy.WithdrawPolicy(ctx, bgp.SRPolicyKey{
			Color:         k.GetColor(),
			Endpoint:      endpoint,
			Distinguisher: k.GetDistinguisher(),
		}); err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{TriggerPrefix: srPolicyKeyTrigger(k.GetColor(), k.GetEndpoint(), k.GetDistinguisher()), Reason: err.Error()})
			continue
		}
		resp.Withdrawn = append(resp.Withdrawn, k)
	}
	return connect.NewResponse(resp), nil
}

func (s *BgpRouteServer) BgpAdvertiseEvpnMac(
	ctx context.Context,
	req *connect.Request[v1.BgpAdvertiseEvpnMacRequest],
) (*connect.Response[v1.BgpAdvertiseEvpnMacResponse], error) {
	if s.evpn == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errBGPDisabled)
	}
	resp := &v1.BgpAdvertiseEvpnMacResponse{
		Advertised: make([]*v1.BgpEvpnMac, 0),
		Errors:     make([]*v1.OperationError, 0),
	}
	for _, m := range req.Msg.Macs {
		route, err := protoToAdvertiseEvpnMac(m)
		if err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{TriggerPrefix: evpnMacTrigger(m.GetRd(), m.GetEthernetTag(), m.GetMac()), Reason: err.Error()})
			continue
		}
		if err := s.evpn.PushEVPNMac(ctx, route); err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{TriggerPrefix: evpnMacTrigger(m.GetRd(), m.GetEthernetTag(), m.GetMac()), Reason: err.Error()})
			continue
		}
		resp.Advertised = append(resp.Advertised, m)
	}
	return connect.NewResponse(resp), nil
}

func (s *BgpRouteServer) BgpWithdrawEvpnMac(
	ctx context.Context,
	req *connect.Request[v1.BgpWithdrawEvpnMacRequest],
) (*connect.Response[v1.BgpWithdrawEvpnMacResponse], error) {
	if s.evpn == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errBGPDisabled)
	}
	resp := &v1.BgpWithdrawEvpnMacResponse{
		Withdrawn: make([]*v1.BgpEvpnMacKey, 0),
		Errors:    make([]*v1.OperationError, 0),
	}
	for _, k := range req.Msg.Keys {
		hw, err := net.ParseMAC(k.GetMac())
		if err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{TriggerPrefix: evpnMacTrigger(k.GetRd(), k.GetEthernetTag(), k.GetMac()), Reason: fmt.Sprintf("invalid MAC: %v", err)})
			continue
		}
		// Normalize the MAC the same way advertise does, so the withdraw key
		// matches the advertised-path tracking key regardless of input format.
		if err := s.evpn.WithdrawEVPNMac(ctx, bgp.EVPNMACKey{
			RD:          k.GetRd(),
			EthernetTag: k.GetEthernetTag(),
			MAC:         hw.String(),
		}); err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{TriggerPrefix: evpnMacTrigger(k.GetRd(), k.GetEthernetTag(), k.GetMac()), Reason: err.Error()})
			continue
		}
		resp.Withdrawn = append(resp.Withdrawn, k)
	}
	return connect.NewResponse(resp), nil
}

func (s *BgpRouteServer) BgpAdvertiseEvpnImet(
	ctx context.Context,
	req *connect.Request[v1.BgpAdvertiseEvpnImetRequest],
) (*connect.Response[v1.BgpAdvertiseEvpnImetResponse], error) {
	if s.evpn == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errBGPDisabled)
	}
	resp := &v1.BgpAdvertiseEvpnImetResponse{
		Advertised: make([]*v1.BgpEvpnImet, 0),
		Errors:     make([]*v1.OperationError, 0),
	}
	for _, m := range req.Msg.Imets {
		// SID / next-hop / RD are validated in the encoder, so a bad request
		// surfaces as a per-item error rather than a controller failure.
		route := bgp.EVPNRoute{
			Type:        bgp.EVPNRouteTypeInclusiveMulticast,
			RD:          m.GetRd(),
			RTs:         m.GetRouteTargets(),
			EthernetTag: m.GetEthernetTag(),
			SRv6SID:     m.GetSid(),
			NextHop:     m.GetNextHop(),
		}
		if err := s.evpn.PushEVPNInclusiveMulticast(ctx, route); err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{TriggerPrefix: evpnImetTrigger(m.GetRd(), m.GetEthernetTag()), Reason: err.Error()})
			continue
		}
		resp.Advertised = append(resp.Advertised, m)
	}
	return connect.NewResponse(resp), nil
}

func (s *BgpRouteServer) BgpWithdrawEvpnImet(
	ctx context.Context,
	req *connect.Request[v1.BgpWithdrawEvpnImetRequest],
) (*connect.Response[v1.BgpWithdrawEvpnImetResponse], error) {
	if s.evpn == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errBGPDisabled)
	}
	resp := &v1.BgpWithdrawEvpnImetResponse{
		Withdrawn: make([]*v1.BgpEvpnImetKey, 0),
		Errors:    make([]*v1.OperationError, 0),
	}
	for _, k := range req.Msg.Keys {
		if err := s.evpn.WithdrawEVPNInclusiveMulticast(ctx, bgp.EVPNMcastKey{
			RD:          k.GetRd(),
			EthernetTag: k.GetEthernetTag(),
		}); err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{TriggerPrefix: evpnImetTrigger(k.GetRd(), k.GetEthernetTag()), Reason: err.Error()})
			continue
		}
		resp.Withdrawn = append(resp.Withdrawn, k)
	}
	return connect.NewResponse(resp), nil
}

// evpnMacTrigger names the RT2 identity for an OperationError.
func evpnMacTrigger(rd string, etag uint32, mac string) string {
	return fmt.Sprintf("rd=%s etag=%d mac=%s", rd, etag, mac)
}

// evpnImetTrigger names the RT3 identity for an OperationError.
func evpnImetTrigger(rd string, etag uint32) string {
	return fmt.Sprintf("rd=%s etag=%d", rd, etag)
}

func (s *BgpRouteServer) BgpAdvertiseEvpnEs(
	ctx context.Context,
	req *connect.Request[v1.BgpAdvertiseEvpnEsRequest],
) (*connect.Response[v1.BgpAdvertiseEvpnEsResponse], error) {
	if s.evpn == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errBGPDisabled)
	}
	resp := &v1.BgpAdvertiseEvpnEsResponse{
		Advertised: make([]*v1.BgpEvpnEs, 0),
		Errors:     make([]*v1.OperationError, 0),
	}
	for _, m := range req.Msg.Segments {
		esi, err := bpf.ParseESI(m.GetEsi())
		if err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{TriggerPrefix: evpnEsTrigger(m.GetRd(), m.GetEsi()), Reason: fmt.Sprintf("invalid ESI: %v", err)})
			continue
		}
		route := bgp.EVPNRoute{
			Type:       bgp.EVPNRouteTypeEthernetSegment,
			RD:         m.GetRd(),
			ESI:        esi,
			ESImportRT: m.GetEsImportRt(),
			NextHop:    m.GetNextHop(),
		}
		if err := s.evpn.PushEVPNEthernetSegment(ctx, route); err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{TriggerPrefix: evpnEsTrigger(m.GetRd(), m.GetEsi()), Reason: err.Error()})
			continue
		}
		resp.Advertised = append(resp.Advertised, m)
	}
	return connect.NewResponse(resp), nil
}

func (s *BgpRouteServer) BgpWithdrawEvpnEs(
	ctx context.Context,
	req *connect.Request[v1.BgpWithdrawEvpnEsRequest],
) (*connect.Response[v1.BgpWithdrawEvpnEsResponse], error) {
	if s.evpn == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errBGPDisabled)
	}
	resp := &v1.BgpWithdrawEvpnEsResponse{
		Withdrawn: make([]*v1.BgpEvpnEsKey, 0),
		Errors:    make([]*v1.OperationError, 0),
	}
	for _, k := range req.Msg.Keys {
		esi, err := bpf.ParseESI(k.GetEsi())
		if err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{TriggerPrefix: evpnEsTrigger(k.GetRd(), k.GetEsi()), Reason: fmt.Sprintf("invalid ESI: %v", err)})
			continue
		}
		if err := s.evpn.WithdrawEVPNEthernetSegment(ctx, bgp.EVPNESKey{RD: k.GetRd(), ESI: esi}); err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{TriggerPrefix: evpnEsTrigger(k.GetRd(), k.GetEsi()), Reason: err.Error()})
			continue
		}
		resp.Withdrawn = append(resp.Withdrawn, k)
	}
	return connect.NewResponse(resp), nil
}

// evpnEsTrigger names the RT4 identity for an OperationError.
func evpnEsTrigger(rd, esi string) string {
	return fmt.Sprintf("rd=%s esi=%s", rd, esi)
}

func (s *BgpRouteServer) BgpAdvertiseEvpnAd(
	ctx context.Context,
	req *connect.Request[v1.BgpAdvertiseEvpnAdRequest],
) (*connect.Response[v1.BgpAdvertiseEvpnAdResponse], error) {
	if s.evpn == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errBGPDisabled)
	}
	resp := &v1.BgpAdvertiseEvpnAdResponse{
		Advertised: make([]*v1.BgpEvpnAd, 0),
		Errors:     make([]*v1.OperationError, 0),
	}
	for _, m := range req.Msg.Routes {
		esi, err := bpf.ParseESI(m.GetEsi())
		if err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{TriggerPrefix: evpnAdTrigger(m.GetRd(), m.GetEsi(), m.GetEthernetTag()), Reason: fmt.Sprintf("invalid ESI: %v", err)})
			continue
		}
		// SID / next-hop / RD are validated in the encoder, so a bad request
		// surfaces as a per-item error rather than a controller failure.
		route := bgp.EVPNRoute{
			Type:         bgp.EVPNRouteTypeEthernetAD,
			RD:           m.GetRd(),
			RTs:          m.GetRouteTargets(),
			ESI:          esi,
			EthernetTag:  m.GetEthernetTag(),
			SRv6SID:      m.GetSid(),
			NextHop:      m.GetNextHop(),
			SingleActive: m.GetSingleActive(),
		}
		if err := s.evpn.PushEVPNEthernetAD(ctx, route); err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{TriggerPrefix: evpnAdTrigger(m.GetRd(), m.GetEsi(), m.GetEthernetTag()), Reason: err.Error()})
			continue
		}
		resp.Advertised = append(resp.Advertised, m)
	}
	return connect.NewResponse(resp), nil
}

func (s *BgpRouteServer) BgpWithdrawEvpnAd(
	ctx context.Context,
	req *connect.Request[v1.BgpWithdrawEvpnAdRequest],
) (*connect.Response[v1.BgpWithdrawEvpnAdResponse], error) {
	if s.evpn == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errBGPDisabled)
	}
	resp := &v1.BgpWithdrawEvpnAdResponse{
		Withdrawn: make([]*v1.BgpEvpnAdKey, 0),
		Errors:    make([]*v1.OperationError, 0),
	}
	for _, k := range req.Msg.Keys {
		esi, err := bpf.ParseESI(k.GetEsi())
		if err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{TriggerPrefix: evpnAdTrigger(k.GetRd(), k.GetEsi(), k.GetEthernetTag()), Reason: fmt.Sprintf("invalid ESI: %v", err)})
			continue
		}
		if err := s.evpn.WithdrawEVPNEthernetAD(ctx, bgp.EVPNADKey{
			RD:          k.GetRd(),
			ESI:         esi,
			EthernetTag: k.GetEthernetTag(),
		}); err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{TriggerPrefix: evpnAdTrigger(k.GetRd(), k.GetEsi(), k.GetEthernetTag()), Reason: err.Error()})
			continue
		}
		resp.Withdrawn = append(resp.Withdrawn, k)
	}
	return connect.NewResponse(resp), nil
}

// evpnAdTrigger names the RT1 identity for an OperationError.
func evpnAdTrigger(rd, esi string, etag uint32) string {
	return fmt.Sprintf("rd=%s esi=%s etag=%d", rd, esi, etag)
}

// protoToAdvertiseEvpnMac validates a BgpEvpnMac advertise request and
// converts it to a bgp.EVPNRoute. The SID / next-hop IPv6 checks happen in the
// encoder; the MAC and optional ESI are validated here so a bad request is a
// per-item error rather than a controller failure.
func protoToAdvertiseEvpnMac(m *v1.BgpEvpnMac) (bgp.EVPNRoute, error) {
	hw, err := net.ParseMAC(m.GetMac())
	if err != nil {
		return bgp.EVPNRoute{}, fmt.Errorf("invalid MAC %q: %w", m.GetMac(), err)
	}
	var esi [bpf.ESILen]byte
	if m.GetEsi() != "" {
		parsed, err := bpf.ParseESI(m.GetEsi())
		if err != nil {
			return bgp.EVPNRoute{}, fmt.Errorf("invalid ESI %q: %w", m.GetEsi(), err)
		}
		esi = parsed
	}
	return bgp.EVPNRoute{
		Type:        bgp.EVPNRouteTypeMACIP,
		RD:          m.GetRd(),
		RTs:         m.GetRouteTargets(),
		ESI:         esi,
		EthernetTag: m.GetEthernetTag(),
		// Store the canonical MAC: gobgp keys the advertised-path tracking
		// map on this string, so a withdraw must derive the same key. Using
		// the raw request value would let case / separator / zero-pad
		// variants miss on withdraw and strand the path.
		MAC:     hw.String(),
		SRv6SID: m.GetSid(),
		NextHop: m.GetNextHop(),
	}, nil
}

// protoToAdvertiseSRPolicy converts a BgpSrPolicy advertise request into a
// bgp.SRPolicy with a single local candidate path.
func protoToAdvertiseSRPolicy(p *v1.BgpSrPolicy) (bgp.SRPolicy, error) {
	endpoint, segments, err := parseSRPolicyEndpointSegments(p.GetEndpoint(), p.GetSegments())
	if err != nil {
		return bgp.SRPolicy{}, err
	}
	// The SR Policy NLRI carries an IPv6 next hop (SRv6 over IPv6); reject a
	// non-routable next hop at the RPC boundary with a per-item error that names
	// the field (the policy also has an endpoint + segments, so an unprefixed
	// error would be ambiguous).
	nh, err := bgp.ValidateIPv6NextHop(p.GetNextHop())
	if err != nil {
		return bgp.SRPolicy{}, fmt.Errorf("next_hop %w", err)
	}
	preference := p.GetPreference()
	if preference == 0 {
		preference = bgp.SRPolicyDefaultPreference
	}
	return bgp.SRPolicy{
		Color:            p.GetColor(),
		Endpoint:         endpoint,
		AdvertiseNextHop: nh,
		Candidates: []bgp.CandidatePath{{
			Origin:        bgp.OriginLocal,
			Distinguisher: p.GetDistinguisher(),
			Preference:    preference,
			SegmentList:   segments,
		}},
	}, nil
}
