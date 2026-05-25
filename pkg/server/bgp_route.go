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
)

// BgpRouteServer is the Connect RPC handler for BgpRouteService. It is a
// thin adapter over bgp.RouteAdvertiser (VPN / unicast) and
// bgp.SRPolicyController (SR Policy). Both are nil when vinberod runs
// without --bgp-enabled; every RPC then fails with FailedPrecondition so
// the operator gets a clear signal rather than a silent no-op.
type BgpRouteServer struct {
	advertiser bgp.RouteAdvertiser
	srPolicy   bgp.SRPolicyController
	evpn       bgp.EVPNController
}

func NewBgpRouteServer(advertiser bgp.RouteAdvertiser, srPolicy bgp.SRPolicyController, evpn bgp.EVPNController) *BgpRouteServer {
	return &BgpRouteServer{advertiser: advertiser, srPolicy: srPolicy, evpn: evpn}
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
		err = s.advertiser.Advertise(ctx, bgp.VPNRoute{
			Family:  fam,
			Prefix:  r.GetPrefix(),
			RD:      r.GetRd(),
			RTs:     r.GetRouteTargets(),
			SRv6SID: r.GetSrv6Sid(),
			NextHop: r.GetNextHop(),
			Color:   r.GetColor(),
		})
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
		if _, err := net.ParseMAC(k.GetMac()); err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{TriggerPrefix: evpnMacTrigger(k.GetRd(), k.GetEthernetTag(), k.GetMac()), Reason: fmt.Sprintf("invalid MAC: %v", err)})
			continue
		}
		if err := s.evpn.WithdrawEVPNMac(ctx, bgp.EVPNMACKey{
			RD:          k.GetRd(),
			EthernetTag: k.GetEthernetTag(),
			MAC:         k.GetMac(),
		}); err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{TriggerPrefix: evpnMacTrigger(k.GetRd(), k.GetEthernetTag(), k.GetMac()), Reason: err.Error()})
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

// protoToAdvertiseEvpnMac validates a BgpEvpnMac advertise request and
// converts it to a bgp.EVPNRoute. The SID / next-hop IPv6 checks happen in the
// encoder; the MAC and optional ESI are validated here so a bad request is a
// per-item error rather than a controller failure.
func protoToAdvertiseEvpnMac(m *v1.BgpEvpnMac) (bgp.EVPNRoute, error) {
	if _, err := net.ParseMAC(m.GetMac()); err != nil {
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
		MAC:         m.GetMac(),
		SRv6SID:     m.GetSid(),
		NextHop:     m.GetNextHop(),
	}, nil
}

// protoToAdvertiseSRPolicy converts a BgpSrPolicy advertise request into a
// bgp.SRPolicy with a single local candidate path.
func protoToAdvertiseSRPolicy(p *v1.BgpSrPolicy) (bgp.SRPolicy, error) {
	endpoint, segments, err := parseSRPolicyEndpointSegments(p.GetEndpoint(), p.GetSegments())
	if err != nil {
		return bgp.SRPolicy{}, err
	}
	nh, err := netip.ParseAddr(p.GetNextHop())
	if err != nil {
		return bgp.SRPolicy{}, fmt.Errorf("invalid next hop: %w", err)
	}
	// The SR Policy NLRI carries an IPv6 next hop (SRv6 over IPv6); an IPv4
	// next hop would be rejected later by the controller, so fail at the RPC
	// boundary with a per-item error to match Advertise/Create.
	if !nh.Is6() {
		return bgp.SRPolicy{}, fmt.Errorf("next hop must be IPv6: %s", nh)
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
