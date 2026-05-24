package server

import (
	"context"
	"errors"
	"net/netip"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
)

// BgpRouteServer is the Connect RPC handler for BgpRouteService. It is a
// thin adapter over bgp.RouteAdvertiser (VPN / unicast) and
// bgp.SRPolicyController (SR Policy). Both are nil when vinberod runs
// without --bgp-enabled; every RPC then fails with FailedPrecondition so
// the operator gets a clear signal rather than a silent no-op.
type BgpRouteServer struct {
	advertiser bgp.RouteAdvertiser
	srPolicy   bgp.SRPolicyController
}

func NewBgpRouteServer(advertiser bgp.RouteAdvertiser, srPolicy bgp.SRPolicyController) *BgpRouteServer {
	return &BgpRouteServer{advertiser: advertiser, srPolicy: srPolicy}
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
			resp.Errors = append(resp.Errors, &v1.OperationError{TriggerPrefix: p.GetEndpoint(), Reason: err.Error()})
			continue
		}
		if err := s.srPolicy.PushPolicy(ctx, policy); err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{TriggerPrefix: p.GetEndpoint(), Reason: err.Error()})
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
			resp.Errors = append(resp.Errors, &v1.OperationError{TriggerPrefix: k.GetEndpoint(), Reason: err.Error()})
			continue
		}
		if err := s.srPolicy.WithdrawPolicy(ctx, bgp.SRPolicyKey{
			Color:         k.GetColor(),
			Endpoint:      endpoint,
			Distinguisher: k.GetDistinguisher(),
		}); err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{TriggerPrefix: k.GetEndpoint(), Reason: err.Error()})
			continue
		}
		resp.Withdrawn = append(resp.Withdrawn, k)
	}
	return connect.NewResponse(resp), nil
}

// protoToAdvertiseSRPolicy converts a BgpSrPolicy advertise request into a
// bgp.SRPolicy with a single local candidate path.
func protoToAdvertiseSRPolicy(p *v1.BgpSrPolicy) (bgp.SRPolicy, error) {
	endpoint, err := netip.ParseAddr(p.GetEndpoint())
	if err != nil {
		return bgp.SRPolicy{}, err
	}
	nh, err := netip.ParseAddr(p.GetNextHop())
	if err != nil {
		return bgp.SRPolicy{}, err
	}
	segments := make([]netip.Addr, 0, len(p.GetSegments()))
	for _, s := range p.GetSegments() {
		sid, err := netip.ParseAddr(s)
		if err != nil {
			return bgp.SRPolicy{}, err
		}
		segments = append(segments, sid)
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
