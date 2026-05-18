package server

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
)

// BgpRouteServer is the Connect RPC handler for BgpRouteService. It is a
// thin adapter over bgp.RouteAdvertiser. advertiser is nil when vinberod
// runs without --bgp-enabled; every RPC then fails with
// FailedPrecondition so the operator gets a clear signal rather than a
// silent no-op.
type BgpRouteServer struct {
	advertiser bgp.RouteAdvertiser
}

func NewBgpRouteServer(advertiser bgp.RouteAdvertiser) *BgpRouteServer {
	return &BgpRouteServer{advertiser: advertiser}
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
