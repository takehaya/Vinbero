package server

import (
	"context"
	"fmt"

	"connectrpc.com/connect"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
)

// validateMUPRouteFields rejects wire values that do not fit the narrower fields
// they map to. Without this an out-of-range proto uint32 would silently wrap to
// a different in-range value (e.g. teid_len=288 -> uint8 32), slipping past the
// downstream "TEIDLen > 32" guard and advertising an unintended route.
func validateMUPRouteFields(r *v1.BgpMupRoute) error {
	if v := r.GetTeidLen(); v > 32 {
		return fmt.Errorf("teid_len %d out of range (0-32)", v)
	}
	if v := r.GetQfi(); v > 63 {
		return fmt.Errorf("qfi %d out of range (0-63)", v)
	}
	if v := r.GetRqi(); v > 1 {
		return fmt.Errorf("rqi %d out of range (0-1)", v)
	}
	if v := r.GetSegmentId2(); v > 0xFFFF {
		return fmt.Errorf("segment_id2 %d out of range (0-65535)", v)
	}
	return nil
}

// protoToMUPRoute converts a wire BgpMupRoute into the bgpd-agnostic form. The
// route type is parsed separately so a bad type is reported per-route, and the
// caller must run validateMUPRouteFields first so the narrowing casts below
// cannot wrap an out-of-range value.
func protoToMUPRoute(r *v1.BgpMupRoute) bgp.MUPRoute {
	return bgp.MUPRoute{
		RD:         r.GetRd(),
		RTs:        r.GetRouteTargets(),
		Prefix:     r.GetPrefix(),
		Address:    r.GetAddress(),
		TEID:       r.GetTeid(),
		TEIDLen:    uint8(r.GetTeidLen()),
		QFI:        uint8(r.GetQfi()),
		RQI:        uint8(r.GetRqi()),
		Endpoint:   r.GetEndpoint(),
		Source:     r.GetSource(),
		SegmentID2: uint16(r.GetSegmentId2()),
		SegmentID4: r.GetSegmentId4(),
		SRv6SID:    r.GetSrv6Sid(),
		NextHop:    r.GetNextHop(),
	}
}

// mupRouteType maps the operator-facing route-type string to the typed enum.
func mupRouteType(s string) (bgp.MUPRouteType, error) {
	switch s {
	case "isd":
		return bgp.MUPRouteTypeISD, nil
	case "dsd":
		return bgp.MUPRouteTypeDSD, nil
	case "t1st":
		return bgp.MUPRouteTypeT1ST, nil
	case "t2st":
		return bgp.MUPRouteTypeT2ST, nil
	default:
		return 0, fmt.Errorf("unknown MUP route_type %q (want isd|dsd|t1st|t2st)", s)
	}
}

// mupRouteID returns a human identifier for a MUP route, for error reporting.
func mupRouteID(r *v1.BgpMupRoute) string {
	switch r.GetRouteType() {
	case "dsd":
		return r.GetAddress()
	case "t2st":
		return fmt.Sprintf("%s/teid:%d", r.GetEndpoint(), r.GetTeid())
	default: // isd / t1st
		return r.GetPrefix()
	}
}

// parseMUPRoute validates a wire MUP route and converts it to the domain form
// with its Type set. Shared by the advertise/withdraw RPCs and MupService so the
// "parse type + range-check + convert" preamble lives in one place.
func parseMUPRoute(r *v1.BgpMupRoute) (bgp.MUPRoute, error) {
	typ, err := mupRouteType(r.GetRouteType())
	if err != nil {
		return bgp.MUPRoute{}, err
	}
	if err := validateMUPRouteFields(r); err != nil {
		return bgp.MUPRoute{}, err
	}
	mr := protoToMUPRoute(r)
	mr.Type = typ
	return mr, nil
}

// pushMUPRoute advertises mr through the MUPController method for its type.
// The caller has set mr.Type (parseMUPRoute does).
func pushMUPRoute(ctx context.Context, ctrl bgp.MUPController, mr bgp.MUPRoute) error {
	switch mr.Type {
	case bgp.MUPRouteTypeISD:
		return ctrl.PushMUPISD(ctx, mr)
	case bgp.MUPRouteTypeDSD:
		return ctrl.PushMUPDSD(ctx, mr)
	case bgp.MUPRouteTypeT1ST:
		return ctrl.PushMUPT1ST(ctx, mr)
	case bgp.MUPRouteTypeT2ST:
		return ctrl.PushMUPT2ST(ctx, mr)
	default:
		return fmt.Errorf("unsupported MUP route type %v", mr.Type)
	}
}

// withdrawMUPRoute withdraws mr through the MUPController method for its type,
// deriving the per-type key from mr. WithdrawMUP* no-ops for a route that was
// never advertised.
func withdrawMUPRoute(ctx context.Context, ctrl bgp.MUPController, mr bgp.MUPRoute) error {
	switch mr.Type {
	case bgp.MUPRouteTypeISD:
		return ctrl.WithdrawMUPISD(ctx, bgp.MUPISDKey{RD: mr.RD, Prefix: mr.Prefix})
	case bgp.MUPRouteTypeDSD:
		return ctrl.WithdrawMUPDSD(ctx, bgp.MUPDSDKey{RD: mr.RD, Address: mr.Address})
	case bgp.MUPRouteTypeT1ST:
		return ctrl.WithdrawMUPT1ST(ctx, bgp.MUPT1STKey{RD: mr.RD, Prefix: mr.Prefix, TEID: mr.TEID})
	case bgp.MUPRouteTypeT2ST:
		return ctrl.WithdrawMUPT2ST(ctx, bgp.MUPT2STKey{RD: mr.RD, Endpoint: mr.Endpoint, TEID: mr.TEID, TEIDLen: mr.TEIDLen})
	default:
		return fmt.Errorf("unsupported MUP route type %v", mr.Type)
	}
}

func (s *BgpRouteServer) BgpAdvertiseMup(
	ctx context.Context,
	req *connect.Request[v1.BgpAdvertiseMupRequest],
) (*connect.Response[v1.BgpAdvertiseMupResponse], error) {
	if s.mup == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errBGPDisabled)
	}
	resp := &v1.BgpAdvertiseMupResponse{
		Advertised: make([]*v1.BgpMupRoute, 0),
		Errors:     make([]*v1.OperationError, 0),
	}
	for _, r := range req.Msg.Routes {
		mr, err := parseMUPRoute(r)
		if err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{TriggerPrefix: mupRouteID(r), Reason: err.Error()})
			continue
		}
		if err := pushMUPRoute(ctx, s.mup, mr); err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{TriggerPrefix: mupRouteID(r), Reason: err.Error()})
			continue
		}
		resp.Advertised = append(resp.Advertised, r)
	}
	return connect.NewResponse(resp), nil
}

func (s *BgpRouteServer) BgpWithdrawMup(
	ctx context.Context,
	req *connect.Request[v1.BgpWithdrawMupRequest],
) (*connect.Response[v1.BgpWithdrawMupResponse], error) {
	if s.mup == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errBGPDisabled)
	}
	resp := &v1.BgpWithdrawMupResponse{
		Withdrawn: make([]*v1.BgpMupRoute, 0),
		Errors:    make([]*v1.OperationError, 0),
	}
	for _, r := range req.Msg.Routes {
		// parseMUPRoute runs validateMUPRouteFields, guarding the T2ST teid_len
		// narrowing cast so an out-of-range value cannot wrap to a key that
		// silently mismatches what was advertised.
		mr, err := parseMUPRoute(r)
		if err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{TriggerPrefix: mupRouteID(r), Reason: err.Error()})
			continue
		}
		if err := withdrawMUPRoute(ctx, s.mup, mr); err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{TriggerPrefix: mupRouteID(r), Reason: err.Error()})
			continue
		}
		resp.Withdrawn = append(resp.Withdrawn, r)
	}
	return connect.NewResponse(resp), nil
}
