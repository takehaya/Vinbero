package server

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bgp/apply"
)

// srPolicyController is the subset of the BGP applier the SR Policy
// service drives: install/withdraw operator-defined policies and read the
// combined (local + BGP) table. It is nil when the in-process BGP speaker
// is disabled, in which case every RPC fails with FailedPrecondition.
type srPolicyController interface {
	ApplyLocalSRPolicy(p bgp.SRPolicy, withdraw bool)
	ListSRPolicies() []apply.SRPolicySnapshot
	HasLocalSRPolicy(color uint32, endpoint netip.Addr) bool
}

// SrPolicyServer is the Connect RPC handler for SrPolicyService. CRUD acts
// on operator-defined (local) SR Policies; BGP-learned policies are
// read-only (visible in List, rejected by Update/Delete).
type SrPolicyServer struct {
	ctrl srPolicyController
}

func NewSrPolicyServer(ctrl srPolicyController) *SrPolicyServer {
	return &SrPolicyServer{ctrl: ctrl}
}

func (s *SrPolicyServer) disabledErr() error {
	return connect.NewError(connect.CodeFailedPrecondition,
		errors.New("SR Policy service requires the in-process BGP speaker (--bgp-enabled)"))
}

// upsert handles both Create and Update: each is an idempotent set of the
// local candidate path for {color, endpoint}.
func (s *SrPolicyServer) upsert(defs []*v1.SrPolicyDef) []*v1.OperationError {
	errs := make([]*v1.OperationError, 0)
	for _, def := range defs {
		p, err := protoToLocalSRPolicy(def)
		if err != nil {
			errs = append(errs, &v1.OperationError{
				TriggerPrefix: def.GetEndpoint(),
				Reason:        err.Error(),
			})
			continue
		}
		s.ctrl.ApplyLocalSRPolicy(p, false)
	}
	return errs
}

func (s *SrPolicyServer) SrPolicyCreate(
	_ context.Context,
	req *connect.Request[v1.SrPolicyCreateRequest],
) (*connect.Response[v1.SrPolicyCreateResponse], error) {
	if s.ctrl == nil {
		return nil, s.disabledErr()
	}
	return connect.NewResponse(&v1.SrPolicyCreateResponse{
		Errors: s.upsert(req.Msg.GetPolicies()),
	}), nil
}

func (s *SrPolicyServer) SrPolicyUpdate(
	_ context.Context,
	req *connect.Request[v1.SrPolicyUpdateRequest],
) (*connect.Response[v1.SrPolicyUpdateResponse], error) {
	if s.ctrl == nil {
		return nil, s.disabledErr()
	}
	return connect.NewResponse(&v1.SrPolicyUpdateResponse{
		Errors: s.upsert(req.Msg.GetPolicies()),
	}), nil
}

func (s *SrPolicyServer) SrPolicyDelete(
	_ context.Context,
	req *connect.Request[v1.SrPolicyDeleteRequest],
) (*connect.Response[v1.SrPolicyDeleteResponse], error) {
	if s.ctrl == nil {
		return nil, s.disabledErr()
	}
	errs := make([]*v1.OperationError, 0)
	for _, key := range req.Msg.GetKeys() {
		endpoint, err := netip.ParseAddr(key.GetEndpoint())
		if err != nil {
			errs = append(errs, &v1.OperationError{
				TriggerPrefix: key.GetEndpoint(),
				Reason:        fmt.Sprintf("invalid endpoint: %v", err),
			})
			continue
		}
		if !endpoint.Is6() {
			errs = append(errs, &v1.OperationError{
				TriggerPrefix: key.GetEndpoint(),
				Reason:        "endpoint must be IPv6",
			})
			continue
		}
		if !s.ctrl.HasLocalSRPolicy(key.GetColor(), endpoint) {
			errs = append(errs, &v1.OperationError{
				TriggerPrefix: key.GetEndpoint(),
				Reason:        "no local SR Policy for this color/endpoint (BGP-learned policies are read-only)",
			})
			continue
		}
		s.ctrl.ApplyLocalSRPolicy(apply.LocalSRPolicy(key.GetColor(), endpoint, nil, 0), true)
	}
	return connect.NewResponse(&v1.SrPolicyDeleteResponse{Errors: errs}), nil
}

func (s *SrPolicyServer) SrPolicyList(
	_ context.Context,
	_ *connect.Request[v1.SrPolicyListRequest],
) (*connect.Response[v1.SrPolicyListResponse], error) {
	if s.ctrl == nil {
		return nil, s.disabledErr()
	}
	snaps := s.ctrl.ListSRPolicies()
	entries := make([]*v1.SrPolicyEntry, 0, len(snaps))
	for i := range snaps {
		entries = append(entries, snapshotToProto(&snaps[i]))
	}
	return connect.NewResponse(&v1.SrPolicyListResponse{Entries: entries}), nil
}

func protoToLocalSRPolicy(def *v1.SrPolicyDef) (bgp.SRPolicy, error) {
	endpoint, err := netip.ParseAddr(def.GetEndpoint())
	if err != nil {
		return bgp.SRPolicy{}, fmt.Errorf("invalid endpoint: %w", err)
	}
	// The SR Policy endpoint is matched against the VPN route's IPv6 next
	// hop (RFC 9252 SRv6 over IPv6), so an IPv4 endpoint can never steer.
	if !endpoint.Is6() {
		return bgp.SRPolicy{}, fmt.Errorf("endpoint must be IPv6: %s", endpoint)
	}
	if len(def.GetSegments()) == 0 {
		return bgp.SRPolicy{}, errors.New("at least one transport segment is required")
	}
	segments := make([]netip.Addr, 0, len(def.GetSegments()))
	for _, s := range def.GetSegments() {
		sid, err := netip.ParseAddr(s)
		if err != nil {
			return bgp.SRPolicy{}, fmt.Errorf("invalid segment %q: %w", s, err)
		}
		segments = append(segments, sid)
	}
	return apply.LocalSRPolicy(def.GetColor(), endpoint, segments, def.GetPreference()), nil
}

func snapshotToProto(snap *apply.SRPolicySnapshot) *v1.SrPolicyEntry {
	cands := make([]*v1.SrPolicyCandidate, 0, len(snap.Candidates))
	for i := range snap.Candidates {
		c := &snap.Candidates[i]
		segs := make([]string, len(c.SegmentList))
		for j, sid := range c.SegmentList {
			segs[j] = sid.String()
		}
		cands = append(cands, &v1.SrPolicyCandidate{
			Origin:        originToProto(c.Origin),
			Distinguisher: c.Distinguisher,
			Preference:    c.Preference,
			Segments:      segs,
			Active:        c.Active,
		})
	}
	return &v1.SrPolicyEntry{
		Color:      snap.Color,
		Endpoint:   snap.Endpoint.String(),
		PolicyId:   snap.PolicyID,
		Candidates: cands,
	}
}

func originToProto(o bgp.Origin) v1.SrPolicyOrigin {
	switch o {
	case bgp.OriginLocal:
		return v1.SrPolicyOrigin_SR_POLICY_ORIGIN_LOCAL
	case bgp.OriginBGP:
		return v1.SrPolicyOrigin_SR_POLICY_ORIGIN_BGP
	default:
		return v1.SrPolicyOrigin_SR_POLICY_ORIGIN_UNSPECIFIED
	}
}
