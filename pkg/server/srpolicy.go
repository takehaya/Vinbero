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
// read-only (visible in List, rejected by Update/Delete). A local policy whose
// advertise flag is set is also originated into BGP (SAFI 73) via advertiser.
type SrPolicyServer struct {
	ctrl srPolicyController
	// advertiser originates a local SR Policy into BGP (SAFI 73) when its
	// advertise flag is set. It is wired non-nil alongside ctrl when the
	// in-process BGP speaker is up; if it is nil, an advertise=true request is a
	// per-item error rather than a silent no-op.
	advertiser bgp.SRPolicyController
	// nextHop is the BGP next hop stamped on an advertised SR Policy: this PE's
	// reachable IPv6 address (bgp.global.next_hop), validated per advertise.
	nextHop string
}

func NewSrPolicyServer(ctrl srPolicyController, advertiser bgp.SRPolicyController, nextHop string) *SrPolicyServer {
	return &SrPolicyServer{ctrl: ctrl, advertiser: advertiser, nextHop: nextHop}
}

func (s *SrPolicyServer) disabledErr() error {
	return connect.NewError(connect.CodeFailedPrecondition,
		errors.New("SR Policy service requires the in-process BGP speaker (--bgp-enabled)"))
}

// upsert handles both Create and Update: each is an idempotent set of the
// local candidate path for {color, endpoint}.
func (s *SrPolicyServer) upsert(ctx context.Context, defs []*v1.SrPolicyDef) []*v1.OperationError {
	errs := make([]*v1.OperationError, 0)
	for _, def := range defs {
		p, err := protoToLocalSRPolicy(def)
		if err != nil {
			errs = append(errs, &v1.OperationError{
				TriggerPrefix: srPolicyTrigger(def.GetColor(), def.GetEndpoint()),
				Reason:        err.Error(),
			})
			continue
		}
		s.ctrl.ApplyLocalSRPolicy(p, false)
		if err := s.syncAdvertise(ctx, def, p); err != nil {
			errs = append(errs, &v1.OperationError{
				TriggerPrefix: srPolicyTrigger(def.GetColor(), def.GetEndpoint()),
				Reason:        err.Error(),
			})
			continue
		}
	}
	return errs
}

// srPolicyAdvertiseKey is the BGP SR Policy NLRI key for advertising or
// withdrawing a local policy. It reuses the local candidate's distinguisher so a
// withdraw matches what syncAdvertise pushed; a local policy from
// apply.LocalSRPolicy always carries exactly one candidate.
func srPolicyAdvertiseKey(p bgp.SRPolicy) bgp.SRPolicyKey {
	return bgp.SRPolicyKey{
		Color:         p.Color,
		Endpoint:      p.Endpoint,
		Distinguisher: p.Candidates[0].Distinguisher,
	}
}

// syncAdvertise reconciles a local policy's BGP advertisement with its advertise
// flag: push it into SAFI 73 (origin local) when set, or withdraw any prior
// advertisement when not, so toggling the flag off on an Update stops advertising.
// The advertised NLRI reuses the local candidate's distinguisher, so the withdraw
// key is deterministic. WithdrawPolicy is a no-op for a policy that was never
// advertised, so the not-advertised branch is safe to run on every upsert.
func (s *SrPolicyServer) syncAdvertise(ctx context.Context, def *v1.SrPolicyDef, p bgp.SRPolicy) error {
	if s.advertiser == nil {
		if def.GetAdvertise() {
			return errors.New("advertise requires the in-process BGP speaker (--bgp-enabled)")
		}
		return nil
	}
	if !def.GetAdvertise() {
		return s.advertiser.WithdrawPolicy(ctx, srPolicyAdvertiseKey(p))
	}
	nh, err := netip.ParseAddr(s.nextHop)
	if err != nil || !nh.Is6() || nh.Is4In6() {
		return fmt.Errorf("advertise requires a valid IPv6 bgp.global.next_hop, got %q", s.nextHop)
	}
	adv := p
	adv.AdvertiseNextHop = nh
	return s.advertiser.PushPolicy(ctx, adv)
}

func (s *SrPolicyServer) SrPolicyCreate(
	ctx context.Context,
	req *connect.Request[v1.SrPolicyCreateRequest],
) (*connect.Response[v1.SrPolicyCreateResponse], error) {
	if s.ctrl == nil {
		return nil, s.disabledErr()
	}
	return connect.NewResponse(&v1.SrPolicyCreateResponse{
		Errors: s.upsert(ctx, req.Msg.GetPolicies()),
	}), nil
}

func (s *SrPolicyServer) SrPolicyUpdate(
	ctx context.Context,
	req *connect.Request[v1.SrPolicyUpdateRequest],
) (*connect.Response[v1.SrPolicyUpdateResponse], error) {
	if s.ctrl == nil {
		return nil, s.disabledErr()
	}
	return connect.NewResponse(&v1.SrPolicyUpdateResponse{
		Errors: s.upsert(ctx, req.Msg.GetPolicies()),
	}), nil
}

func (s *SrPolicyServer) SrPolicyDelete(
	ctx context.Context,
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
				TriggerPrefix: srPolicyTrigger(key.GetColor(), key.GetEndpoint()),
				Reason:        fmt.Sprintf("invalid endpoint: %v", err),
			})
			continue
		}
		if !endpoint.Is6() {
			errs = append(errs, &v1.OperationError{
				TriggerPrefix: srPolicyTrigger(key.GetColor(), key.GetEndpoint()),
				Reason:        "endpoint must be IPv6",
			})
			continue
		}
		if !s.ctrl.HasLocalSRPolicy(key.GetColor(), endpoint) {
			errs = append(errs, &v1.OperationError{
				TriggerPrefix: srPolicyTrigger(key.GetColor(), key.GetEndpoint()),
				Reason:        "no local SR Policy for this color/endpoint (BGP-learned policies are read-only)",
			})
			continue
		}
		lp := apply.LocalSRPolicy(key.GetColor(), endpoint, nil, 0)
		s.ctrl.ApplyLocalSRPolicy(lp, true)
		// Withdraw any BGP advertisement this policy had (a no-op if it was never
		// advertised). The key reuses the local candidate's distinguisher so it
		// matches what syncAdvertise pushed.
		if s.advertiser != nil {
			if err := s.advertiser.WithdrawPolicy(ctx, srPolicyAdvertiseKey(lp)); err != nil {
				errs = append(errs, &v1.OperationError{
					TriggerPrefix: srPolicyTrigger(key.GetColor(), key.GetEndpoint()),
					Reason:        err.Error(),
				})
				continue
			}
		}
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
	endpoint, segments, err := parseSRPolicyEndpointSegments(def.GetEndpoint(), def.GetSegments())
	if err != nil {
		return bgp.SRPolicy{}, err
	}
	return apply.LocalSRPolicy(def.GetColor(), endpoint, segments, def.GetPreference()), nil
}

// parseSRPolicyEndpointSegments validates and parses an SR Policy endpoint
// and its transport segment list, shared by the local-CRUD and advertise
// converters. The endpoint must be IPv6: it is matched against the VPN
// route's IPv6 next hop (RFC 9252 SRv6 over IPv6), so an IPv4 endpoint could
// never steer. A policy needs at least one transport segment to compose
// ahead of the service SID.
func parseSRPolicyEndpointSegments(endpoint string, segs []string) (netip.Addr, []netip.Addr, error) {
	ep, err := netip.ParseAddr(endpoint)
	if err != nil {
		return netip.Addr{}, nil, fmt.Errorf("invalid endpoint: %w", err)
	}
	if !ep.Is6() {
		return netip.Addr{}, nil, fmt.Errorf("endpoint must be IPv6: %s", ep)
	}
	if len(segs) == 0 {
		return netip.Addr{}, nil, errors.New("at least one transport segment is required")
	}
	out := make([]netip.Addr, 0, len(segs))
	for _, s := range segs {
		sid, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Addr{}, nil, fmt.Errorf("invalid segment %q: %w", s, err)
		}
		// Transport segments are SRv6 SIDs, so they must be IPv6. Rejecting
		// here returns a per-item RPC error instead of a silent create that
		// the data-plane write (UpsertSRPolicy) would later refuse.
		if !sid.Is6() {
			return netip.Addr{}, nil, fmt.Errorf("transport segment must be IPv6: %s", sid)
		}
		out = append(out, sid)
	}
	return ep, out, nil
}

// srPolicyTrigger formats the SR Policy identity for an OperationError so a
// per-item failure names the offending {color, endpoint} rather than just
// the endpoint -- multiple colors can share one endpoint.
func srPolicyTrigger(color uint32, endpoint string) string {
	return fmt.Sprintf("color=%d endpoint=%s", color, endpoint)
}

// srPolicyKeyTrigger is srPolicyTrigger plus the distinguisher, for the BGP
// advertise/withdraw paths whose NLRI key is {color, endpoint, distinguisher}.
func srPolicyKeyTrigger(color uint32, endpoint string, distinguisher uint32) string {
	return fmt.Sprintf("color=%d endpoint=%s dist=%d", color, endpoint, distinguisher)
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
