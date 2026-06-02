package server

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
)

// mupLocalKey identifies one locally-originated MUP route. typ is first so an
// ISD {rd,prefix} can never collide with a T1ST {rd,prefix,teid=0}. Only the
// fields that identify each route type are set (the rest stay zero), matching
// the per-type BGP withdraw keys, so the key a create stores equals the key a
// delete derives.
type mupLocalKey struct {
	typ      bgp.MUPRouteType
	rd       string
	prefix   string // ISD / T1ST
	address  string // DSD
	endpoint string // T2ST
	teid     uint32 // T1ST / T2ST
	teidLen  uint8  // T2ST
}

func mupKeyFor(mr bgp.MUPRoute) mupLocalKey {
	k := mupLocalKey{typ: mr.Type, rd: mr.RD}
	switch mr.Type {
	case bgp.MUPRouteTypeISD:
		k.prefix = mr.Prefix
	case bgp.MUPRouteTypeDSD:
		k.address = mr.Address
	case bgp.MUPRouteTypeT1ST:
		k.prefix = mr.Prefix
		k.teid = mr.TEID
	case bgp.MUPRouteTypeT2ST:
		k.endpoint = mr.Endpoint
		k.teid = mr.TEID
		k.teidLen = mr.TEIDLen
	}
	return k
}

// MupServer is the Connect RPC handler for MupService. It originates a node's
// local BGP MUP routes (SAFI 85) and tracks them in an in-memory table so
// MupList can report them. advertiser is non-nil exactly when the in-process
// BGP speaker is up (the same condition gates every RPC with
// FailedPrecondition); nextHop is the default BGP next hop
// (bgp.global.next_hop) used when a route does not carry its own.
type MupServer struct {
	// mu guards routes + pending only -- it is NOT held across the gobgp
	// Push/Withdraw I/O (so a wedged gobgp management channel cannot block
	// MupList or other RPCs). To keep the cap exact under concurrent creates, a
	// new route reserves a slot (pending++) under mu before its Push and finalizes
	// (pending--, store on success) under mu after; the cap counts routes+pending.
	mu      sync.Mutex
	pending int // NEW routes whose Push is in flight, reserved against the cap
	// maxRoutes caps how many local MUP routes may be originated (0 = unlimited),
	// bounding SAFI 85 amplification from the unauthenticated surface; a new route
	// beyond the cap is a per-item error.
	maxRoutes  uint32
	advertiser bgp.MUPController
	nextHop    string
	routes     map[mupLocalKey]bgp.MUPRoute
}

func NewMupServer(advertiser bgp.MUPController, nextHop string, maxRoutes uint32) *MupServer {
	return &MupServer{
		advertiser: advertiser,
		nextHop:    nextHop,
		maxRoutes:  maxRoutes,
		routes:     make(map[mupLocalKey]bgp.MUPRoute),
	}
}

func (s *MupServer) disabledErr() error {
	return connect.NewError(connect.CodeFailedPrecondition,
		errors.New("MUP service requires the in-process BGP speaker (--bgp-enabled)"))
}

// upsert handles both Create and Update: each is an idempotent originate of the
// MUP route keyed by its type + identifying fields. The route is stored only
// after a successful Push, so MupList never reports a route the encoder rejected.
func (s *MupServer) upsert(ctx context.Context, routes []*v1.BgpMupRoute) []*v1.OperationError {
	errs := make([]*v1.OperationError, 0)
	for _, r := range routes {
		mr, err := parseMUPRoute(r)
		if err != nil {
			errs = append(errs, &v1.OperationError{TriggerPrefix: mupRouteID(r), Reason: err.Error()})
			continue
		}
		// Default an empty next hop to the configured bgp.global.next_hop, then
		// require it to be a routable IPv6 (SRv6 over IPv6); empty / IPv4 / :: would
		// serialize into a route no PE can forward toward.
		if mr.NextHop == "" {
			mr.NextHop = s.nextHop
		}
		if _, err := bgp.ValidateIPv6NextHop(mr.NextHop); err != nil {
			errs = append(errs, &v1.OperationError{
				TriggerPrefix: mupRouteID(r),
				Reason:        fmt.Sprintf("bgp.global.next_hop %v (or set --next-hop)", err),
			})
			continue
		}
		// Cap + reserve atomically, then Push outside the lock. A NEW route reserves
		// a slot (pending++) so a concurrent create sees it and cannot also pass an
		// under-cap check; an update of an existing key is always allowed. The
		// counter is conservative (it can only over-count, never under-count), so
		// the cap is never exceeded. The route is stored only after Push succeeds.
		key := mupKeyFor(mr)
		s.mu.Lock()
		_, exists := s.routes[key]
		if !exists && s.maxRoutes > 0 && uint32(len(s.routes)+s.pending) >= s.maxRoutes {
			s.mu.Unlock()
			errs = append(errs, &v1.OperationError{
				TriggerPrefix: mupRouteID(r),
				Reason:        fmt.Sprintf("MUP route limit reached (mup_max_routes=%d)", s.maxRoutes),
			})
			continue
		}
		if !exists {
			s.pending++
		}
		s.mu.Unlock()

		err = pushMUPRoute(ctx, s.advertiser, mr)

		s.mu.Lock()
		if !exists {
			s.pending--
		}
		if err != nil {
			s.mu.Unlock()
			errs = append(errs, &v1.OperationError{TriggerPrefix: mupRouteID(r), Reason: err.Error()})
			continue
		}
		s.routes[key] = mr
		s.mu.Unlock()
	}
	return errs
}

func (s *MupServer) MupCreate(
	ctx context.Context,
	req *connect.Request[v1.MupCreateRequest],
) (*connect.Response[v1.MupCreateResponse], error) {
	if s.advertiser == nil {
		return nil, s.disabledErr()
	}
	return connect.NewResponse(&v1.MupCreateResponse{Errors: s.upsert(ctx, req.Msg.GetRoutes())}), nil
}

func (s *MupServer) MupUpdate(
	ctx context.Context,
	req *connect.Request[v1.MupUpdateRequest],
) (*connect.Response[v1.MupUpdateResponse], error) {
	if s.advertiser == nil {
		return nil, s.disabledErr()
	}
	return connect.NewResponse(&v1.MupUpdateResponse{Errors: s.upsert(ctx, req.Msg.GetRoutes())}), nil
}

func (s *MupServer) MupDelete(
	ctx context.Context,
	req *connect.Request[v1.MupDeleteRequest],
) (*connect.Response[v1.MupDeleteResponse], error) {
	if s.advertiser == nil {
		return nil, s.disabledErr()
	}
	errs := make([]*v1.OperationError, 0)
	for _, r := range req.Msg.GetRoutes() {
		// parseMUPRoute re-runs validateMUPRouteFields so the T2ST teid_len
		// narrowing cast cannot wrap into a key that mismatches what was pushed.
		mr, err := parseMUPRoute(r)
		if err != nil {
			errs = append(errs, &v1.OperationError{TriggerPrefix: mupRouteID(r), Reason: err.Error()})
			continue
		}
		// Withdraw outside the lock (the lock never spans gobgp I/O), then drop the
		// table entry. WithdrawMUP* no-ops for an unadvertised route. A concurrent
		// same-key create races here, but the RIB is authoritative and the table is
		// the List view -- the same benign window the create path accepts.
		if err := withdrawMUPRoute(ctx, s.advertiser, mr); err != nil {
			errs = append(errs, &v1.OperationError{TriggerPrefix: mupRouteID(r), Reason: err.Error()})
			continue
		}
		s.mu.Lock()
		delete(s.routes, mupKeyFor(mr))
		s.mu.Unlock()
	}
	return connect.NewResponse(&v1.MupDeleteResponse{Errors: errs}), nil
}

func (s *MupServer) MupList(
	_ context.Context,
	_ *connect.Request[v1.MupListRequest],
) (*connect.Response[v1.MupListResponse], error) {
	if s.advertiser == nil {
		return nil, s.disabledErr()
	}
	s.mu.Lock()
	out := make([]*v1.BgpMupRoute, 0, len(s.routes))
	for _, mr := range s.routes {
		out = append(out, mupRouteToProto(mr))
	}
	s.mu.Unlock()
	// Stable order for a deterministic CLI table / test assertions.
	sort.Slice(out, func(i, j int) bool {
		if out[i].GetRouteType() != out[j].GetRouteType() {
			return out[i].GetRouteType() < out[j].GetRouteType()
		}
		return mupRouteID(out[i]) < mupRouteID(out[j])
	})
	return connect.NewResponse(&v1.MupListResponse{Routes: out}), nil
}

// mupRouteToProto is the reverse of protoToMUPRoute, for MupList. route_type
// comes from MUPRouteType.String() (isd/dsd/t1st/t2st); the uint8 fields widen
// back to uint32.
func mupRouteToProto(mr bgp.MUPRoute) *v1.BgpMupRoute {
	return &v1.BgpMupRoute{
		RouteType:    mr.Type.String(),
		Rd:           mr.RD,
		RouteTargets: mr.RTs,
		Prefix:       mr.Prefix,
		Address:      mr.Address,
		Teid:         mr.TEID,
		TeidLen:      uint32(mr.TEIDLen),
		Qfi:          uint32(mr.QFI),
		Rqi:          uint32(mr.RQI),
		Endpoint:     mr.Endpoint,
		Source:       mr.Source,
		SegmentId2:   uint32(mr.SegmentID2),
		SegmentId4:   mr.SegmentID4,
		Srv6Sid:      mr.SRv6SID,
		NextHop:      mr.NextHop,
	}
}
