package server

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/locator"
)

// LocatorServer is the Connect RPC handler for LocatorService. It is a
// thin adapter over locator.Manager; the manager owns lifecycle, the
// handler owns proto translation and error mapping.
type LocatorServer struct {
	mgr *locator.Manager
	// add registers a locator. SidFunctionService supplies a version that
	// also claims the CSIDs of uA entries already installed inside it,
	// under its own lock so a concurrent SidFunctionCreate cannot take one
	// in between. nil falls back to a plain Manager.Add.
	add func(*locator.Locator) error
	// del removes a locator. SidFunctionService supplies a version that
	// also refuses (unless forced) while a uN/uT-shaped SID entry uses the
	// locator's own prefix as its trigger -- such entries hold no
	// allocation binding, so Manager.Delete alone cannot see them. nil
	// falls back to a plain Manager.Delete.
	del func(name string, force bool) error
}

func NewLocatorServer(mgr *locator.Manager, add func(*locator.Locator) error, del func(string, bool) error) *LocatorServer {
	return &LocatorServer{mgr: mgr, add: add, del: del}
}

// replayOnSourceLocator wraps add so that registering the BGP source locator
// requests a replay of the VPN loc-rib. Every VPN headend entry takes its
// encapsulation source from that locator, so a route received while it was
// missing is tracked but never programmed, and nothing re-delivers it. The
// locator is often created over RPC after the daemon, and so its BGP
// sessions, are already up. The replay also rewrites installed routes when
// the locator comes back with a different prefix. add is returned unchanged
// when BGP or the source locator is not configured.
func replayOnSourceLocator(add func(*locator.Locator) error, source string, request func([]bgp.Family)) func(*locator.Locator) error {
	if add == nil || source == "" || request == nil {
		return add
	}
	return func(loc *locator.Locator) error {
		if err := add(loc); err != nil {
			return err
		}
		if loc.Name == source {
			request(vpnFamilies)
		}
		return nil
	}
}

func (s *LocatorServer) deleteLocator(name string, force bool) error {
	if s.del != nil {
		return s.del(name, force)
	}
	return s.mgr.Delete(name, force)
}

func (s *LocatorServer) addLocator(loc *locator.Locator) error {
	if s.add != nil {
		return s.add(loc)
	}
	return s.mgr.Add(loc)
}

func (s *LocatorServer) LocatorCreate(
	_ context.Context,
	req *connect.Request[v1.LocatorCreateRequest],
) (*connect.Response[v1.LocatorCreateResponse], error) {
	resp := &v1.LocatorCreateResponse{
		Created: make([]*v1.Locator, 0),
		Errors:  make([]*v1.OperationError, 0),
	}
	for _, in := range req.Msg.Locators {
		loc, err := protoToLocator(in)
		if err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: in.GetName(),
				Reason:        err.Error(),
			})
			continue
		}
		if err := s.addLocator(&loc); err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: in.GetName(),
				Reason:        err.Error(),
			})
			continue
		}
		// Echo the STORED locator, not the request: Manager.Add normalizes
		// host bits out of the prefix, and the response must match what
		// Get/List and locator_ref will actually see.
		resp.Created = append(resp.Created, locatorToProto(&loc))
	}
	return connect.NewResponse(resp), nil
}

func (s *LocatorServer) LocatorDelete(
	_ context.Context,
	req *connect.Request[v1.LocatorDeleteRequest],
) (*connect.Response[v1.LocatorDeleteResponse], error) {
	resp := &v1.LocatorDeleteResponse{
		DeletedNames: make([]string, 0),
		Errors:       make([]*v1.OperationError, 0),
	}
	force := req.Msg.GetForce()
	for _, name := range req.Msg.Names {
		if err := s.deleteLocator(name, force); err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: name,
				Reason:        err.Error(),
			})
			continue
		}
		resp.DeletedNames = append(resp.DeletedNames, name)
	}
	return connect.NewResponse(resp), nil
}

func (s *LocatorServer) LocatorList(
	_ context.Context,
	_ *connect.Request[v1.LocatorListRequest],
) (*connect.Response[v1.LocatorListResponse], error) {
	locs := s.mgr.List()
	out := make([]*v1.Locator, 0, len(locs))
	for i := range locs {
		out = append(out, locatorToProto(&locs[i]))
	}
	return connect.NewResponse(&v1.LocatorListResponse{Locators: out}), nil
}

func (s *LocatorServer) LocatorGet(
	_ context.Context,
	req *connect.Request[v1.LocatorGetRequest],
) (*connect.Response[v1.LocatorGetResponse], error) {
	loc, ok := s.mgr.Get(req.Msg.Name)
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("locator not found"))
	}
	return connect.NewResponse(&v1.LocatorGetResponse{Locator: locatorToProto(&loc)}), nil
}

func protoToLocator(in *v1.Locator) (locator.Locator, error) {
	prefix, err := netip.ParsePrefix(in.GetPrefix())
	if err != nil {
		return locator.Locator{}, err
	}
	// proto fields are uint32 but the locator struct stores them as uint8
	// (max 128 bits in an IPv6 SID, plus a small safety margin). Reject
	// values that would silently truncate so a typo like block_len=384
	// cannot wrap to a valid-looking 128.
	for _, f := range []struct {
		name string
		v    uint32
	}{
		{"block_len", in.GetBlockLen()},
		{"node_len", in.GetNodeLen()},
		{"function_len", in.GetFunctionLen()},
		{"argument_len", in.GetArgumentLen()},
	} {
		if f.v > 255 {
			return locator.Locator{}, fmt.Errorf("%s=%d exceeds uint8 range", f.name, f.v)
		}
	}
	return locator.Locator{
		Name:              in.GetName(),
		Prefix:            prefix,
		BlockLen:          uint8(in.GetBlockLen()),
		NodeLen:           uint8(in.GetNodeLen()),
		FunctionLen:       uint8(in.GetFunctionLen()),
		ArgumentLen:       uint8(in.GetArgumentLen()),
		Behavior:          protoToBehavior(in.GetBehavior()),
		FunctionAutoStart: in.GetFunctionAutoStart(),
		FunctionAutoEnd:   in.GetFunctionAutoEnd(),
	}, nil
}

func locatorToProto(loc *locator.Locator) *v1.Locator {
	return &v1.Locator{
		Name:              loc.Name,
		Prefix:            loc.Prefix.String(),
		BlockLen:          uint32(loc.BlockLen),
		NodeLen:           uint32(loc.NodeLen),
		FunctionLen:       uint32(loc.FunctionLen),
		ArgumentLen:       uint32(loc.ArgumentLen),
		Behavior:          behaviorToProto(loc.Behavior),
		FunctionAutoStart: loc.FunctionAutoStart,
		FunctionAutoEnd:   loc.FunctionAutoEnd,
	}
}

func protoToBehavior(b v1.LocatorBehaviorMode) locator.Behavior {
	switch b {
	case v1.LocatorBehaviorMode_LOCATOR_BEHAVIOR_MODE_CLASSIC:
		return locator.BehaviorClassic
	case v1.LocatorBehaviorMode_LOCATOR_BEHAVIOR_MODE_USID:
		return locator.BehaviorUSID
	default:
		return locator.BehaviorUnspecified
	}
}

func behaviorToProto(b locator.Behavior) v1.LocatorBehaviorMode {
	switch b {
	case locator.BehaviorClassic:
		return v1.LocatorBehaviorMode_LOCATOR_BEHAVIOR_MODE_CLASSIC
	case locator.BehaviorUSID:
		return v1.LocatorBehaviorMode_LOCATOR_BEHAVIOR_MODE_USID
	default:
		return v1.LocatorBehaviorMode_LOCATOR_BEHAVIOR_MODE_UNSPECIFIED
	}
}
