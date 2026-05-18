package server

import (
	"context"
	"errors"
	"net/netip"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/locator"
)

// LocatorServer is the Connect RPC handler for LocatorService. It is a
// thin adapter over locator.Manager; the manager owns lifecycle, the
// handler owns proto translation and error mapping.
type LocatorServer struct {
	mgr *locator.Manager
}

func NewLocatorServer(mgr *locator.Manager) *LocatorServer {
	return &LocatorServer{mgr: mgr}
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
		if err := s.mgr.Add(&loc); err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: in.GetName(),
				Reason:        err.Error(),
			})
			continue
		}
		resp.Created = append(resp.Created, in)
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
		if err := s.mgr.Delete(name, force); err != nil {
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
