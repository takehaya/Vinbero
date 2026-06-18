package server

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/ingressvrf"
)

// IngressVrfServer is the Connect RPC handler for IngressVrfService. It is a
// thin adapter over ingressvrf.Manager: each mutation updates the manager then
// reconciles the data-plane maps (ingress_vrf_map + the global policy).
type IngressVrfServer struct {
	mgr    *ingressvrf.Manager
	mapOps *bpf.MapOperations
}

func NewIngressVrfServer(mgr *ingressvrf.Manager, mapOps *bpf.MapOperations) *IngressVrfServer {
	return &IngressVrfServer{mgr: mgr, mapOps: mapOps}
}

func (s *IngressVrfServer) reconcile() error {
	return s.mgr.Reconcile(ingressvrf.ResolveByName, s.mapOps)
}

func (s *IngressVrfServer) IngressVrfBind(
	_ context.Context,
	req *connect.Request[v1.IngressVrfBindRequest],
) (*connect.Response[v1.IngressVrfBindResponse], error) {
	resp := &v1.IngressVrfBindResponse{
		Bound:  make([]*v1.IngressVrfEntry, 0),
		Errors: make([]*v1.OperationError, 0),
	}
	for _, e := range req.Msg.Entries {
		if e.Vlan > 4095 {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: fmt.Sprintf("%s.%d", e.InterfaceName, e.Vlan),
				Reason:        fmt.Sprintf("vlan %d out of range (0..4095)", e.Vlan),
			})
			continue
		}
		if err := s.mgr.Bind(e.InterfaceName, uint16(e.Vlan), e.VrfId); err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: fmt.Sprintf("%s.%d", e.InterfaceName, e.Vlan),
				Reason:        err.Error(),
			})
			continue
		}
		resp.Bound = append(resp.Bound, e)
	}
	if err := s.reconcile(); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(resp), nil
}

func (s *IngressVrfServer) IngressVrfUnbind(
	_ context.Context,
	req *connect.Request[v1.IngressVrfUnbindRequest],
) (*connect.Response[v1.IngressVrfUnbindResponse], error) {
	resp := &v1.IngressVrfUnbindResponse{
		Unbound: make([]*v1.IngressVrfEntry, 0),
		Errors:  make([]*v1.OperationError, 0),
	}
	for _, e := range req.Msg.Entries {
		s.mgr.Unbind(e.InterfaceName, uint16(e.Vlan))
		resp.Unbound = append(resp.Unbound, e)
	}
	if err := s.reconcile(); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(resp), nil
}

func (s *IngressVrfServer) IngressVrfList(
	_ context.Context,
	_ *connect.Request[v1.IngressVrfListRequest],
) (*connect.Response[v1.IngressVrfListResponse], error) {
	entries := s.mgr.List()
	out := make([]*v1.IngressVrfEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, &v1.IngressVrfEntry{
			InterfaceName: e.Interface,
			Vlan:          uint32(e.VLAN),
			VrfId:         e.VRFID,
		})
	}
	pol := s.mgr.Policy()
	return connect.NewResponse(&v1.IngressVrfListResponse{
		Entries: out,
		Policy: &v1.IngressVrfPolicy{
			DefaultDeny: pol.DefaultDeny,
			DenyAction:  denyActionString(pol.DenyAction),
		},
	}), nil
}

func (s *IngressVrfServer) IngressVrfSetPolicy(
	_ context.Context,
	req *connect.Request[v1.IngressVrfSetPolicyRequest],
) (*connect.Response[v1.IngressVrfSetPolicyResponse], error) {
	p := req.Msg.GetPolicy()
	action, err := parseDenyAction(p.GetDenyAction())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	s.mgr.SetPolicy(ingressvrf.Policy{DefaultDeny: p.GetDefaultDeny(), DenyAction: action})
	if err := s.reconcile(); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&v1.IngressVrfSetPolicyResponse{
		Policy: &v1.IngressVrfPolicy{
			DefaultDeny: p.GetDefaultDeny(),
			DenyAction:  denyActionString(action),
		},
	}), nil
}

// parseDenyAction maps the wire string to the data-plane code. Empty defaults
// to drop (the safe default for a deny policy).
func parseDenyAction(s string) (uint8, error) {
	switch s {
	case "", "drop":
		return ingressvrf.DenyActionDrop, nil
	case "pass":
		return ingressvrf.DenyActionPass, nil
	default:
		return 0, fmt.Errorf("deny_action %q: want \"drop\" or \"pass\"", s)
	}
}

func denyActionString(a uint8) string {
	if a == ingressvrf.DenyActionPass {
		return "pass"
	}
	return "drop"
}
