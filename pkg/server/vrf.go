package server

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/vrf"
)

// VrfServer is the Connect RPC handler for VrfService: the VRF's ingress facet
// (access-circuit membership + global default-deny policy). It is a thin
// adapter over vrf.Manager; each mutation reconciles the data-plane maps
// (ingress_vrf_map + the global policy). It depends on vrf.Programmer (which
// *bpf.MapOperations satisfies) and a resolver so the handlers can be tested
// without a live BPF map.
type VrfServer struct {
	mgr     *vrf.Manager
	prog    vrf.Programmer
	resolve func(string) (uint32, error)
}

func NewVrfServer(mgr *vrf.Manager, prog vrf.Programmer) *VrfServer {
	return &VrfServer{mgr: mgr, prog: prog, resolve: vrf.ResolveByName}
}

func (s *VrfServer) reconcile() error {
	return s.mgr.Reconcile(s.resolve, s.prog)
}

func (s *VrfServer) VrfAcAdd(
	_ context.Context,
	req *connect.Request[v1.VrfAcAddRequest],
) (*connect.Response[v1.VrfAcAddResponse], error) {
	ac := req.Msg.GetAc()
	if ac.GetVlan() > 4095 {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("vlan %d out of range (0..4095)", ac.GetVlan()))
	}
	name := req.Msg.GetName()
	if err := s.mgr.AddAC(name, vrf.AC{Interface: ac.GetInterfaceName(), VLAN: uint16(ac.GetVlan())}); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if err := s.reconcile(); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	id, _ := s.mgr.IDForName(name)
	v, _ := s.mgr.ByID(id)
	return connect.NewResponse(&v1.VrfAcAddResponse{Vrf: vrfToProto(v)}), nil
}

func (s *VrfServer) VrfAcRemove(
	_ context.Context,
	req *connect.Request[v1.VrfAcRemoveRequest],
) (*connect.Response[v1.VrfAcRemoveResponse], error) {
	ac := req.Msg.GetAc()
	// Range-check before the uint16 cast: a vlan past 4095 would wrap (e.g.
	// 4096 -> 0) and delete a different AC than the operator named.
	if ac.GetVlan() > 4095 {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("vlan %d out of range (0..4095)", ac.GetVlan()))
	}
	s.mgr.RemoveAC(req.Msg.GetName(), vrf.AC{Interface: ac.GetInterfaceName(), VLAN: uint16(ac.GetVlan())})
	if err := s.reconcile(); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&v1.VrfAcRemoveResponse{}), nil
}

func (s *VrfServer) VrfSetPolicy(
	_ context.Context,
	req *connect.Request[v1.VrfSetPolicyRequest],
) (*connect.Response[v1.VrfSetPolicyResponse], error) {
	p := req.Msg.GetPolicy()
	action, err := parseDenyAction(p.GetDenyAction())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	s.mgr.SetPolicy(vrf.Policy{DefaultDeny: p.GetDefaultDeny(), DenyAction: action})
	if err := s.reconcile(); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&v1.VrfSetPolicyResponse{
		Policy: &v1.VrfPolicy{DefaultDeny: p.GetDefaultDeny(), DenyAction: denyActionString(action)},
	}), nil
}

func (s *VrfServer) VrfShow(
	_ context.Context,
	_ *connect.Request[v1.VrfShowRequest],
) (*connect.Response[v1.VrfShowResponse], error) {
	vrfs := s.mgr.List()
	out := make([]*v1.Vrf, 0, len(vrfs))
	for _, v := range vrfs {
		out = append(out, vrfToProto(v))
	}
	pol := s.mgr.Policy()
	return connect.NewResponse(&v1.VrfShowResponse{
		Vrfs:   out,
		Policy: &v1.VrfPolicy{DefaultDeny: pol.DefaultDeny, DenyAction: denyActionString(pol.DenyAction)},
	}), nil
}

// vrfToProto renders a VRF's ingress facet (name, vrf_id, access circuits).
func vrfToProto(v vrf.VRF) *v1.Vrf {
	acs := make([]*v1.VrfAc, 0, len(v.ACs))
	for _, ac := range v.ACs {
		acs = append(acs, &v1.VrfAc{InterfaceName: ac.Interface, Vlan: uint32(ac.VLAN)})
	}
	return &v1.Vrf{Name: v.Name, VrfId: v.ID, Acs: acs}
}

// parseDenyAction maps the wire string to the data-plane code; empty = drop.
func parseDenyAction(s string) (uint8, error) {
	switch s {
	case "", "drop":
		return vrf.DenyActionDrop, nil
	case "pass":
		return vrf.DenyActionPass, nil
	default:
		return 0, fmt.Errorf("deny_action %q: want \"drop\" or \"pass\"", s)
	}
}

func denyActionString(a uint8) string {
	if a == vrf.DenyActionPass {
		return "pass"
	}
	return "drop"
}
