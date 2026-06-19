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

// reconcileOrRollback programs the data plane after an in-memory mutation. On
// failure it invokes undo to revert the mutation and re-reconciles so the data
// plane converges to the reverted state, then returns the original error. This
// keeps the RPC atomic: a failed reconcile (an unresolvable AC interface, a
// transient map-write error) must not leave the in-memory state ahead of the
// data plane — in particular a bad AC left behind would fail every later
// reconcile too.
//
// undo returns an error so a rollback that itself fails (e.g. re-adding an AC
// that a concurrent bind now claims for another VRF) is surfaced rather than
// swallowed: when it does, the in-memory state could not be restored, so both
// errors are reported and the compensating re-reconcile is skipped. When undo
// succeeds the re-reconcile is best-effort; the original error is surfaced.
func (s *VrfServer) reconcileOrRollback(undo func() error) error {
	if err := s.reconcile(); err != nil {
		if uerr := undo(); uerr != nil {
			return fmt.Errorf("%w; rollback failed (in-memory state may diverge from the data plane): %v", err, uerr)
		}
		// undo restored the prior in-memory state; re-reconcile to converge the
		// data plane onto it. If that also fails the in-memory and data-plane
		// state can still diverge, so surface it alongside the original error
		// rather than swallowing it.
		if rerr := s.reconcile(); rerr != nil {
			return fmt.Errorf("%w; data plane could not be reverted after rollback (state may diverge): %v", err, rerr)
		}
		return err
	}
	return nil
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
	acVal := vrf.AC{Interface: ac.GetInterfaceName(), VLAN: uint16(ac.GetVlan())}
	added, err := s.mgr.AddAC(name, acVal)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	// Roll back only what this call changed: if the AC was already present
	// (added == false), a reconcile failure must not remove the pre-existing AC.
	undo := func() error { return nil }
	if added {
		undo = func() error { s.mgr.RemoveAC(name, acVal); return nil }
	}
	if err := s.reconcileOrRollback(undo); err != nil {
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
	// Required fields: RemoveAC is idempotent on a genuinely-absent AC, but an
	// empty name or interface is an operator typo, not a legitimate remove, so
	// reject it instead of silently no-op'ing.
	if req.Msg.GetName() == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("vrf name is required"))
	}
	if ac.GetInterfaceName() == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("ac interface_name is required"))
	}
	// Range-check before the uint16 cast: a vlan past 4095 would wrap (e.g.
	// 4096 -> 0) and delete a different AC than the operator named.
	if ac.GetVlan() > 4095 {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("vlan %d out of range (0..4095)", ac.GetVlan()))
	}
	name := req.Msg.GetName()
	acVal := vrf.AC{Interface: ac.GetInterfaceName(), VLAN: uint16(ac.GetVlan())}
	removed := s.mgr.RemoveAC(name, acVal)
	// Roll back only what this call changed: if the AC was already absent
	// (removed == false), a reconcile failure must not create it via the undo.
	undo := func() error { return nil }
	if removed {
		undo = func() error { _, err := s.mgr.AddAC(name, acVal); return err }
	}
	if err := s.reconcileOrRollback(undo); err != nil {
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
	prev := s.mgr.Policy()
	s.mgr.SetPolicy(vrf.Policy{DefaultDeny: p.GetDefaultDeny(), DenyAction: action})
	if err := s.reconcileOrRollback(func() error { s.mgr.SetPolicy(prev); return nil }); err != nil {
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
