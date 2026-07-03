package server

import (
	"context"
	"fmt"
	"sync"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/vrf"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

// SidLister is the SID-table surface the VRF delete reference check reads.
// *bpf.MapOperations satisfies it; tests use a fake.
type SidLister interface {
	ListSidFunctions() (map[string]*bpf.SidFunctionEntry, error)
	GetSidAux(index uint32) (*bpf.SidAuxEntry, error)
}

// BindingGetter reports whether a vrf-bgp binding references a VRF name, so
// VrfDelete can refuse while the BGP facet is still attached.
// *vrfbgp.Manager satisfies it; tests use a fake.
type BindingGetter interface {
	Get(vrfName string) (vrfbgp.Binding, bool)
}

// VrfServer is the Connect RPC handler for VrfService: the single VRF
// surface. It drives both facets of the VRF object — the kernel device
// (VrfCreate/VrfDelete via vrf.DeviceOps, which *netresource.ResourceManager
// satisfies) and the ingress membership + default-deny policy (VrfAc*/
// VrfSetPolicy via vrf.Programmer, which *bpf.MapOperations satisfies). Every
// dependency is an interface (plus the resolve func) so the handlers can be
// tested without netlink or a live BPF map.
type VrfServer struct {
	mgr      *vrf.Manager
	prog     vrf.Programmer
	resolve  func(string) (uint32, error)
	dev      vrf.DeviceOps
	sids     SidLister
	bindings BindingGetter
	// mu serializes the mutation handlers' mutate+reconcile(+rollback)
	// sequence and the device create/delete flows. SetIngressVrf /
	// SetIngressPolicy replace the maps with a snapshot-then-rollback strategy
	// (not a kernel-atomic swap), so two concurrent reconciles could interleave
	// and one rollback could clobber the other's write; the delete flow's
	// check-then-act likewise must not interleave with an AC add. Mirrors
	// VrfBgpServer.mu, which serializes the same way.
	mu sync.Mutex
}

func NewVrfServer(mgr *vrf.Manager, prog vrf.Programmer, dev vrf.DeviceOps, sids SidLister, bindings BindingGetter) *VrfServer {
	return &VrfServer{mgr: mgr, prog: prog, resolve: vrf.ResolveByName, dev: dev, sids: sids, bindings: bindings}
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

// VrfCreate creates (or adopts) the kernel VRF device for each requested VRF
// and allocates its vrf_id, so a device-created VRF is a full first-class
// object from the start. The request is the kernel facet only: acs and vrf_id
// are server-owned and must be unset. No ingress reconcile is needed (no AC
// changed).
func (s *VrfServer) VrfCreate(
	_ context.Context,
	req *connect.Request[v1.VrfCreateRequest],
) (*connect.Response[v1.VrfCreateResponse], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	resp := &v1.VrfCreateResponse{
		Created: make([]*v1.Vrf, 0),
		Errors:  make([]*v1.OperationError, 0),
	}
	for _, in := range req.Msg.Vrfs {
		created, opErr := s.createOne(in)
		if opErr != nil {
			resp.Errors = append(resp.Errors, opErr)
			continue
		}
		resp.Created = append(resp.Created, vrfToProto(created))
	}
	return connect.NewResponse(resp), nil
}

// createOne validates and creates one kernel VRF device, returning the
// resulting VRF (both server-assigned ids filled). Caller holds s.mu.
func (s *VrfServer) createOne(in *v1.Vrf) (vrf.VRF, *v1.OperationError) {
	fail := func(reason string) (vrf.VRF, *v1.OperationError) {
		return vrf.VRF{}, &v1.OperationError{TriggerPrefix: in.GetName(), Reason: reason}
	}
	// acs / vrf_id / ifindex are server-owned outputs; a request carrying them
	// is a caller mixing up the facets (or replaying a VrfShow result), so
	// reject rather than silently ignore.
	if len(in.GetAcs()) > 0 {
		return fail("acs are managed via VrfAcAdd, not VrfCreate")
	}
	if in.GetVrfId() != 0 || in.GetIfindex() != 0 {
		return fail("vrf_id and ifindex are server-assigned and must be unset")
	}
	created, err := s.mgr.CreateDevice(in.GetName(), vrf.Device{
		TableID:          in.GetTableId(),
		Members:          in.GetMembers(),
		EnableL3mdevRule: in.GetEnableL3MdevRule(),
	}, s.dev)
	if err != nil {
		return fail(err.Error())
	}
	return created, nil
}

// VrfDelete removes whole VRF objects. It refuses while anything still
// references the VRF — an installed End.T/DT* SID on its device, remaining
// ingress ACs, or a vrf-bgp binding — so a delete can never silently strand a
// facet (refuse-to-guess; the operator tears the references down first).
func (s *VrfServer) VrfDelete(
	_ context.Context,
	req *connect.Request[v1.VrfDeleteRequest],
) (*connect.Response[v1.VrfDeleteResponse], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	resp := &v1.VrfDeleteResponse{
		DeletedNames: make([]string, 0),
		Errors:       make([]*v1.OperationError, 0),
	}
	for _, name := range req.Msg.Names {
		if opErr := s.deleteOne(name); opErr != nil {
			resp.Errors = append(resp.Errors, opErr)
			continue
		}
		resp.DeletedNames = append(resp.DeletedNames, name)
	}
	return connect.NewResponse(resp), nil
}

// deleteOne deletes one VRF after the reference checks. Caller holds s.mu,
// which serializes it against every VrfService mutation; a concurrent
// vrfbgp.Bind can still slip a binding in after the check (the same
// check-then-act window today's SID check has) — acceptable, since the
// binding then simply references a VRF that Ensure will recreate.
func (s *VrfServer) deleteOne(name string) *v1.OperationError {
	fail := func(reason string) *v1.OperationError {
		return &v1.OperationError{TriggerPrefix: name, Reason: reason}
	}
	if name == "" {
		return fail("vrf name is required")
	}
	if name == vrf.GlobalVRFName {
		return fail("the reserved global VRF cannot be deleted")
	}
	v, ok := s.mgr.Get(name)
	if !ok {
		return fail("unknown VRF (a raw kernel device is not managed here; adopt it via VrfCreate first)")
	}
	if len(v.ACs) > 0 {
		return fail(fmt.Sprintf("%d ingress AC(s) remain; remove them first (vrf ac-remove)", len(v.ACs)))
	}
	if _, bound := s.bindings.Get(name); bound {
		return fail("a vrf-bgp binding references this VRF; unbind it first (vrf-bgp unbind)")
	}
	// SID reference check on the device ifindex. A deviceless VRF can still
	// shadow a same-named raw kernel device that SIDs reference, so fall back
	// to a best-effort name resolve.
	var ifindex uint32
	if v.Device != nil {
		ifindex = v.Device.Ifindex
	} else if resolved, err := s.resolve(name); err == nil {
		ifindex = resolved
	}
	if ifindex != 0 {
		ref, err := findVrfReference(s.sids, ifindex)
		if err != nil {
			return fail(fmt.Sprintf("failed to check SID references: %v", err))
		}
		if ref != "" {
			return fail(fmt.Sprintf("VRF is referenced by SID %s", ref))
		}
	}
	// Device teardown before identity removal: a failed netlink delete leaves
	// the manager untouched, so the two states stay consistent and the delete
	// can simply be retried.
	if v.Device != nil {
		if err := s.dev.DeleteVrf(name); err != nil {
			return fail(fmt.Sprintf("delete kernel device: %v", err))
		}
	}
	s.mgr.Delete(name)
	return nil
}

// findVrfReference returns the prefix of an End.T/DT4/DT6/DT46 SID whose
// l3vrf aux references the given vrf_ifindex ("" = unreferenced). Deleting a
// VRF device under such a SID would blackhole its decap traffic.
func findVrfReference(sids SidLister, ifindex uint32) (string, error) {
	entries, err := sids.ListSidFunctions()
	if err != nil {
		return "", fmt.Errorf("list SID functions: %w", err)
	}
	for prefix, entry := range entries {
		switch v1.Srv6LocalAction(entry.Action) {
		case v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_T,
			v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DT4,
			v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DT6,
			v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DT46:
		default:
			continue
		}
		if entry.AuxIndex == 0 {
			continue
		}
		aux, err := sids.GetSidAux(uint32(entry.AuxIndex))
		if err != nil {
			continue
		}
		if bpf.SidAuxL3VrfData(aux) == ifindex {
			return prefix, nil
		}
	}
	return "", nil
}

func (s *VrfServer) VrfAcAdd(
	_ context.Context,
	req *connect.Request[v1.VrfAcAddRequest],
) (*connect.Response[v1.VrfAcAddResponse], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
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
	s.mu.Lock()
	defer s.mu.Unlock()
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
	s.mu.Lock()
	defer s.mu.Unlock()
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

// vrfToProto renders a VRF's full state: identity (name, vrf_id), the ingress
// facet (access circuits), and the kernel-device facet when present.
func vrfToProto(v vrf.VRF) *v1.Vrf {
	acs := make([]*v1.VrfAc, 0, len(v.ACs))
	for _, ac := range v.ACs {
		acs = append(acs, &v1.VrfAc{InterfaceName: ac.Interface, Vlan: uint32(ac.VLAN)})
	}
	out := &v1.Vrf{Name: v.Name, VrfId: v.ID, Acs: acs}
	if v.Device != nil {
		out.TableId = v.Device.TableID
		out.Members = v.Device.Members
		out.EnableL3MdevRule = v.Device.EnableL3mdevRule
		out.Ifindex = v.Device.Ifindex
	}
	return out
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
