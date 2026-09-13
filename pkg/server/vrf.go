package server

import (
	"context"
	"fmt"
	"math"
	"slices"
	"sync"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/vrf"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

// SidLister is the SID-table surface the VRF delete reference check reads.
// *bpf.MapOperations satisfies it; tests use a fake.
type SidLister interface {
	ListSidFunctions() (map[string]*bpf.SidFunctionEntry, error)
	GetSidAux(index uint32) (*bpf.SidAuxEntry, error)
	// EndtVRFGrantReferences reports whether a plugin-dispatched End.DT* grant
	// points at this VRF's device ifindex. A plugin handoff keeps its decap
	// VRF in a host-owned grant map rather than in l3vrf aux, so the aux scan
	// above cannot see it.
	EndtVRFGrantReferences(vrfIfindex uint32) (uint32, bool, error)
}

// BindingGetter reports whether a vrf-bgp binding references a VRF name, so
// VrfDelete can refuse while the BGP facet is still attached and the bridge
// attach can gate its EVPN enable on the binding's export RTs.
// *vrfbgp.Manager satisfies it; tests use a fake.
type BindingGetter interface {
	Get(vrfName string) (vrfbgp.Binding, bool)
}

// FdbRegistrar is the FDB-watcher surface the bridge facet lifecycle drives:
// an attached bridge's MAC learning feeds fdb_map (and EVPN RT2 when auto-
// advertise is on). *netlinkwatch.FDBWatcher satisfies it; tests use a fake.
type FdbRegistrar interface {
	RegisterBridge(ifindex int, bdID uint16)
	UnregisterBridge(ifindex int)
}

// VrfServer is the Connect RPC handler for VrfService: the single VRF
// surface. It drives every facet of the VRF object — the kernel device
// (VrfCreate/VrfDelete via vrf.DeviceOps), the L2 bridge domain
// (VrfBridgeAttach/VrfBridgeDetach via vrf.BridgeOps + FdbRegistrar + the
// EVPN coordinator; *netresource.ResourceManager satisfies both ops
// interfaces) and the ingress membership + default-deny policy (VrfAc*/
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
	bridges  vrf.BridgeOps
	fdb      FdbRegistrar
	evpn     *EvpnCoordinator // nil unless EVPN auto-advertise is on
	// evpnReplay re-applies the EVPN loc-rib through the applier; nil when
	// BGP is off. VrfBridgeAttach fires it when the VRF's binding imports
	// EVPN RTs: the just-attached facet completes the import surface, so
	// routes dropped fail-closed before the attach are rescued. Failures
	// are logged inside the hook (best-effort).
	evpnReplay func()
	// mu serializes the mutation handlers' mutate+reconcile(+rollback)
	// sequence and the device / bridge create+delete flows. SetIngressVrf /
	// SetIngressPolicy replace the maps with a snapshot-then-rollback strategy
	// (not a kernel-atomic swap), so two concurrent reconciles could interleave
	// and one rollback could clobber the other's write; the delete flows'
	// check-then-act likewise must not interleave with an AC add or a bridge
	// attach.
	//
	// The mutex is SHARED with VrfBgpServer (server.go wires the same one into
	// both): the cross-facet flows (VrfDelete refuses while a binding exists;
	// commitBinding / VrfBgpUnbind read the bridge facet to drive the EVPN
	// coordinator while attach/detach mutate it) are check-then-act across the
	// two managers, so serializing only within each server would leave a
	// window where the check and the act see different states.
	mu *sync.Mutex
	// grantLease closes the last window between a plugin's decap-grant install
	// and this VRF delete. VrfDelete holds it across the grant-reference check
	// and the device teardown; the plugin's local-SID install holds the same
	// lock across its VRF resolve and grant write. With it, a grant can never
	// be written for an ifindex a delete is freeing: the delete either sees the
	// grant and refuses, or the install's resolve fails because the device is
	// gone. It is the cplane manager's lock, shared here; nil when control-
	// plane plugins are disabled -- pinned grants from an earlier run can
	// still exist then, but no install can race the delete, and the reference
	// check below still refuses while one is live. It is a leaf lock, always
	// taken under s.mu and releasing nothing else, so it cannot deadlock with
	// applyMu (which the delete never takes).
	grantLease *sync.Mutex
}

// NewVrfServer wires the handler. mu is the mutation mutex, shared with
// VrfBgpServer so cross-facet invariants hold (see the field comment); nil
// allocates a private one (tests without a VrfBgpServer).
func NewVrfServer(mgr *vrf.Manager, prog vrf.Programmer, dev vrf.DeviceOps, sids SidLister, bindings BindingGetter, bridges vrf.BridgeOps, fdb FdbRegistrar, evpn *EvpnCoordinator, evpnReplay func(), mu *sync.Mutex, grantLease *sync.Mutex) *VrfServer {
	if mu == nil {
		mu = &sync.Mutex{}
	}
	return &VrfServer{mgr: mgr, prog: prog, resolve: vrf.ResolveByName, dev: dev, sids: sids, bindings: bindings, bridges: bridges, fdb: fdb, evpn: evpn, evpnReplay: evpnReplay, mu: mu, grantLease: grantLease}
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
	// acs / bridge / vrf_id / ifindex are managed elsewhere or server-owned; a
	// request carrying them is a caller mixing up the facets (or replaying a
	// VrfShow result), so reject rather than silently ignore.
	if len(in.GetAcs()) > 0 {
		return fail("acs are managed via VrfAcAdd, not VrfCreate")
	}
	if in.GetBridge() != nil {
		return fail("the bridge facet is managed via VrfBridgeAttach, not VrfCreate")
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
	if v.Bridge != nil {
		return fail(fmt.Sprintf("bridge %q is attached; detach it first (vrf bridge-detach)", v.Bridge.Name))
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
	// Hold the grant lease across the grant-reference check and the device
	// teardown below. A plugin's decap-grant install takes the same lock across
	// its VRF resolve and grant write, so a grant cannot appear for this
	// ifindex between the check and the moment teardown makes the ifindex
	// unresolvable: the install either wrote the grant before this check (which
	// then refuses) or resolves after the device is gone (and fails). It is a
	// leaf held only here; nil when control-plane plugins are off, where no
	// install exists to race (the reference check below still guards pinned
	// grants a previous run left behind).
	if s.grantLease != nil {
		s.grantLease.Lock()
		defer s.grantLease.Unlock()
	}
	if ifindex != 0 {
		ref, err := findVrfReference(s.sids, ifindex)
		if err != nil {
			return fail(fmt.Sprintf("failed to check SID references: %v", err))
		}
		if ref != "" {
			return fail(fmt.Sprintf("VRF is referenced by SID %s", ref))
		}
		// A plugin-dispatched End.DT* keeps its decap VRF in a host-owned grant
		// map, not in l3vrf aux, so the scan above cannot see it. Refuse the
		// delete while a grant still points at this device: dropping it would
		// dangle the grant, and a reused ifindex would send that plugin's decap
		// into another routing domain.
		auxIdx, granted, err := s.sids.EndtVRFGrantReferences(ifindex)
		if err != nil {
			return fail(fmt.Sprintf("failed to check plugin decap-VRF grants: %v", err))
		}
		if granted {
			return fail(fmt.Sprintf("VRF is referenced by a plugin decap-VRF grant (aux index %d)", auxIdx))
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

// findVrfReference returns the prefix of an End.T/DT4/DT6/DT46/uT SID whose
// l3vrf aux references the given vrf_ifindex ("" = unreferenced). Deleting a
// VRF device under such a SID would blackhole its decap traffic (uT reads
// the same leading bytes through the l3vrf view).
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
			v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DT46,
			v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_UT:
		default:
			continue
		}
		if entry.AuxIndex == 0 {
			continue
		}
		aux, err := sids.GetSidAux(uint32(entry.AuxIndex))
		if err != nil {
			// Fail closed: an unreadable aux might be the reference. Treating
			// it as "no reference" could delete a device an End.DT* SID still
			// delivers into (blackholing its decap traffic); surfacing the
			// error refuses the delete and leaves it retryable.
			return "", fmt.Errorf("read aux %d of SID %s: %w", entry.AuxIndex, prefix, err)
		}
		if bpf.SidAuxL3VrfData(aux) == ifindex {
			return prefix, nil
		}
	}
	return "", nil
}

// VrfBridgeAttach attaches the L2 bridge-domain facet: it creates (or adopts)
// the kernel bridge, records it on the VRF, and registers the bridge with the
// FDB watcher for MAC learning. When EVPN auto-advertise is on and the VRF's
// binding declares EVPN export RTs, the bridge domain is enabled (RT3 + FDB
// replay as RT2) — the facet attached here is the bd the coordinator
// resolves. The binding lookup is direct by VRF name.
func (s *VrfServer) VrfBridgeAttach(
	_ context.Context,
	req *connect.Request[v1.VrfBridgeAttachRequest],
) (*connect.Response[v1.VrfBridgeAttachResponse], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	vrfName := req.Msg.GetVrfName()
	br := req.Msg.GetBridge()
	if vrfName == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("vrf_name is required"))
	}
	if br.GetName() == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("bridge.name is required"))
	}
	if br.GetIfindex() != 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("bridge.ifindex is server-assigned and must be unset"))
	}
	// Range-check before the uint16 cast: bd_id past 65535 would wrap and
	// scope the FDB to a different bridge domain than the caller asked for.
	if br.GetBdId() == 0 || br.GetBdId() > math.MaxUint16 {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("bridge.bd_id %d out of range (1..%d)", br.GetBdId(), math.MaxUint16))
	}
	bdID := uint16(br.GetBdId())
	attached, err := s.mgr.AttachBridge(vrfName, vrf.Bridge{
		Name:    br.GetName(),
		BdID:    bdID,
		Members: br.GetMembers(),
	}, s.bridges)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	s.fdb.RegisterBridge(int(attached.Bridge.Ifindex), bdID)
	// EVPN facet side: enable only when the binding actually advertises EVPN
	// (export RTs present) -- an ungated enable could push RT3 with an empty
	// RT list; this aligns with commitBinding. The coordinator resolves the
	// just-attached facet by VRF name, so the facet IS this bridge.
	if s.evpn != nil {
		if b, bound := s.bindings.Get(vrfName); bound && len(b.ExportRTsForFamily(bgp.FamilyEVPN)) > 0 {
			s.evpn.Enable(b)
		}
	}
	// Receive side: the attach completed the import surface (binding with
	// EVPN import RTs + facet), so replay the loc-rib to rescue routes that
	// were dropped fail-closed while the facet was missing. The import-RT
	// gate is deliberately separate from the export-RT gate above: a
	// receive-only PE imports without advertising.
	if s.evpnReplay != nil {
		if b, bound := s.bindings.Get(vrfName); bound && len(importRTsForFamily(b, bgp.FamilyEVPN)) > 0 {
			s.evpnReplay()
		}
	}
	return connect.NewResponse(&v1.VrfBridgeAttachResponse{Vrf: vrfToProto(attached)}), nil
}

// VrfBridgeDetach removes the L2 facet: it deletes the kernel bridge (refusing
// while a SID other than the exporter's own lifecycle SIDs references it),
// unregisters the FDB watcher, disables EVPN auto-advertise for the bd, and
// clears the facet. Ordering keeps a failed device delete fully retryable —
// the watcher stays registered and EVPN stays enabled until the delete
// actually succeeded (the old bridge path unregistered the watcher first and
// left the bridge unwatched on failure).
func (s *VrfServer) VrfBridgeDetach(
	_ context.Context,
	req *connect.Request[v1.VrfBridgeDetachRequest],
) (*connect.Response[v1.VrfBridgeDetachResponse], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	vrfName := req.Msg.GetVrfName()
	if vrfName == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("vrf_name is required"))
	}
	v, ok := s.mgr.Get(vrfName)
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("unknown VRF %q", vrfName))
	}
	if v.Bridge == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("vrf %q carries no bridge facet", vrfName))
	}
	// The exporter's own End.DT2U/DT2M lifecycle SIDs are released by the
	// Disable below, so they must not block the detach.
	var selfSIDs []string
	if s.evpn != nil {
		selfSIDs = s.evpn.SIDsForBD(v.Bridge.BdID)
	}
	ref, err := findBridgeReference(s.sids, v.Bridge.Ifindex, selfSIDs)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to check SID references: %w", err))
	}
	if ref != "" {
		return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("bridge is referenced by SID %s", ref))
	}
	if err := s.bridges.DeleteBridge(v.Bridge.Name); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("delete bridge: %w", err))
	}
	s.fdb.UnregisterBridge(int(v.Bridge.Ifindex))
	if s.evpn != nil {
		s.evpn.Disable(v.Bridge.BdID)
	}
	s.mgr.RemoveBridge(vrfName)
	return connect.NewResponse(&v1.VrfBridgeDetachResponse{}), nil
}

// findBridgeReference returns the prefix of an End.DT2/DT2M SID whose L2 aux
// references the given bridge ifindex ("" = unreferenced), skipping the
// exclude prefixes (the EVPN exporter's own lifecycle SIDs, which the detach
// itself releases). Fail closed on an unreadable aux, same as
// findVrfReference: deleting a bridge a SID still decaps into would blackhole
// its traffic.
func findBridgeReference(sids SidLister, ifindex uint32, exclude []string) (string, error) {
	entries, err := sids.ListSidFunctions()
	if err != nil {
		return "", fmt.Errorf("list SID functions: %w", err)
	}
	for prefix, entry := range entries {
		if slices.Contains(exclude, prefix) {
			continue
		}
		switch v1.Srv6LocalAction(entry.Action) {
		case v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DT2,
			v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DT2M:
		default:
			continue
		}
		if entry.AuxIndex == 0 {
			continue
		}
		aux, err := sids.GetSidAux(uint32(entry.AuxIndex))
		if err != nil {
			return "", fmt.Errorf("read aux %d of SID %s: %w", entry.AuxIndex, prefix, err)
		}
		if _, bridgeIfindex := bpf.SidAuxL2Data(aux); bridgeIfindex == ifindex {
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
	if v.Bridge != nil {
		out.Bridge = &v1.Bridge{
			Name:    v.Bridge.Name,
			BdId:    uint32(v.Bridge.BdID),
			Members: v.Bridge.Members,
			Ifindex: v.Bridge.Ifindex,
		}
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
