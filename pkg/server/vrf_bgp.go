package server

import (
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"sync"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

// VrfExporter is the runtime auto-advertise hook a VrfBgpServer drives: a
// successful Bind enables the VRF for auto advertise, an Unbind disables it.
// *pkg/bgp/export.Exporter satisfies it; it is nil when auto-advertise is off.
type VrfExporter interface {
	AddVRF(b vrfbgp.Binding) error
	RemoveVRF(vrfName string)
}

// VrfBgpServer is the Connect RPC handler for VrfBgpService, a thin
// adapter over vrfbgp.Manager. When auto-advertise is on it also drives the
// L3VPN VrfExporter and the EVPN coordinator so a runtime bind/unbind
// enables/disables auto advertise on both families: L3VPN (DT4/DT6) and EVPN
// (RT2/RT3) for a binding with a bridge domain.
type VrfBgpServer struct {
	mgr      *vrfbgp.Manager
	exporter VrfExporter      // L3VPN auto-advertise hook; nil when off
	evpn     *EvpnCoordinator // EVPN BD lifecycle (binding axis); nil when off
	// mu serializes a bind/unbind's manager + exporter mutations per call so two
	// concurrent same-VRF RPCs cannot interleave (the manager Bind/Unbind and the
	// exporter AddVRF/RemoveVRF are separate registries; the exporter's own opMu
	// cannot see the manager, so the agreement must be enforced here).
	mu sync.Mutex
}

func NewVrfBgpServer(mgr *vrfbgp.Manager, exporter VrfExporter, evpn *EvpnCoordinator) *VrfBgpServer {
	return &VrfBgpServer{mgr: mgr, exporter: exporter, evpn: evpn}
}

// protoToBinding converts a wire VrfBgpBinding into the runtime Binding. The
// caller is responsible for validating bd_id's range first. Families on the
// wire are translated to the typed runtime form; an unknown family name or
// direction string yields an error so an InvalidArgument is returned at the
// RPC boundary rather than a silent drop.
func protoToBinding(b *v1.VrfBgpBinding) (vrfbgp.Binding, error) {
	families, err := protoFamiliesToBinding(b.GetFamilies())
	if err != nil {
		return vrfbgp.Binding{}, err
	}
	return vrfbgp.Binding{
		VRFName:        b.GetVrfName(),
		RD:             b.GetRd(),
		ImportRTs:      b.GetImportRts(),
		ExportRTs:      b.GetExportRts(),
		Redistribute:   b.GetRedistribute(),
		MaxPrefixes:    b.GetMaxPrefixes(),
		DefaultLocator: b.GetDefaultLocator(),
		BDID:           uint16(b.GetBdId()),
		Families:       families,
	}, nil
}

// bindingToProto is the inverse of protoToBinding for VrfBgpList and the
// mutation RPCs' "updated binding" response.
func bindingToProto(b vrfbgp.Binding) *v1.VrfBgpBinding {
	return &v1.VrfBgpBinding{
		VrfName:        b.VRFName,
		Rd:             b.RD,
		ImportRts:      b.ImportRTs,
		ExportRts:      b.ExportRTs,
		Redistribute:   b.Redistribute,
		MaxPrefixes:    b.MaxPrefixes,
		DefaultLocator: b.DefaultLocator,
		BdId:           uint32(b.BDID),
		Families:       bindingFamiliesToProto(b.Families),
	}
}

// protoFamiliesToBinding validates the family map and translates it to the
// runtime form. Returns nil (and no error) when the caller did not send any
// family entry so vrfbgp.Binding.Normalize takes the legacy-expansion path.
func protoFamiliesToBinding(in map[string]*v1.VrfBgpFamily) (map[bgp.Family]vrfbgp.FamilyPolicy, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make(map[bgp.Family]vrfbgp.FamilyPolicy, len(in))
	for famStr, fam := range in {
		if err := vrfbgp.ValidateFamily(famStr); err != nil {
			return nil, err
		}
		rts, err := protoRouteTargets(fam.GetRouteTargets())
		if err != nil {
			return nil, fmt.Errorf("family %q: %w", famStr, err)
		}
		out[bgp.Family(famStr)] = vrfbgp.FamilyPolicy{RouteTargets: rts}
	}
	return out, nil
}

// bindingFamiliesToProto renders the runtime families map back onto the wire.
func bindingFamiliesToProto(in map[bgp.Family]vrfbgp.FamilyPolicy) map[string]*v1.VrfBgpFamily {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]*v1.VrfBgpFamily, len(in))
	for fam, fp := range in {
		rts := make([]*v1.VrfBgpRouteTarget, 0, len(fp.RouteTargets))
		for _, rt := range fp.RouteTargets {
			rts = append(rts, &v1.VrfBgpRouteTarget{Rt: rt.RT, Direction: rt.Direction.String()})
		}
		out[string(fam)] = &v1.VrfBgpFamily{RouteTargets: rts}
	}
	return out
}

// commitBinding swaps the binding in the manager and re-drives the exporter
// and EVPN coordinator. Every mutation RPC funnels through here so the
// manager + exporter + EVPN state stays in lock-step. Caller must hold s.mu.
//
// Normalize runs before the exporter reads ExportRTs and EVPN reads
// Families: a caller that set only Families (or only the legacy lists)
// would otherwise hand the exporter a half-populated binding.
func (s *VrfBgpServer) commitBinding(updated vrfbgp.Binding) error {
	updated = updated.Normalize()
	prev, existed := s.mgr.Get(updated.VRFName)
	if s.exporter != nil {
		if err := s.exporter.AddVRF(updated); err != nil {
			reason := fmt.Errorf("auto advertise: %w", err)
			if existed {
				if rerr := s.exporter.AddVRF(prev); rerr != nil {
					// Restoring prev in the exporter failed; surface both
					// errors. The manager was never touched so prev still
					// lives there -- do NOT Unbind(updated.VRFName) because
					// that would delete prev (same key) and leave the
					// manager empty while it is the authoritative state.
					return fmt.Errorf("%w; restoring prior binding failed: %v", reason, rerr)
				}
			}
			return reason
		}
	}
	if err := s.mgr.Bind(updated); err != nil {
		if s.exporter != nil {
			if existed {
				// AddVRF(updated) already replaced prev in the exporter;
				// restore prev so the exporter agrees with the manager (which
				// still holds prev). A second failure here surfaces alongside
				// the Bind error so the operator sees the divergence.
				if rerr := s.exporter.AddVRF(prev); rerr != nil {
					return fmt.Errorf("%w; restoring prior binding in exporter failed: %v", err, rerr)
				}
			} else {
				s.exporter.RemoveVRF(updated.VRFName)
			}
		}
		return err
	}
	if s.evpn != nil {
		// Disable the prior BD when it is going away -- either because the
		// new binding moved BD, or because the caller removed the evpn
		// family explicitly (so EVPN is unwanted even with an unchanged
		// BDID). EnableForBinding then fires for the current BD when EVPN
		// is still desired AND something EVPN-relevant actually changed;
		// otherwise a per-RT mutation on a non-EVPN family (vpnv4 RT add /
		// remove on a BDID-bound binding) would re-run EnableForBridge ->
		// replayFDB -> RT2 origination for every learned MAC, an O(N)
		// BGP storm on an unrelated edit.
		_, hadEvpn := prev.Families[bgp.FamilyEVPN]
		_, hasEvpn := updated.Families[bgp.FamilyEVPN]
		evpnRemoved := hadEvpn && !hasEvpn
		if existed && prev.BDID != 0 && (prev.BDID != updated.BDID || evpnRemoved) {
			s.evpn.Disable(prev.BDID)
		}
		// hasEvpn gates EnableForBinding: a binding with bd_id set but no
		// FamilyEVPN entry (e.g. `bind --bd-id 100 --rt vpnv4:...`, the
		// operator forgot --rt evpn) would otherwise advertise RT3 with empty
		// extended-community RTs, which no peer can import. Legacy-form
		// bindings auto-expand into FamilyEVPN through legacyToFamilies, so
		// this only filters genuinely RT-less EVPN attempts.
		if updated.BDID != 0 && hasEvpn && !evpnRemoved && evpnFieldsChanged(existed, prev, updated) {
			s.evpn.EnableForBinding(updated)
		}
	}
	return nil
}

// evpnFieldsChanged reports whether any EVPN-origination field differs
// between prev and updated, so an unrelated mutation (e.g. AddRouteTarget
// on vpnv4) does not re-drive EnableForBinding and trigger an FDB replay.
// MaxPrefixes is excluded: it caps RT2 origination per-event but does not
// alter the BD's RT3 or the SIDs, so a cap-only update would only flap
// O(N MACs) for no advertisement change. A first-bind (existed=false)
// always counts as changed.
func evpnFieldsChanged(existed bool, prev, updated vrfbgp.Binding) bool {
	if !existed {
		return true
	}
	if prev.BDID != updated.BDID ||
		prev.RD != updated.RD ||
		prev.DefaultLocator != updated.DefaultLocator {
		return true
	}
	return !sameRouteTargets(prev.Families[bgp.FamilyEVPN].RouteTargets, updated.Families[bgp.FamilyEVPN].RouteTargets)
}

// sameRouteTargets compares two RT lists as sets (RT + Direction). The slice
// is operator-supplied via a proto map, whose wire order on the same logical
// set is not stable across reconcile cycles. An order-sensitive compare would
// otherwise return false on every reordered re-bind and re-drive EVPN
// (replayFDB → RT2 storm). Lists are tiny; clone and sort to canonicalize.
func sameRouteTargets(a, b []vrfbgp.RouteTarget) bool {
	if len(a) != len(b) {
		return false
	}
	ac := append([]vrfbgp.RouteTarget(nil), a...)
	bc := append([]vrfbgp.RouteTarget(nil), b...)
	less := func(x, y vrfbgp.RouteTarget) int {
		if x.RT != y.RT {
			if x.RT < y.RT {
				return -1
			}
			return 1
		}
		if x.Direction != y.Direction {
			if x.Direction < y.Direction {
				return -1
			}
			return 1
		}
		return 0
	}
	slices.SortFunc(ac, less)
	slices.SortFunc(bc, less)
	for i := range ac {
		if ac[i] != bc[i] {
			return false
		}
	}
	return true
}

func (s *VrfBgpServer) VrfBgpBind(
	_ context.Context,
	req *connect.Request[v1.VrfBgpBindRequest],
) (*connect.Response[v1.VrfBgpBindResponse], error) {
	resp := &v1.VrfBgpBindResponse{
		Bound:  make([]*v1.VrfBgpBinding, 0),
		Errors: make([]*v1.OperationError, 0),
	}
	for _, b := range req.Msg.Bindings {
		// bd_id is uint32 on the wire but a uint16 bridge domain in the data
		// plane; reject out-of-range values rather than silently truncating
		// (which would bind to a different BD than the caller asked for).
		if b.GetBdId() > math.MaxUint16 {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: b.GetVrfName(),
				Reason:        fmt.Sprintf("bd_id %d out of range (max %d)", b.GetBdId(), math.MaxUint16),
			})
			continue
		}
		if bound, opErr := s.bindOne(b); opErr != nil {
			resp.Errors = append(resp.Errors, opErr)
		} else {
			resp.Bound = append(resp.Bound, bound)
		}
	}
	return connect.NewResponse(resp), nil
}

// bindOne binds one VRF and drives the exporter, holding s.mu so manager
// and exporter mutations are atomic against a concurrent same-VRF
// bind/unbind. The response reflects the normalized stored state (legacy
// and Families both populated by vrfbgp.Binding.Normalize).
func (s *VrfBgpServer) bindOne(b *v1.VrfBgpBinding) (*v1.VrfBgpBinding, *v1.OperationError) {
	s.mu.Lock()
	defer s.mu.Unlock()
	binding, err := protoToBinding(b)
	if err != nil {
		return nil, &v1.OperationError{TriggerPrefix: b.GetVrfName(), Reason: err.Error()}
	}
	if err := s.commitBinding(binding); err != nil {
		return nil, &v1.OperationError{TriggerPrefix: b.GetVrfName(), Reason: err.Error()}
	}
	stored, _ := s.mgr.Get(binding.VRFName)
	return bindingToProto(stored), nil
}

func (s *VrfBgpServer) VrfBgpUnbind(
	_ context.Context,
	req *connect.Request[v1.VrfBgpUnbindRequest],
) (*connect.Response[v1.VrfBgpUnbindResponse], error) {
	resp := &v1.VrfBgpUnbindResponse{
		UnboundVrfNames: make([]string, 0),
		Errors:          make([]*v1.OperationError, 0),
	}
	for _, name := range req.Msg.VrfNames {
		// Hold s.mu across the manager Unbind + exporter/EVPN teardown so
		// a concurrent same-VRF bind cannot interleave; capture the prior
		// binding before Unbind so the EVPN axis can disable its BD.
		s.mu.Lock()
		prev, existed := s.mgr.Get(name)
		err := s.mgr.Unbind(name)
		if err == nil {
			if s.exporter != nil {
				s.exporter.RemoveVRF(name)
			}
			if s.evpn != nil && existed && prev.BDID != 0 {
				s.evpn.Disable(prev.BDID)
			}
		}
		s.mu.Unlock()
		if err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: name,
				Reason:        err.Error(),
			})
			continue
		}
		resp.UnboundVrfNames = append(resp.UnboundVrfNames, name)
	}
	return connect.NewResponse(resp), nil
}

func (s *VrfBgpServer) VrfBgpList(
	_ context.Context,
	_ *connect.Request[v1.VrfBgpListRequest],
) (*connect.Response[v1.VrfBgpListResponse], error) {
	bindings := s.mgr.List()
	out := make([]*v1.VrfBgpBinding, 0, len(bindings))
	for _, b := range bindings {
		out = append(out, bindingToProto(b))
	}
	return connect.NewResponse(&v1.VrfBgpListResponse{Bindings: out}), nil
}

// UpdateBinding atomically replaces the named binding with the supplied one.
// It is the recommended primitive for multi-field edits because the
// exporter / EVPN reconciler runs once after the replacement, instead of
// once per field as with the route-target-level RPCs.
func (s *VrfBgpServer) UpdateBinding(
	_ context.Context,
	req *connect.Request[v1.UpdateBindingRequest],
) (*connect.Response[v1.UpdateBindingResponse], error) {
	if req.Msg.GetExpectedVersion() != "" {
		// expected_version is reserved for the optimistic-concurrency P2
		// extension; non-empty values would silently no-op otherwise, which
		// is the kind of partial implementation that confuses operators.
		return nil, connect.NewError(connect.CodeUnimplemented, fmt.Errorf("expected_version is reserved for the P2 optimistic-concurrency feature"))
	}
	b := req.Msg.GetBinding()
	if b == nil || b.GetVrfName() == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("binding.vrf_name is required"))
	}
	if b.GetBdId() > math.MaxUint16 {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("bd_id %d out of range (max %d)", b.GetBdId(), math.MaxUint16))
	}
	binding, err := protoToBinding(b)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, existed := s.mgr.Get(binding.VRFName); !existed {
		// UpdateBinding is by name "update" and the design table reserves
		// row-creation semantics for VrfBgpBind. Reject typoed --vrf names
		// here so a typo registers as NotFound instead of a stray new binding.
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("binding %q not found (use VrfBgpBind to create)", binding.VRFName))
	}
	if err := s.commitBinding(binding); err != nil {
		// commitBinding failures are dominantly input-driven (missing rd /
		// default_locator, unknown locator) surfaced by the exporter, so
		// surface as InvalidArgument; rare infrastructure failures still
		// carry the underlying error message for the operator.
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	stored, _ := s.mgr.Get(binding.VRFName)
	return connect.NewResponse(&v1.UpdateBindingResponse{Binding: bindingToProto(stored)}), nil
}

// BatchModifyRouteTargets applies a list of add / remove operations on one
// binding atomically. The whole batch rolls back on any single op's failure
// so the binding state is unchanged unless every op succeeded. Ops are
// applied in the order received.
func (s *VrfBgpServer) BatchModifyRouteTargets(
	_ context.Context,
	req *connect.Request[v1.BatchModifyRouteTargetsRequest],
) (*connect.Response[v1.BatchModifyRouteTargetsResponse], error) {
	vrfName := req.Msg.GetVrfName()
	if vrfName == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("vrf_name is required"))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.mgr.Get(vrfName)
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("binding %q not found", vrfName))
	}
	scratch := cloneBinding(b)
	for i, op := range req.Msg.GetOps() {
		if err := applyRouteTargetOp(&scratch, op); err != nil {
			// Preserve a mutator's typed connect code so a batch call
			// returns the same gRPC code the single-call RPC would for the
			// same failure; wrap a bare error as InvalidArgument.
			var cerr *connect.Error
			if errors.As(err, &cerr) {
				return nil, connect.NewError(cerr.Code(), fmt.Errorf("op[%d]: %w", i, cerr))
			}
			return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("op[%d]: %w", i, err))
		}
	}
	if err := s.commitBinding(scratch); err != nil {
		// Same input-driven failure dominance as UpdateBinding.
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	stored, _ := s.mgr.Get(vrfName)
	return connect.NewResponse(&v1.BatchModifyRouteTargetsResponse{Binding: bindingToProto(stored)}), nil
}

// AddRouteTarget adds (or extends the direction bitmask of) one RT under one
// family of an existing binding. The operation is idempotent: re-adding the
// same {family, rt, direction} returns success without changing state.
func (s *VrfBgpServer) AddRouteTarget(
	_ context.Context,
	req *connect.Request[v1.AddRouteTargetRequest],
) (*connect.Response[v1.AddRouteTargetResponse], error) {
	updated, err := s.mutateOne(req.Msg.GetVrfName(), func(b *vrfbgp.Binding) error {
		return addRouteTarget(b, req.Msg.GetFamily(), req.Msg.GetRouteTarget())
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&v1.AddRouteTargetResponse{Binding: updated}), nil
}

// RemoveRouteTarget strips one direction bit (or, when direction is empty,
// the whole RT) from a family's RT list. A missing entry is treated as a
// no-op success so the operation is idempotent.
func (s *VrfBgpServer) RemoveRouteTarget(
	_ context.Context,
	req *connect.Request[v1.RemoveRouteTargetRequest],
) (*connect.Response[v1.RemoveRouteTargetResponse], error) {
	updated, err := s.mutateOne(req.Msg.GetVrfName(), func(b *vrfbgp.Binding) error {
		return removeRouteTarget(b, req.Msg.GetFamily(), req.Msg.GetRt(), req.Msg.GetDirection())
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&v1.RemoveRouteTargetResponse{Binding: updated}), nil
}

// ListRouteTargets returns the route-target set of one binding, optionally
// filtered by family and / or direction. Order inside each family matches
// the order entries were registered in.
func (s *VrfBgpServer) ListRouteTargets(
	_ context.Context,
	req *connect.Request[v1.ListRouteTargetsRequest],
) (*connect.Response[v1.ListRouteTargetsResponse], error) {
	vrfName := req.Msg.GetVrfName()
	if vrfName == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("vrf_name is required"))
	}
	famFilter := req.Msg.GetFamily()
	if famFilter != "" {
		if err := vrfbgp.ValidateFamily(famFilter); err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
	}
	dirFilter, err := directionFilter(req.Msg.GetDirection())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.mgr.Get(vrfName)
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("binding %q not found", vrfName))
	}
	out := &v1.ListRouteTargetsResponse{}
	for _, fam := range vrfbgp.CanonicalFamilyOrder(b.Families) {
		famStr := string(fam)
		if famFilter != "" && famStr != famFilter {
			continue
		}
		rts := make([]*v1.VrfBgpRouteTarget, 0, len(b.Families[fam].RouteTargets))
		for _, rt := range b.Families[fam].RouteTargets {
			if dirFilter != 0 && !rt.Direction.Has(dirFilter) {
				continue
			}
			rts = append(rts, &v1.VrfBgpRouteTarget{Rt: rt.RT, Direction: rt.Direction.String()})
		}
		out.Families = append(out.Families, &v1.FamilyRouteTargets{Family: famStr, RouteTargets: rts})
	}
	return connect.NewResponse(out), nil
}

// AddFamily registers a new family entry on an existing binding. It is
// strict by design: re-adding an existing family returns AlreadyExists so
// the operator picks UpdateBinding for a deliberate replace.
func (s *VrfBgpServer) AddFamily(
	_ context.Context,
	req *connect.Request[v1.AddFamilyRequest],
) (*connect.Response[v1.AddFamilyResponse], error) {
	updated, err := s.mutateOne(req.Msg.GetVrfName(), func(b *vrfbgp.Binding) error {
		return addFamily(b, req.Msg.GetFamily(), req.Msg.GetConfig())
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&v1.AddFamilyResponse{Binding: updated}), nil
}

// RemoveFamily removes one family entry from a binding. A missing family is
// NotFound (consistent with the design's "Remove* preserves the postcondition
// that the named entry is absent" rule).
func (s *VrfBgpServer) RemoveFamily(
	_ context.Context,
	req *connect.Request[v1.RemoveFamilyRequest],
) (*connect.Response[v1.RemoveFamilyResponse], error) {
	updated, err := s.mutateOne(req.Msg.GetVrfName(), func(b *vrfbgp.Binding) error {
		return removeFamily(b, req.Msg.GetFamily())
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&v1.RemoveFamilyResponse{Binding: updated}), nil
}

// mutateOne is the shared body of the per-RT and per-family mutation RPCs:
// it loads the binding under s.mu, applies the mutation on a clone, commits
// via commitBinding, and returns the stored view on the wire. A mutator
// that returns a typed *connect.Error has its code preserved; any other
// error is wrapped as InvalidArgument.
func (s *VrfBgpServer) mutateOne(vrfName string, mutate func(*vrfbgp.Binding) error) (*v1.VrfBgpBinding, error) {
	if vrfName == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("vrf_name is required"))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.mgr.Get(vrfName)
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("binding %q not found", vrfName))
	}
	scratch := cloneBinding(b)
	if err := mutate(&scratch); err != nil {
		var cerr *connect.Error
		if errors.As(err, &cerr) {
			return nil, err
		}
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if err := s.commitBinding(scratch); err != nil {
		// Same input-driven failure dominance as UpdateBinding.
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	stored, _ := s.mgr.Get(vrfName)
	return bindingToProto(stored), nil
}

// cloneBinding returns a deep copy of b suitable for mutation under s.mu so
// a failed in-flight RPC cannot leave a partially modified binding visible.
// The Families map is always non-nil after the clone -- even when the input
// had no families -- so a subsequent RemoveFamily / RemoveRouteTarget that
// empties Families does not collapse back to nil, which Normalize would
// re-expand from the legacy ImportRTs / ExportRTs and silently undo the
// operator's intent.
func cloneBinding(b vrfbgp.Binding) vrfbgp.Binding {
	out := b
	out.ImportRTs = slices.Clone(b.ImportRTs)
	out.ExportRTs = slices.Clone(b.ExportRTs)
	out.Redistribute = slices.Clone(b.Redistribute)
	out.Families = make(map[bgp.Family]vrfbgp.FamilyPolicy, len(b.Families))
	for fam, fp := range b.Families {
		out.Families[fam] = vrfbgp.FamilyPolicy{RouteTargets: slices.Clone(fp.RouteTargets)}
	}
	return out
}

// addRouteTarget implements AddRouteTarget on a binding scratch. The family
// must already exist (AddFamily is the only way to introduce one), so this
// stays idempotent on the RT but strict on family existence.
func addRouteTarget(b *vrfbgp.Binding, fam string, rt *v1.VrfBgpRouteTarget) error {
	if rt == nil {
		return fmt.Errorf("route_target is required")
	}
	if err := vrfbgp.ValidateRouteTarget(rt.GetRt()); err != nil {
		return err
	}
	if err := vrfbgp.ValidateFamily(fam); err != nil {
		return err
	}
	dir, err := vrfbgp.ParseDirection(rt.GetDirection())
	if err != nil {
		return err
	}
	famKey := bgp.Family(fam)
	fp, exists := b.Families[famKey]
	if !exists {
		return connect.NewError(connect.CodeNotFound, fmt.Errorf("family %q not declared on binding (call AddFamily first)", fam))
	}
	// Existing RT: OR the direction (idempotent on identical (rt, direction)).
	for i, existing := range fp.RouteTargets {
		if existing.RT == rt.GetRt() {
			fp.RouteTargets[i].Direction |= dir
			b.Families[famKey] = fp
			return nil
		}
	}
	fp.RouteTargets = append(fp.RouteTargets, vrfbgp.RouteTarget{RT: rt.GetRt(), Direction: dir})
	b.Families[famKey] = fp
	return nil
}

// removeRouteTarget implements RemoveRouteTarget on a binding scratch.
// Empty direction strips the entire RT; a specific direction clears only
// that bit and removes the RT when the bitmask becomes 0. A missing entry
// is idempotent success.
func removeRouteTarget(b *vrfbgp.Binding, fam, rt, direction string) error {
	if rt == "" {
		return fmt.Errorf("rt is required")
	}
	if err := vrfbgp.ValidateFamily(fam); err != nil {
		return err
	}
	dir, err := vrfbgp.ParseDirection(direction)
	if err != nil {
		return err
	}
	famKey := bgp.Family(fam)
	fp, exists := b.Families[famKey]
	if !exists {
		return nil
	}
	for i, existing := range fp.RouteTargets {
		if existing.RT != rt {
			continue
		}
		// Specific direction clears only those bits; keep the RT if any
		// bit remains. Empty direction (or no bits remaining) drops it.
		if direction != "" {
			fp.RouteTargets[i].Direction &^= dir
			if fp.RouteTargets[i].Direction != 0 {
				b.Families[famKey] = fp
				return nil
			}
		}
		fp.RouteTargets = slices.Delete(fp.RouteTargets, i, i+1)
		b.Families[famKey] = fp
		return nil
	}
	return nil
}

// addFamily implements AddFamily on a binding scratch. AlreadyExists is
// returned as a typed connect error so the wrapping path preserves the
// gRPC code on the response.
func addFamily(b *vrfbgp.Binding, fam string, cfg *v1.VrfBgpFamily) error {
	if err := vrfbgp.ValidateFamily(fam); err != nil {
		return err
	}
	famKey := bgp.Family(fam)
	if _, exists := b.Families[famKey]; exists {
		return connect.NewError(connect.CodeAlreadyExists, fmt.Errorf("family %q already declared on binding", fam))
	}
	rts, err := protoRouteTargets(cfg.GetRouteTargets())
	if err != nil {
		return err
	}
	if b.Families == nil {
		b.Families = make(map[bgp.Family]vrfbgp.FamilyPolicy)
	}
	b.Families[famKey] = vrfbgp.FamilyPolicy{RouteTargets: rts}
	return nil
}

// protoRouteTargets converts a wire RT list into the runtime form, validating
// each entry's rt and direction string. Returns an empty (non-nil) slice when
// the input is empty so the caller can always assign the result.
func protoRouteTargets(in []*v1.VrfBgpRouteTarget) ([]vrfbgp.RouteTarget, error) {
	out := make([]vrfbgp.RouteTarget, 0, len(in))
	for _, rt := range in {
		if err := vrfbgp.ValidateRouteTarget(rt.GetRt()); err != nil {
			return nil, err
		}
		dir, err := vrfbgp.ParseDirection(rt.GetDirection())
		if err != nil {
			return nil, fmt.Errorf("rt %q: %w", rt.GetRt(), err)
		}
		out = append(out, vrfbgp.RouteTarget{RT: rt.GetRt(), Direction: dir})
	}
	return out, nil
}

// removeFamily implements RemoveFamily on a binding scratch. NotFound is
// returned for a missing family so the caller can distinguish a true miss
// from a silent no-op (consistent with the error code table in the design).
func removeFamily(b *vrfbgp.Binding, fam string) error {
	if err := vrfbgp.ValidateFamily(fam); err != nil {
		return err
	}
	famKey := bgp.Family(fam)
	if _, exists := b.Families[famKey]; !exists {
		return connect.NewError(connect.CodeNotFound, fmt.Errorf("family %q not declared on binding", fam))
	}
	delete(b.Families, famKey)
	return nil
}

// applyRouteTargetOp dispatches a batch op to the per-op mutator. An
// unspecified kind is rejected so the client never silently no-ops a typo.
func applyRouteTargetOp(b *vrfbgp.Binding, op *v1.RouteTargetOp) error {
	switch op.GetKind() {
	case v1.RouteTargetOp_KIND_ADD:
		return addRouteTarget(b, op.GetFamily(), op.GetRouteTarget())
	case v1.RouteTargetOp_KIND_REMOVE:
		rt := op.GetRouteTarget()
		if rt == nil {
			return fmt.Errorf("REMOVE op requires route_target")
		}
		return removeRouteTarget(b, op.GetFamily(), rt.GetRt(), rt.GetDirection())
	default:
		return fmt.Errorf("op.kind is required (got %s)", op.GetKind())
	}
}

// directionFilter parses a direction string for ListRouteTargets. An empty
// string returns 0 ("no narrowing", show every RT). Any explicit direction
// (import / export / both) returns its bitmask so the caller's filter is
// applied verbatim. With Direction.Has's bitmask containment, an "import"
// filter naturally includes RTs declared as "both" (import bit set), and a
// "both" filter selects only RTs with both bits set -- the strict
// bidirectional view. Operators wanting "everything" pass no filter.
func directionFilter(s string) (vrfbgp.Direction, error) {
	if s == "" {
		return 0, nil
	}
	return vrfbgp.ParseDirection(s)
}
