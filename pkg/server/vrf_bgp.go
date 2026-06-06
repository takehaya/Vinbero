package server

import (
	"context"
	"fmt"
	"math"
	"sync"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
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
// caller is responsible for validating bd_id's range first.
func protoToBinding(b *v1.VrfBgpBinding) vrfbgp.Binding {
	return vrfbgp.Binding{
		VRFName:        b.GetVrfName(),
		RD:             b.GetRd(),
		ImportRTs:      b.GetImportRts(),
		ExportRTs:      b.GetExportRts(),
		Redistribute:   b.GetRedistribute(),
		MaxPrefixes:    b.GetMaxPrefixes(),
		DefaultLocator: b.GetDefaultLocator(),
		BDID:           uint16(b.GetBdId()),
	}
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

// bindOne binds one VRF and drives the exporter, holding s.mu so the manager and
// exporter mutations are atomic against a concurrent same-VRF bind/unbind. It
// drives the exporter FIRST and commits the manager binding only if the exporter
// accepts it, so the manager always reflects what the exporter is honoring. On a
// failed re-bind it restores the prior binding in the exporter (the manager still
// holds it); a failed brand-new bind leaves the VRF unbound. It returns either
// the bound binding or a per-item error, never both.
func (s *VrfBgpServer) bindOne(b *v1.VrfBgpBinding) (*v1.VrfBgpBinding, *v1.OperationError) {
	s.mu.Lock()
	defer s.mu.Unlock()
	binding := protoToBinding(b)
	// Capture the prior binding once: the L3VPN restore path needs it to undo a
	// failed re-bind, and the EVPN axis needs it to disable a bridge domain a
	// re-bind moved off of.
	prev, existed := s.mgr.Get(binding.VRFName)
	if s.exporter != nil {
		// AddVRF removes any prior enablement before re-enabling.
		if err := s.exporter.AddVRF(binding); err != nil {
			reason := fmt.Sprintf("auto advertise: %v", err)
			if existed {
				// Restore the prior enablement AddVRF tore down. The manager
				// still holds prev (we have not rebound it), so a successful
				// restore needs no manager write; only if the restore also fails
				// do we drop prev from the manager so both registries agree.
				if rerr := s.exporter.AddVRF(prev); rerr != nil {
					_ = s.mgr.Unbind(binding.VRFName)
					reason = fmt.Sprintf("auto advertise: %v; restoring prior binding failed: %v", err, rerr)
				}
			}
			return nil, &v1.OperationError{TriggerPrefix: b.GetVrfName(), Reason: reason}
		}
	}
	// The exporter accepted the binding (or auto-advertise is off): commit it to
	// the manager. On the rare Bind failure, undo the exporter enablement so the
	// two registries do not diverge.
	if err := s.mgr.Bind(binding); err != nil {
		if s.exporter != nil {
			s.exporter.RemoveVRF(binding.VRFName)
		}
		return nil, &v1.OperationError{TriggerPrefix: b.GetVrfName(), Reason: err.Error()}
	}
	// EVPN binding axis: enable auto-advertise for the committed binding's bridge
	// domain if its bridge is already up (a no-op otherwise; BridgeCreate enables
	// it when the bridge arrives). A re-bind that moved the VRF to a different BD
	// (or dropped it) disables the old BD first so it stops advertising.
	if s.evpn != nil {
		if existed && prev.BDID != 0 && prev.BDID != binding.BDID {
			s.evpn.Disable(prev.BDID)
		}
		s.evpn.EnableForBinding(binding)
	}
	return b, nil
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
		// Hold s.mu across the manager Unbind + exporter/EVPN teardown so an unbind
		// and a concurrent same-VRF bind cannot interleave. Capture the binding
		// before Unbind so the EVPN axis knows which bridge domain to disable.
		s.mu.Lock()
		prev, existed := s.mgr.Get(name)
		err := s.mgr.Unbind(name)
		if err == nil {
			if s.exporter != nil {
				s.exporter.RemoveVRF(name)
			}
			// EVPN: stop advertising RT2/RT3 for the unbound binding's bridge domain.
			// Without this the exporter would keep originating under the removed
			// RD/RT even though the binding is gone (the bridge device may still be
			// up; a later re-bind re-enables it via the binding axis).
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
		out = append(out, &v1.VrfBgpBinding{
			VrfName:        b.VRFName,
			Rd:             b.RD,
			ImportRts:      b.ImportRTs,
			ExportRts:      b.ExportRTs,
			Redistribute:   b.Redistribute,
			MaxPrefixes:    b.MaxPrefixes,
			DefaultLocator: b.DefaultLocator,
			BdId:           uint32(b.BDID),
		})
	}
	return connect.NewResponse(&v1.VrfBgpListResponse{Bindings: out}), nil
}

// The handlers below are P0 step 1 stubs for the new families /
// route-target / batch / update RPCs added to VrfBgpService in
// docs/plan/rt-rd-unified-design.md. They return Unimplemented until
// P0 step 7 wires them into the manager. Keeping the *VrfBgpServer
// interface satisfied here lets the proto + protobuf-gen commit land
// without the rest of the P0 stack.

func (s *VrfBgpServer) UpdateBinding(
	_ context.Context,
	_ *connect.Request[v1.UpdateBindingRequest],
) (*connect.Response[v1.UpdateBindingResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, fmt.Errorf("UpdateBinding: not yet wired in P0 step 1"))
}

func (s *VrfBgpServer) BatchModifyRouteTargets(
	_ context.Context,
	_ *connect.Request[v1.BatchModifyRouteTargetsRequest],
) (*connect.Response[v1.BatchModifyRouteTargetsResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, fmt.Errorf("BatchModifyRouteTargets: not yet wired in P0 step 1"))
}

func (s *VrfBgpServer) AddRouteTarget(
	_ context.Context,
	_ *connect.Request[v1.AddRouteTargetRequest],
) (*connect.Response[v1.AddRouteTargetResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, fmt.Errorf("AddRouteTarget: not yet wired in P0 step 1"))
}

func (s *VrfBgpServer) RemoveRouteTarget(
	_ context.Context,
	_ *connect.Request[v1.RemoveRouteTargetRequest],
) (*connect.Response[v1.RemoveRouteTargetResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, fmt.Errorf("RemoveRouteTarget: not yet wired in P0 step 1"))
}

func (s *VrfBgpServer) ListRouteTargets(
	_ context.Context,
	_ *connect.Request[v1.ListRouteTargetsRequest],
) (*connect.Response[v1.ListRouteTargetsResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, fmt.Errorf("ListRouteTargets: not yet wired in P0 step 1"))
}

func (s *VrfBgpServer) AddFamily(
	_ context.Context,
	_ *connect.Request[v1.AddFamilyRequest],
) (*connect.Response[v1.AddFamilyResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, fmt.Errorf("AddFamily: not yet wired in P0 step 1"))
}

func (s *VrfBgpServer) RemoveFamily(
	_ context.Context,
	_ *connect.Request[v1.RemoveFamilyRequest],
) (*connect.Response[v1.RemoveFamilyResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, fmt.Errorf("RemoveFamily: not yet wired in P0 step 1"))
}
