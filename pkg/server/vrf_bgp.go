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
// adapter over vrfbgp.Manager. When auto-advertise is on it also drives a
// VrfExporter so a runtime bind/unbind enables/disables auto advertise.
type VrfBgpServer struct {
	mgr      *vrfbgp.Manager
	exporter VrfExporter // nil when auto-advertise is off
	// mu serializes a bind/unbind's manager + exporter mutations per call so two
	// concurrent same-VRF RPCs cannot interleave (the manager Bind/Unbind and the
	// exporter AddVRF/RemoveVRF are separate registries; the exporter's own opMu
	// cannot see the manager, so the agreement must be enforced here).
	mu sync.Mutex
}

func NewVrfBgpServer(mgr *vrfbgp.Manager, exporter VrfExporter) *VrfBgpServer {
	return &VrfBgpServer{mgr: mgr, exporter: exporter}
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
	if s.exporter != nil {
		// AddVRF removes any prior enablement before re-enabling, so capture the
		// prior binding to restore it if the re-bind fails.
		prev, existed := s.mgr.Get(binding.VRFName)
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
		// Hold s.mu across the manager Unbind + exporter RemoveVRF so an unbind
		// and a concurrent same-VRF bind cannot interleave.
		s.mu.Lock()
		err := s.mgr.Unbind(name)
		if err == nil && s.exporter != nil {
			s.exporter.RemoveVRF(name)
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
