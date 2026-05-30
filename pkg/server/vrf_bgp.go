package server

import (
	"context"
	"fmt"
	"math"

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
		binding := protoToBinding(b)
		if err := s.mgr.Bind(binding); err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: b.GetVrfName(),
				Reason:        err.Error(),
			})
			continue
		}
		// Enable auto advertise for the binding. On failure roll the manager
		// bind back so the binding registry and the exporter stay consistent.
		if s.exporter != nil {
			if err := s.exporter.AddVRF(binding); err != nil {
				_ = s.mgr.Unbind(binding.VRFName)
				resp.Errors = append(resp.Errors, &v1.OperationError{
					TriggerPrefix: b.GetVrfName(),
					Reason:        fmt.Sprintf("auto advertise: %v", err),
				})
				continue
			}
		}
		resp.Bound = append(resp.Bound, b)
	}
	return connect.NewResponse(resp), nil
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
		if err := s.mgr.Unbind(name); err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: name,
				Reason:        err.Error(),
			})
			continue
		}
		if s.exporter != nil {
			s.exporter.RemoveVRF(name)
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
