package server

import (
	"context"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

// VrfBgpServer is the Connect RPC handler for VrfBgpService, a thin
// adapter over vrfbgp.Manager.
type VrfBgpServer struct {
	mgr *vrfbgp.Manager
}

func NewVrfBgpServer(mgr *vrfbgp.Manager) *VrfBgpServer {
	return &VrfBgpServer{mgr: mgr}
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
		if err := s.mgr.Bind(vrfbgp.Binding{
			VRFName:        b.GetVrfName(),
			ImportRTs:      b.GetImportRts(),
			ExportRTs:      b.GetExportRts(),
			DefaultLocator: b.GetDefaultLocator(),
			BDID:           uint16(b.GetBdId()),
		}); err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: b.GetVrfName(),
				Reason:        err.Error(),
			})
			continue
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
			ImportRts:      b.ImportRTs,
			ExportRts:      b.ExportRTs,
			DefaultLocator: b.DefaultLocator,
			BdId:           uint32(b.BDID),
		})
	}
	return connect.NewResponse(&v1.VrfBgpListResponse{Bindings: out}), nil
}
