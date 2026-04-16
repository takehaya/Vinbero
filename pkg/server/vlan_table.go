package server

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
)

type VlanTableServer struct {
	mapOps *bpf.MapOperations
}

func NewVlanTableServer(mapOps *bpf.MapOperations) *VlanTableServer {
	return &VlanTableServer{mapOps: mapOps}
}

func (s *VlanTableServer) VlanTableCreate(
	ctx context.Context,
	req *connect.Request[v1.VlanTableCreateRequest],
) (*connect.Response[v1.VlanTableCreateResponse], error) {
	resp := &v1.VlanTableCreateResponse{
		Created: make([]*v1.VlanTableEntry, 0),
		Errors:  make([]*v1.OperationError, 0),
	}

	for _, e := range req.Msg.Entries {
		if e.VlanId > 4095 {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: fmt.Sprintf("table=%d,vlan=%d", e.TableId, e.VlanId),
				Reason:        fmt.Sprintf("vlan_id %d exceeds maximum 4095", e.VlanId),
			})
			continue
		}
		if e.TableId > 65535 {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: fmt.Sprintf("table=%d,vlan=%d", e.TableId, e.VlanId),
				Reason:        fmt.Sprintf("table_id %d exceeds maximum 65535", e.TableId),
			})
			continue
		}

		oif, err := resolveIfindex(e.InterfaceName)
		if err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: fmt.Sprintf("table=%d,vlan=%d", e.TableId, e.VlanId),
				Reason:        fmt.Sprintf("interface %q: %v", e.InterfaceName, err),
			})
			continue
		}

		if err := s.mapOps.CreateDx2vVlan(uint16(e.TableId), uint16(e.VlanId), oif); err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: fmt.Sprintf("table=%d,vlan=%d", e.TableId, e.VlanId),
				Reason:        err.Error(),
			})
			continue
		}

		resp.Created = append(resp.Created, e)
	}

	return connect.NewResponse(resp), nil
}

func (s *VlanTableServer) VlanTableDelete(
	ctx context.Context,
	req *connect.Request[v1.VlanTableDeleteRequest],
) (*connect.Response[v1.VlanTableDeleteResponse], error) {
	resp := &v1.VlanTableDeleteResponse{
		Deleted: make([]*v1.VlanTableEntry, 0),
		Errors:  make([]*v1.OperationError, 0),
	}

	for _, e := range req.Msg.Entries {
		if e.VlanId > 4095 || e.TableId > 65535 {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: fmt.Sprintf("table=%d,vlan=%d", e.TableId, e.VlanId),
				Reason:        "table_id must be <= 65535 and vlan_id must be <= 4095",
			})
			continue
		}
		if err := s.mapOps.DeleteDx2vVlan(uint16(e.TableId), uint16(e.VlanId)); err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: fmt.Sprintf("table=%d,vlan=%d", e.TableId, e.VlanId),
				Reason:        err.Error(),
			})
			continue
		}

		resp.Deleted = append(resp.Deleted, e)
	}

	return connect.NewResponse(resp), nil
}

func (s *VlanTableServer) VlanTableList(
	ctx context.Context,
	req *connect.Request[v1.VlanTableListRequest],
) (*connect.Response[v1.VlanTableListResponse], error) {
	entries, err := s.mapOps.ListDx2vVlan()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	resp := &v1.VlanTableListResponse{
		Entries: make([]*v1.VlanTableEntry, 0, len(entries)),
	}

	for key, entry := range entries {
		if req.Msg.TableId != 0 && uint32(key.TableId) != req.Msg.TableId {
			continue
		}
		resp.Entries = append(resp.Entries, &v1.VlanTableEntry{
			TableId:       uint32(key.TableId),
			VlanId:        uint32(key.VlanId),
			InterfaceName: ifindexToName(entry.Oif),
		})
	}

	return connect.NewResponse(resp), nil
}
