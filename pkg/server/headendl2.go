package server

import (
	"context"
	"fmt"
	"net"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
)

// HeadendL2Server implements the HeadendL2ServiceHandler interface
type HeadendL2Server struct {
	mapOps *bpf.MapOperations
}

// NewHeadendL2Server creates a new HeadendL2Server
func NewHeadendL2Server(mapOps *bpf.MapOperations) *HeadendL2Server {
	return &HeadendL2Server{mapOps: mapOps}
}

func resolveIfindex(name string) (uint32, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0, fmt.Errorf("interface %q not found: %w", name, err)
	}
	return uint32(iface.Index), nil
}

// HeadendL2Create creates Headend L2 entries
func (s *HeadendL2Server) HeadendL2Create(
	ctx context.Context,
	req *connect.Request[v1.HeadendL2CreateRequest],
) (*connect.Response[v1.HeadendL2CreateResponse], error) {
	resp := &v1.HeadendL2CreateResponse{
		Created: make([]*v1.HeadendL2, 0),
		Errors:  make([]*v1.OperationError, 0),
	}

	for _, headend := range req.Msg.HeadendL2S {
		ifindex, err := resolveIfindex(headend.InterfaceName)
		if err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: fmt.Sprintf("%s:vlan_%d", headend.InterfaceName, headend.VlanId),
				Reason:        err.Error(),
			})
			continue
		}

		entry, err := s.protoToEntry(headend)
		if err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: fmt.Sprintf("%s:vlan_%d", headend.InterfaceName, headend.VlanId),
				Reason:        err.Error(),
			})
			continue
		}

		if err := s.mapOps.CreateHeadendL2(ifindex, uint16(headend.VlanId), entry); err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: fmt.Sprintf("%s:vlan_%d", headend.InterfaceName, headend.VlanId),
				Reason:        err.Error(),
			})
			continue
		}

		resp.Created = append(resp.Created, headend)
	}

	return connect.NewResponse(resp), nil
}

// HeadendL2Delete deletes Headend L2 entries
func (s *HeadendL2Server) HeadendL2Delete(
	ctx context.Context,
	req *connect.Request[v1.HeadendL2DeleteRequest],
) (*connect.Response[v1.HeadendL2DeleteResponse], error) {
	resp := &v1.HeadendL2DeleteResponse{
		Deleted: make([]*v1.HeadendL2DeleteTarget, 0),
		Errors:  make([]*v1.OperationError, 0),
	}

	for _, target := range req.Msg.Targets {
		ifindex, err := resolveIfindex(target.InterfaceName)
		if err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: fmt.Sprintf("%s:vlan_%d", target.InterfaceName, target.VlanId),
				Reason:        err.Error(),
			})
			continue
		}

		if err := s.mapOps.DeleteHeadendL2(ifindex, uint16(target.VlanId)); err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: fmt.Sprintf("%s:vlan_%d", target.InterfaceName, target.VlanId),
				Reason:        err.Error(),
			})
			continue
		}

		resp.Deleted = append(resp.Deleted, target)
	}

	return connect.NewResponse(resp), nil
}

// HeadendL2List lists all Headend L2 entries
func (s *HeadendL2Server) HeadendL2List(
	ctx context.Context,
	req *connect.Request[v1.HeadendL2ListRequest],
) (*connect.Response[v1.HeadendL2ListResponse], error) {
	entries, err := s.mapOps.ListHeadendL2()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	resp := &v1.HeadendL2ListResponse{
		HeadendL2S: make([]*v1.HeadendL2, 0, len(entries)),
	}

	for key, entry := range entries {
		headend := s.entryToProto(key, entry)
		resp.HeadendL2S = append(resp.HeadendL2S, headend)
	}

	return connect.NewResponse(resp), nil
}

// HeadendL2Get retrieves a specific Headend L2 entry
func (s *HeadendL2Server) HeadendL2Get(
	ctx context.Context,
	req *connect.Request[v1.HeadendL2GetRequest],
) (*connect.Response[v1.HeadendL2GetResponse], error) {
	ifindex, err := resolveIfindex(req.Msg.InterfaceName)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	entry, err := s.mapOps.GetHeadendL2(ifindex, uint16(req.Msg.VlanId))
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}

	key := bpf.HeadendL2Key{Ifindex: ifindex, VlanId: uint16(req.Msg.VlanId)}
	resp := &v1.HeadendL2GetResponse{
		HeadendL2: s.entryToProto(key, entry),
	}

	return connect.NewResponse(resp), nil
}

// protoToEntry converts a protobuf HeadendL2 to a BPF map entry
func (s *HeadendL2Server) protoToEntry(headend *v1.HeadendL2) (*bpf.HeadendEntry, error) {
	srcAddr, err := bpf.ParseIPv6(headend.SrcAddr)
	if err != nil {
		return nil, err
	}

	segments, numSegments, err := bpf.ParseSegments(headend.Segments)
	if err != nil {
		return nil, err
	}

	return &bpf.HeadendEntry{
		Mode:        uint8(v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2),
		NumSegments: numSegments,
		SrcAddr:     srcAddr,
		Segments:    segments,
		BdId:        uint16(headend.BdId),
	}, nil
}

// entryToProto converts a BPF map entry to a protobuf HeadendL2
func (s *HeadendL2Server) entryToProto(key bpf.HeadendL2Key, entry *bpf.HeadendEntry) *v1.HeadendL2 {
	// Reverse-resolve ifindex to interface name (best-effort)
	ifaceName := fmt.Sprintf("ifindex:%d", key.Ifindex)
	if iface, err := net.InterfaceByIndex(int(key.Ifindex)); err == nil {
		ifaceName = iface.Name
	}

	return &v1.HeadendL2{
		VlanId:        uint32(key.VlanId),
		SrcAddr:       bpf.FormatIPv6(entry.SrcAddr),
		Segments:      bpf.FormatSegments(entry.Segments, entry.NumSegments),
		BdId:          uint32(entry.BdId),
		InterfaceName: ifaceName,
	}
}
