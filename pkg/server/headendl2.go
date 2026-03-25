package server

import (
	"context"
	"fmt"

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
		entry, err := s.protoToEntry(headend)
		if err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: fmt.Sprintf("vlan_id:%d", headend.VlanId),
				Reason:        err.Error(),
			})
			continue
		}

		vlanID := uint16(headend.VlanId)
		if err := s.mapOps.CreateHeadendL2(vlanID, entry); err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: fmt.Sprintf("vlan_id:%d", headend.VlanId),
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
		DeletedVlanIds: make([]uint32, 0),
		Errors:         make([]*v1.OperationError, 0),
	}

	for _, vlanID := range req.Msg.VlanIds {
		if err := s.mapOps.DeleteHeadendL2(uint16(vlanID)); err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: fmt.Sprintf("vlan_id:%d", vlanID),
				Reason:        err.Error(),
			})
			continue
		}

		resp.DeletedVlanIds = append(resp.DeletedVlanIds, vlanID)
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

	for vlanID, entry := range entries {
		headend := s.entryToProto(vlanID, entry)
		resp.HeadendL2S = append(resp.HeadendL2S, headend)
	}

	return connect.NewResponse(resp), nil
}

// HeadendL2Get retrieves a specific Headend L2 entry
func (s *HeadendL2Server) HeadendL2Get(
	ctx context.Context,
	req *connect.Request[v1.HeadendL2GetRequest],
) (*connect.Response[v1.HeadendL2GetResponse], error) {
	entry, err := s.mapOps.GetHeadendL2(uint16(req.Msg.VlanId))
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}

	resp := &v1.HeadendL2GetResponse{
		HeadendL2: s.entryToProto(uint16(req.Msg.VlanId), entry),
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
	}, nil
}

// entryToProto converts a BPF map entry to a protobuf HeadendL2
func (s *HeadendL2Server) entryToProto(vlanID uint16, entry *bpf.HeadendEntry) *v1.HeadendL2 {
	return &v1.HeadendL2{
		VlanId:   uint32(vlanID),
		SrcAddr:  bpf.FormatIPv6(entry.SrcAddr),
		Segments: bpf.FormatSegments(entry.Segments, entry.NumSegments),
	}
}
