package server

import (
	"context"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
)

// SidFunctionServer implements the SidFunctionServiceHandler interface
type SidFunctionServer struct {
	mapOps *bpf.MapOperations
}

// NewSidFunctionServer creates a new SidFunctionServer
func NewSidFunctionServer(mapOps *bpf.MapOperations) *SidFunctionServer {
	return &SidFunctionServer{mapOps: mapOps}
}

// SidFunctionCreate creates SID function entries
func (s *SidFunctionServer) SidFunctionCreate(
	ctx context.Context,
	req *connect.Request[v1.SidFunctionCreateRequest],
) (*connect.Response[v1.SidFunctionCreateResponse], error) {
	resp := &v1.SidFunctionCreateResponse{
		Created: make([]*v1.SidFunction, 0),
		Errors:  make([]*v1.OperationError, 0),
	}

	for _, sidFunc := range req.Msg.SidFunctions {
		entry, err := s.protoToEntry(sidFunc)
		if err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: sidFunc.TriggerPrefix,
				Reason:        err.Error(),
			})
			continue
		}

		if err := s.mapOps.CreateSidFunction(sidFunc.TriggerPrefix, entry); err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: sidFunc.TriggerPrefix,
				Reason:        err.Error(),
			})
			continue
		}

		resp.Created = append(resp.Created, sidFunc)
	}

	return connect.NewResponse(resp), nil
}

// SidFunctionDelete deletes SID function entries
func (s *SidFunctionServer) SidFunctionDelete(
	ctx context.Context,
	req *connect.Request[v1.SidFunctionDeleteRequest],
) (*connect.Response[v1.SidFunctionDeleteResponse], error) {
	resp := &v1.SidFunctionDeleteResponse{
		DeletedTriggerPrefixes: make([]string, 0),
		Errors:                 make([]*v1.OperationError, 0),
	}

	for _, prefix := range req.Msg.TriggerPrefixes {
		if err := s.mapOps.DeleteSidFunction(prefix); err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: prefix,
				Reason:        err.Error(),
			})
			continue
		}
		resp.DeletedTriggerPrefixes = append(resp.DeletedTriggerPrefixes, prefix)
	}

	return connect.NewResponse(resp), nil
}

// SidFunctionList lists all SID function entries
func (s *SidFunctionServer) SidFunctionList(
	ctx context.Context,
	req *connect.Request[v1.SidFunctionListRequest],
) (*connect.Response[v1.SidFunctionListResponse], error) {
	entries, err := s.mapOps.ListSidFunctions()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	resp := &v1.SidFunctionListResponse{
		SidFunctions: make([]*v1.SidFunction, 0, len(entries)),
	}

	for prefix, entry := range entries {
		sidFunc := s.entryToProto(prefix, entry)
		resp.SidFunctions = append(resp.SidFunctions, sidFunc)
	}

	return connect.NewResponse(resp), nil
}

// SidFunctionGet retrieves a specific SID function entry
func (s *SidFunctionServer) SidFunctionGet(
	ctx context.Context,
	req *connect.Request[v1.SidFunctionGetRequest],
) (*connect.Response[v1.SidFunctionGetResponse], error) {
	entry, err := s.mapOps.GetSidFunction(req.Msg.TriggerPrefix)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}

	resp := &v1.SidFunctionGetResponse{
		SidFunction: s.entryToProto(req.Msg.TriggerPrefix, entry),
	}

	return connect.NewResponse(resp), nil
}

// protoToEntry converts a protobuf SidFunction to a BPF map entry
func (s *SidFunctionServer) protoToEntry(sidFunc *v1.SidFunction) (*bpf.SidFunctionEntry, error) {
	srcAddr, err := bpf.ParseIPv6(sidFunc.SrcAddr)
	if err != nil {
		return nil, err
	}

	dstAddr, err := bpf.ParseIPv6(sidFunc.DstAddr)
	if err != nil {
		return nil, err
	}

	nexthop, err := bpf.ParseIPv6(sidFunc.Nexthop)
	if err != nil {
		return nil, err
	}

	return &bpf.SidFunctionEntry{
		Action:       uint8(sidFunc.Action),
		Flavor:       uint8(sidFunc.Flavor),
		SrcAddr:      srcAddr,
		DstAddr:      dstAddr,
		Nexthop:      nexthop,
		ArgSrcOffset: uint8(sidFunc.ArgSrcOffset),
		ArgDstOffset: uint8(sidFunc.ArgDstOffset),
	}, nil
}

// entryToProto converts a BPF map entry to a protobuf SidFunction
func (s *SidFunctionServer) entryToProto(prefix string, entry *bpf.SidFunctionEntry) *v1.SidFunction {
	return &v1.SidFunction{
		Action:        v1.Srv6LocalAction(entry.Action),
		TriggerPrefix: prefix,
		SrcAddr:       bpf.FormatIPv6(entry.SrcAddr),
		DstAddr:       bpf.FormatIPv6(entry.DstAddr),
		Nexthop:       bpf.FormatIPv6(entry.Nexthop),
		Flavor:        v1.Srv6LocalFlavor(entry.Flavor),
		ArgSrcOffset:  uint32(entry.ArgSrcOffset),
		ArgDstOffset:  uint32(entry.ArgDstOffset),
	}
}
