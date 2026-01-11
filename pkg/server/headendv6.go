package server

import (
	"context"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
)

// Headendv6Server implements the Headendv6ServiceHandler interface
type Headendv6Server struct {
	mapOps *bpf.MapOperations
}

// NewHeadendv6Server creates a new Headendv6Server
func NewHeadendv6Server(mapOps *bpf.MapOperations) *Headendv6Server {
	return &Headendv6Server{mapOps: mapOps}
}

// Headendv6Create creates Headend v6 entries
func (s *Headendv6Server) Headendv6Create(
	ctx context.Context,
	req *connect.Request[v1.Headendv6CreateRequest],
) (*connect.Response[v1.Headendv6CreateResponse], error) {
	resp := &v1.Headendv6CreateResponse{
		Created: make([]*v1.Headendv6, 0),
		Errors:  make([]*v1.OperationError, 0),
	}

	for _, headend := range req.Msg.Headendv6S {
		entry, err := s.protoToEntry(headend)
		if err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: headend.TriggerPrefix,
				Reason:        err.Error(),
			})
			continue
		}

		if err := s.mapOps.CreateHeadendV6(headend.TriggerPrefix, entry); err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: headend.TriggerPrefix,
				Reason:        err.Error(),
			})
			continue
		}

		resp.Created = append(resp.Created, headend)
	}

	return connect.NewResponse(resp), nil
}

// Headendv6Delete deletes Headend v6 entries
func (s *Headendv6Server) Headendv6Delete(
	ctx context.Context,
	req *connect.Request[v1.Headendv6DeleteRequest],
) (*connect.Response[v1.Headendv6DeleteResponse], error) {
	resp := &v1.Headendv6DeleteResponse{
		DeletedTriggerPrefixes: make([]string, 0),
		Errors:                 make([]*v1.OperationError, 0),
	}

	for _, prefix := range req.Msg.TriggerPrefixes {
		if err := s.mapOps.DeleteHeadendV6(prefix); err != nil {
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

// Headendv6List lists all Headend v6 entries
func (s *Headendv6Server) Headendv6List(
	ctx context.Context,
	req *connect.Request[v1.Headendv6ListRequest],
) (*connect.Response[v1.Headendv6ListResponse], error) {
	entries, err := s.mapOps.ListHeadendV6()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	resp := &v1.Headendv6ListResponse{
		Headendv6S: make([]*v1.Headendv6, 0, len(entries)),
	}

	for prefix, entry := range entries {
		headend := s.entryToProto(prefix, entry)
		resp.Headendv6S = append(resp.Headendv6S, headend)
	}

	return connect.NewResponse(resp), nil
}

// Headendv6Get retrieves a specific Headend v6 entry
func (s *Headendv6Server) Headendv6Get(
	ctx context.Context,
	req *connect.Request[v1.Headendv6GetRequest],
) (*connect.Response[v1.Headendv6GetResponse], error) {
	entry, err := s.mapOps.GetHeadendV6(req.Msg.TriggerPrefix)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}

	resp := &v1.Headendv6GetResponse{
		Headendv6: s.entryToProto(req.Msg.TriggerPrefix, entry),
	}

	return connect.NewResponse(resp), nil
}

// protoToEntry converts a protobuf Headendv6 to a BPF map entry
func (s *Headendv6Server) protoToEntry(headend *v1.Headendv6) (*bpf.HeadendEntry, error) {
	srcAddr, err := bpf.ParseIPv6(headend.SrcAddr)
	if err != nil {
		return nil, err
	}

	dstAddr, err := bpf.ParseIPv6(headend.DstAddr)
	if err != nil {
		return nil, err
	}

	segments, numSegments, err := bpf.ParseSegments(headend.Segments)
	if err != nil {
		return nil, err
	}

	return &bpf.HeadendEntry{
		Mode:        uint8(headend.Mode),
		NumSegments: numSegments,
		SrcAddr:     srcAddr,
		DstAddr:     dstAddr,
		Segments:    segments,
	}, nil
}

// entryToProto converts a BPF map entry to a protobuf Headendv6
func (s *Headendv6Server) entryToProto(prefix string, entry *bpf.HeadendEntry) *v1.Headendv6 {
	return &v1.Headendv6{
		Mode:          v1.Srv6HeadendBehavior(entry.Mode),
		TriggerPrefix: prefix,
		SrcAddr:       bpf.FormatIPv6(entry.SrcAddr),
		DstAddr:       bpf.FormatIPv6(entry.DstAddr),
		Segments:      bpf.FormatSegments(entry.Segments, entry.NumSegments),
	}
}
