package server

import (
	"context"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
)

// Headendv4Server implements the Headendv4ServiceHandler interface
type Headendv4Server struct {
	mapOps *bpf.MapOperations
}

// NewHeadendv4Server creates a new Headendv4Server
func NewHeadendv4Server(mapOps *bpf.MapOperations) *Headendv4Server {
	return &Headendv4Server{mapOps: mapOps}
}

// Headendv4Create creates Headend v4 entries
func (s *Headendv4Server) Headendv4Create(
	ctx context.Context,
	req *connect.Request[v1.Headendv4CreateRequest],
) (*connect.Response[v1.Headendv4CreateResponse], error) {
	resp := &v1.Headendv4CreateResponse{
		Created: make([]*v1.Headendv4, 0),
		Errors:  make([]*v1.OperationError, 0),
	}

	for _, headend := range req.Msg.Headendv4S {
		entry, err := s.protoToEntry(headend)
		if err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: headend.TriggerPrefix,
				Reason:        err.Error(),
			})
			continue
		}

		if err := s.mapOps.CreateHeadendV4(headend.TriggerPrefix, entry); err != nil {
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

// Headendv4Delete deletes Headend v4 entries
func (s *Headendv4Server) Headendv4Delete(
	ctx context.Context,
	req *connect.Request[v1.Headendv4DeleteRequest],
) (*connect.Response[v1.Headendv4DeleteResponse], error) {
	resp := &v1.Headendv4DeleteResponse{
		DeletedTriggerPrefixes: make([]string, 0),
		Errors:                 make([]*v1.OperationError, 0),
	}

	for _, prefix := range req.Msg.TriggerPrefixes {
		if err := s.mapOps.DeleteHeadendV4(prefix); err != nil {
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

// Headendv4List lists all Headend v4 entries
func (s *Headendv4Server) Headendv4List(
	ctx context.Context,
	req *connect.Request[v1.Headendv4ListRequest],
) (*connect.Response[v1.Headendv4ListResponse], error) {
	entries, err := s.mapOps.ListHeadendV4()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	resp := &v1.Headendv4ListResponse{
		Headendv4S: make([]*v1.Headendv4, 0, len(entries)),
	}

	for prefix, entry := range entries {
		headend := s.entryToProto(prefix, entry)
		resp.Headendv4S = append(resp.Headendv4S, headend)
	}

	return connect.NewResponse(resp), nil
}

// Headendv4Get retrieves a specific Headend v4 entry
func (s *Headendv4Server) Headendv4Get(
	ctx context.Context,
	req *connect.Request[v1.Headendv4GetRequest],
) (*connect.Response[v1.Headendv4GetResponse], error) {
	entry, err := s.mapOps.GetHeadendV4(req.Msg.TriggerPrefix)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}

	resp := &v1.Headendv4GetResponse{
		Headendv4: s.entryToProto(req.Msg.TriggerPrefix, entry),
	}

	return connect.NewResponse(resp), nil
}

// protoToEntry converts a protobuf Headendv4 to a BPF map entry
func (s *Headendv4Server) protoToEntry(headend *v1.Headendv4) (*bpf.HeadendEntry, error) {
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

// entryToProto converts a BPF map entry to a protobuf Headendv4
func (s *Headendv4Server) entryToProto(prefix string, entry *bpf.HeadendEntry) *v1.Headendv4 {
	return &v1.Headendv4{
		Mode:          v1.Srv6HeadendBehavior(entry.Mode),
		TriggerPrefix: prefix,
		SrcAddr:       bpf.FormatIPv6(entry.SrcAddr),
		DstAddr:       bpf.FormatIPv6(entry.DstAddr),
		Segments:      bpf.FormatSegments(entry.Segments, entry.NumSegments),
	}
}
