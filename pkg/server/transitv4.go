package server

import (
	"context"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
)

// Transitv4Server implements the Transitv4ServiceHandler interface
type Transitv4Server struct {
	mapOps *bpf.MapOperations
}

// NewTransitv4Server creates a new Transitv4Server
func NewTransitv4Server(mapOps *bpf.MapOperations) *Transitv4Server {
	return &Transitv4Server{mapOps: mapOps}
}

// Transitv4Create creates Transit v4 entries
func (s *Transitv4Server) Transitv4Create(
	ctx context.Context,
	req *connect.Request[v1.Transitv4CreateRequest],
) (*connect.Response[v1.Transitv4CreateResponse], error) {
	resp := &v1.Transitv4CreateResponse{
		Created: make([]*v1.Transitv4, 0),
		Errors:  make([]*v1.OperationError, 0),
	}

	for _, transit := range req.Msg.Transitv4S {
		entry, err := s.protoToEntry(transit)
		if err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: transit.TriggerPrefix,
				Reason:        err.Error(),
			})
			continue
		}

		if err := s.mapOps.CreateTransitV4(transit.TriggerPrefix, entry); err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: transit.TriggerPrefix,
				Reason:        err.Error(),
			})
			continue
		}

		resp.Created = append(resp.Created, transit)
	}

	return connect.NewResponse(resp), nil
}

// Transitv4Delete deletes Transit v4 entries
func (s *Transitv4Server) Transitv4Delete(
	ctx context.Context,
	req *connect.Request[v1.Transitv4DeleteRequest],
) (*connect.Response[v1.Transitv4DeleteResponse], error) {
	resp := &v1.Transitv4DeleteResponse{
		DeletedTriggerPrefixes: make([]string, 0),
		Errors:                 make([]*v1.OperationError, 0),
	}

	for _, prefix := range req.Msg.TriggerPrefixes {
		if err := s.mapOps.DeleteTransitV4(prefix); err != nil {
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

// Transitv4List lists all Transit v4 entries
func (s *Transitv4Server) Transitv4List(
	ctx context.Context,
	req *connect.Request[v1.Transitv4ListRequest],
) (*connect.Response[v1.Transitv4ListResponse], error) {
	entries, err := s.mapOps.ListTransitV4()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	resp := &v1.Transitv4ListResponse{
		Transitv4S: make([]*v1.Transitv4, 0, len(entries)),
	}

	for prefix, entry := range entries {
		transit := s.entryToProto(prefix, entry)
		resp.Transitv4S = append(resp.Transitv4S, transit)
	}

	return connect.NewResponse(resp), nil
}

// Transitv4Get retrieves a specific Transit v4 entry
func (s *Transitv4Server) Transitv4Get(
	ctx context.Context,
	req *connect.Request[v1.Transitv4GetRequest],
) (*connect.Response[v1.Transitv4GetResponse], error) {
	entry, err := s.mapOps.GetTransitV4(req.Msg.TriggerPrefix)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}

	resp := &v1.Transitv4GetResponse{
		Transitv4: s.entryToProto(req.Msg.TriggerPrefix, entry),
	}

	return connect.NewResponse(resp), nil
}

// protoToEntry converts a protobuf Transitv4 to a BPF map entry
func (s *Transitv4Server) protoToEntry(transit *v1.Transitv4) (*bpf.TransitEntry, error) {
	srcAddr, err := bpf.ParseIPv6(transit.SrcAddr)
	if err != nil {
		return nil, err
	}

	dstAddr, err := bpf.ParseIPv6(transit.DstAddr)
	if err != nil {
		return nil, err
	}

	segments, numSegments, err := bpf.ParseSegments(transit.Segments)
	if err != nil {
		return nil, err
	}

	return &bpf.TransitEntry{
		Mode:        uint8(transit.Mode),
		NumSegments: numSegments,
		SrcAddr:     srcAddr,
		DstAddr:     dstAddr,
		Segments:    segments,
	}, nil
}

// entryToProto converts a BPF map entry to a protobuf Transitv4
func (s *Transitv4Server) entryToProto(prefix string, entry *bpf.TransitEntry) *v1.Transitv4 {
	return &v1.Transitv4{
		Mode:          v1.Srv6EncapMode(entry.Mode),
		TriggerPrefix: prefix,
		SrcAddr:       bpf.FormatIPv6(entry.SrcAddr),
		DstAddr:       bpf.FormatIPv6(entry.DstAddr),
		Segments:      bpf.FormatSegments(entry.Segments, entry.NumSegments),
	}
}
