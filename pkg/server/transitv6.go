package server

import (
	"context"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
)

// Transitv6Server implements the Transitv6ServiceHandler interface
type Transitv6Server struct {
	mapOps *bpf.MapOperations
}

// NewTransitv6Server creates a new Transitv6Server
func NewTransitv6Server(mapOps *bpf.MapOperations) *Transitv6Server {
	return &Transitv6Server{mapOps: mapOps}
}

// Transitv6Create creates Transit v6 entries
func (s *Transitv6Server) Transitv6Create(
	ctx context.Context,
	req *connect.Request[v1.Transitv6CreateRequest],
) (*connect.Response[v1.Transitv6CreateResponse], error) {
	resp := &v1.Transitv6CreateResponse{
		Created: make([]*v1.Transitv6, 0),
		Errors:  make([]*v1.OperationError, 0),
	}

	for _, transit := range req.Msg.Transitv6S {
		entry, err := s.protoToEntry(transit)
		if err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: transit.TriggerPrefix,
				Reason:        err.Error(),
			})
			continue
		}

		if err := s.mapOps.CreateTransitV6(transit.TriggerPrefix, entry); err != nil {
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

// Transitv6Delete deletes Transit v6 entries
func (s *Transitv6Server) Transitv6Delete(
	ctx context.Context,
	req *connect.Request[v1.Transitv6DeleteRequest],
) (*connect.Response[v1.Transitv6DeleteResponse], error) {
	resp := &v1.Transitv6DeleteResponse{
		DeletedTriggerPrefixes: make([]string, 0),
		Errors:                 make([]*v1.OperationError, 0),
	}

	for _, prefix := range req.Msg.TriggerPrefixes {
		if err := s.mapOps.DeleteTransitV6(prefix); err != nil {
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

// Transitv6List lists all Transit v6 entries
func (s *Transitv6Server) Transitv6List(
	ctx context.Context,
	req *connect.Request[v1.Transitv6ListRequest],
) (*connect.Response[v1.Transitv6ListResponse], error) {
	entries, err := s.mapOps.ListTransitV6()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	resp := &v1.Transitv6ListResponse{
		Transitv6S: make([]*v1.Transitv6, 0, len(entries)),
	}

	for prefix, entry := range entries {
		transit := s.entryToProto(prefix, entry)
		resp.Transitv6S = append(resp.Transitv6S, transit)
	}

	return connect.NewResponse(resp), nil
}

// Transitv6Get retrieves a specific Transit v6 entry
func (s *Transitv6Server) Transitv6Get(
	ctx context.Context,
	req *connect.Request[v1.Transitv6GetRequest],
) (*connect.Response[v1.Transitv6GetResponse], error) {
	entry, err := s.mapOps.GetTransitV6(req.Msg.TriggerPrefix)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}

	resp := &v1.Transitv6GetResponse{
		Transitv6: s.entryToProto(req.Msg.TriggerPrefix, entry),
	}

	return connect.NewResponse(resp), nil
}

// protoToEntry converts a protobuf Transitv6 to a BPF map entry
func (s *Transitv6Server) protoToEntry(transit *v1.Transitv6) (*bpf.TransitEntry, error) {
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

// entryToProto converts a BPF map entry to a protobuf Transitv6
func (s *Transitv6Server) entryToProto(prefix string, entry *bpf.TransitEntry) *v1.Transitv6 {
	return &v1.Transitv6{
		Mode:          v1.Srv6EncapMode(entry.Mode),
		TriggerPrefix: prefix,
		SrcAddr:       bpf.FormatIPv6(entry.SrcAddr),
		DstAddr:       bpf.FormatIPv6(entry.DstAddr),
		Segments:      bpf.FormatSegments(entry.Segments, entry.NumSegments),
	}
}
