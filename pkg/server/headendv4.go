package server

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
	"google.golang.org/protobuf/proto"
)

// Headendv4Server implements the Headendv4ServiceHandler interface
type Headendv4Server struct {
	mapOps *bpf.MapOperations
	vrfs   HeadendVRFs
}

// NewHeadendv4Server creates a new Headendv4Server. vrfs resolves the
// vrf_name of a request; nil accepts the global VRF only.
func NewHeadendv4Server(mapOps *bpf.MapOperations, vrfs HeadendVRFs) *Headendv4Server {
	return &Headendv4Server{mapOps: mapOps, vrfs: vrfs}
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

		created, err := s.create(headend, entry)
		if err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: headend.TriggerPrefix,
				Reason:        err.Error(),
			})
			continue
		}

		resp.Created = append(resp.Created, created)
	}

	return connect.NewResponse(resp), nil
}

// create writes one entry in the VRF it names, holding the VRF against
// deletion until the entry is in place. The entry returned carries the
// VRF's id; a request without vrf_name comes back as it was sent.
func (s *Headendv4Server) create(headend *v1.Headendv4, entry *bpf.HeadendEntry) (*v1.Headendv4, error) {
	vrfID, release, err := resolveHeadendVRF(s.vrfs, headend.VrfName, true)
	if err != nil {
		return nil, err
	}
	defer release()
	if err := s.mapOps.CreateHeadendV4In(vrfID, headend.TriggerPrefix, entry, bpf.OwnerRPC); err != nil {
		return nil, err
	}
	if headend.VrfName == "" {
		return headend, nil
	}
	out := proto.Clone(headend).(*v1.Headendv4)
	out.VrfName = headendVRFName(s.vrfs, vrfID)
	out.VrfId = vrfID
	return out, nil
}

// Headendv4Delete deletes Headend v4 entries of one VRF
func (s *Headendv4Server) Headendv4Delete(
	ctx context.Context,
	req *connect.Request[v1.Headendv4DeleteRequest],
) (*connect.Response[v1.Headendv4DeleteResponse], error) {
	vrfID, _, err := resolveHeadendVRF(s.vrfs, req.Msg.VrfName, false)
	if err != nil {
		return nil, headendVRFError(err)
	}
	resp := &v1.Headendv4DeleteResponse{
		DeletedTriggerPrefixes: make([]string, 0),
		Errors:                 make([]*v1.OperationError, 0),
	}

	for _, prefix := range req.Msg.TriggerPrefixes {
		if err := s.mapOps.DeleteHeadendV4In(vrfID, prefix, bpf.OwnerRPC); err != nil {
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

// Headendv4Flush removes the headend v4 entries the RPC wrote: those of
// every VRF, or of the VRF the request names.
func (s *Headendv4Server) Headendv4Flush(
	ctx context.Context,
	req *connect.Request[v1.Headendv4FlushRequest],
) (*connect.Response[v1.Headendv4FlushResponse], error) {
	var (
		count uint32
		err   error
	)
	if req.Msg.VrfName == "" {
		count, err = s.mapOps.FlushHeadendV4(bpf.OwnerRPC)
	} else {
		vrfID, _, rerr := resolveHeadendVRF(s.vrfs, req.Msg.VrfName, false)
		if rerr != nil {
			return nil, headendVRFError(rerr)
		}
		count, err = s.mapOps.FlushHeadendV4In(vrfID, bpf.OwnerRPC)
	}
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&v1.Headendv4FlushResponse{DeletedCount: count}), nil
}

// Headendv4List lists the Headend v4 entries of every VRF, or of the VRF
// the request names. Each carries its VRF.
func (s *Headendv4Server) Headendv4List(
	ctx context.Context,
	req *connect.Request[v1.Headendv4ListRequest],
) (*connect.Response[v1.Headendv4ListResponse], error) {
	var only *uint32
	if req.Msg.VrfName != "" {
		vrfID, _, err := resolveHeadendVRF(s.vrfs, req.Msg.VrfName, false)
		if err != nil {
			return nil, headendVRFError(err)
		}
		only = &vrfID
	}
	entries, err := s.mapOps.ListHeadendV4IDs()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	resp := &v1.Headendv4ListResponse{
		Headendv4S: make([]*v1.Headendv4, 0, len(entries)),
	}

	for id, entry := range entries {
		if only != nil && id.VRF != *only {
			continue
		}
		headend := s.entryToProto(id, entry)
		resp.Headendv4S = append(resp.Headendv4S, headend)
	}

	return connect.NewResponse(resp), nil
}

// Headendv4Get retrieves a specific Headend v4 entry
func (s *Headendv4Server) Headendv4Get(
	ctx context.Context,
	req *connect.Request[v1.Headendv4GetRequest],
) (*connect.Response[v1.Headendv4GetResponse], error) {
	vrfID, _, err := resolveHeadendVRF(s.vrfs, req.Msg.VrfName, false)
	if err != nil {
		return nil, headendVRFError(err)
	}
	entry, err := s.mapOps.GetHeadendV4In(vrfID, req.Msg.TriggerPrefix)
	if err != nil {
		if errors.Is(err, bpf.ErrInvalidHeadendPrefix) {
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
		return nil, connect.NewError(connect.CodeNotFound, err)
	}

	resp := &v1.Headendv4GetResponse{
		Headendv4: s.entryToProto(bpf.HeadendID{VRF: vrfID, Prefix: req.Msg.TriggerPrefix}, entry),
	}

	return connect.NewResponse(resp), nil
}

// protoToEntry converts a protobuf Headendv4 to a BPF map entry
func (s *Headendv4Server) protoToEntry(headend *v1.Headendv4) (*bpf.HeadendEntry, error) {
	if headend.VrfId != 0 {
		return nil, errVRFIDServerAssigned
	}
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

	if headend.ArgsOffset > 15 {
		return nil, fmt.Errorf("args_offset must be 0-15, got %d", headend.ArgsOffset)
	}

	return &bpf.HeadendEntry{
		Mode:        uint8(headend.Mode),
		NumSegments: numSegments,
		SrcAddr:     srcAddr,
		DstAddr:     dstAddr,
		Segments:    segments,
		ArgsOffset:  uint8(headend.ArgsOffset),
	}, nil
}

// entryToProto converts a BPF map entry to a protobuf Headendv4
func (s *Headendv4Server) entryToProto(id bpf.HeadendID, entry *bpf.HeadendEntry) *v1.Headendv4 {
	return &v1.Headendv4{
		VrfName:       headendVRFName(s.vrfs, id.VRF),
		VrfId:         id.VRF,
		Mode:          v1.Srv6HeadendBehavior(entry.Mode),
		TriggerPrefix: id.Prefix,
		SrcAddr:       bpf.FormatIPv6(entry.SrcAddr),
		DstAddr:       bpf.FormatIPv6(entry.DstAddr),
		Segments:      bpf.FormatSegments(entry.Segments, entry.NumSegments),
		ArgsOffset:    uint32(entry.ArgsOffset),
	}
}
