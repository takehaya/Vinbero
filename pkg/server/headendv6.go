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

// Headendv6Server implements the Headendv6ServiceHandler interface
type Headendv6Server struct {
	mapOps *bpf.MapOperations
	vrfs   HeadendVRFs
}

// NewHeadendv6Server creates a new Headendv6Server. vrfs resolves the
// vrf_name of a request; nil accepts the global VRF only.
func NewHeadendv6Server(mapOps *bpf.MapOperations, vrfs HeadendVRFs) *Headendv6Server {
	return &Headendv6Server{mapOps: mapOps, vrfs: vrfs}
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
func (s *Headendv6Server) create(headend *v1.Headendv6, entry *bpf.HeadendEntry) (*v1.Headendv6, error) {
	vrfID, release, err := resolveHeadendVRF(s.vrfs, headend.VrfName, true)
	if err != nil {
		return nil, err
	}
	defer release()
	if err := s.mapOps.CreateHeadendV6In(vrfID, headend.TriggerPrefix, entry, bpf.OwnerRPC); err != nil {
		return nil, err
	}
	if headend.VrfName == "" {
		return headend, nil
	}
	out := proto.Clone(headend).(*v1.Headendv6)
	out.VrfName = headendVRFName(s.vrfs, vrfID)
	out.VrfId = vrfID
	return out, nil
}

// Headendv6Delete deletes Headend v6 entries of one VRF
func (s *Headendv6Server) Headendv6Delete(
	ctx context.Context,
	req *connect.Request[v1.Headendv6DeleteRequest],
) (*connect.Response[v1.Headendv6DeleteResponse], error) {
	vrfID, _, err := resolveHeadendVRF(s.vrfs, req.Msg.VrfName, false)
	if err != nil {
		return nil, headendVRFError(err)
	}
	resp := &v1.Headendv6DeleteResponse{
		DeletedTriggerPrefixes: make([]string, 0),
		Errors:                 make([]*v1.OperationError, 0),
	}

	for _, prefix := range req.Msg.TriggerPrefixes {
		if err := s.mapOps.DeleteHeadendV6In(vrfID, prefix, bpf.OwnerRPC); err != nil {
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

// Headendv6Flush removes the headend v6 entries the RPC wrote: those of
// every VRF, or of the VRF the request names.
func (s *Headendv6Server) Headendv6Flush(
	ctx context.Context,
	req *connect.Request[v1.Headendv6FlushRequest],
) (*connect.Response[v1.Headendv6FlushResponse], error) {
	var (
		count uint32
		err   error
	)
	if req.Msg.VrfName == "" {
		count, err = s.mapOps.FlushHeadendV6(bpf.OwnerRPC)
	} else {
		vrfID, _, rerr := resolveHeadendVRF(s.vrfs, req.Msg.VrfName, false)
		if rerr != nil {
			return nil, headendVRFError(rerr)
		}
		count, err = s.mapOps.FlushHeadendV6In(vrfID, bpf.OwnerRPC)
	}
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&v1.Headendv6FlushResponse{DeletedCount: count}), nil
}

// Headendv6List lists the Headend v6 entries of every VRF, or of the VRF
// the request names. Each carries its VRF.
func (s *Headendv6Server) Headendv6List(
	ctx context.Context,
	req *connect.Request[v1.Headendv6ListRequest],
) (*connect.Response[v1.Headendv6ListResponse], error) {
	var only *uint32
	if req.Msg.VrfName != "" {
		vrfID, _, err := resolveHeadendVRF(s.vrfs, req.Msg.VrfName, false)
		if err != nil {
			return nil, headendVRFError(err)
		}
		only = &vrfID
	}
	entries, err := s.mapOps.ListHeadendV6IDs()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	resp := &v1.Headendv6ListResponse{
		Headendv6S: make([]*v1.Headendv6, 0, len(entries)),
	}

	for id, entry := range entries {
		if only != nil && id.VRF != *only {
			continue
		}
		headend := s.entryToProto(id, entry)
		resp.Headendv6S = append(resp.Headendv6S, headend)
	}

	return connect.NewResponse(resp), nil
}

// Headendv6Get retrieves a specific Headend v6 entry
func (s *Headendv6Server) Headendv6Get(
	ctx context.Context,
	req *connect.Request[v1.Headendv6GetRequest],
) (*connect.Response[v1.Headendv6GetResponse], error) {
	vrfID, _, err := resolveHeadendVRF(s.vrfs, req.Msg.VrfName, false)
	if err != nil {
		return nil, headendVRFError(err)
	}
	entry, err := s.mapOps.GetHeadendV6In(vrfID, req.Msg.TriggerPrefix)
	if err != nil {
		if errors.Is(err, bpf.ErrInvalidHeadendPrefix) {
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
		return nil, connect.NewError(connect.CodeNotFound, err)
	}

	resp := &v1.Headendv6GetResponse{
		Headendv6: s.entryToProto(bpf.HeadendID{VRF: vrfID, Prefix: req.Msg.TriggerPrefix}, entry),
	}

	return connect.NewResponse(resp), nil
}

// protoToEntry converts a protobuf Headendv6 to a BPF map entry
func (s *Headendv6Server) protoToEntry(headend *v1.Headendv6) (*bpf.HeadendEntry, error) {
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

	// H.M.GTP6.D writes the 5-byte Args.Mob.Session at args_offset, so offset+5
	// must fit the 16-byte SID: max 11. The BPF drops anything larger, so reject
	// it here for a create-time error instead of a silent per-packet drop.
	if headend.ArgsOffset > 11 {
		return nil, fmt.Errorf("args_offset must be 0-11, got %d", headend.ArgsOffset)
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

// entryToProto converts a BPF map entry to a protobuf Headendv6
func (s *Headendv6Server) entryToProto(id bpf.HeadendID, entry *bpf.HeadendEntry) *v1.Headendv6 {
	return &v1.Headendv6{
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
