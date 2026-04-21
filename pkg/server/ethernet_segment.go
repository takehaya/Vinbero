package server

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	"github.com/cilium/ebpf"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
)

type EthernetSegmentServer struct {
	mapOps *bpf.MapOperations
}

func NewEthernetSegmentServer(mapOps *bpf.MapOperations) *EthernetSegmentServer {
	return &EthernetSegmentServer{mapOps: mapOps}
}

func protoToEsiCfg(e *v1.EthernetSegment) (bpf.EsiConfig, error) {
	localPE, err := bpf.ParseIPv6(e.LocalPeSrcAddr)
	if err != nil {
		return bpf.EsiConfig{}, fmt.Errorf("local_pe_src_addr: %w", err)
	}
	dfPE, err := bpf.ParseIPv6(e.DfPeSrcAddr)
	if err != nil {
		return bpf.EsiConfig{}, fmt.Errorf("df_pe_src_addr: %w", err)
	}
	var zero [bpf.IPv6AddrLen]byte
	if e.LocalAttached && localPE == zero {
		return bpf.EsiConfig{}, errors.New("local_pe_src_addr required when local_attached=true (needed for DF judgement)")
	}
	return bpf.EsiConfig{
		LocalAttached:  e.LocalAttached,
		RedundancyMode: uint8(e.RedundancyMode),
		LocalPeSrcAddr: localPE,
		DfPeSrcAddr:    dfPE,
	}, nil
}

func (s *EthernetSegmentServer) entryToProto(esi [bpf.ESILen]byte, entry *bpf.EsiEntry) *v1.EthernetSegment {
	out := &v1.EthernetSegment{
		Esi:            bpf.FormatESI(esi),
		LocalAttached:  entry.IsLocalAttached(),
		RedundancyMode: v1.EsiRedundancyMode(entry.RedundancyMode),
	}
	var zero [bpf.IPv6AddrLen]byte
	if entry.LocalPeSrcAddr != zero {
		out.LocalPeSrcAddr = bpf.FormatIPv6(entry.LocalPeSrcAddr)
	}
	if entry.DfPeSrcAddr != zero {
		out.DfPeSrcAddr = bpf.FormatIPv6(entry.DfPeSrcAddr)
	}
	return out
}

func (s *EthernetSegmentServer) EsCreate(
	ctx context.Context,
	req *connect.Request[v1.EsCreateRequest],
) (*connect.Response[v1.EsCreateResponse], error) {
	resp := &v1.EsCreateResponse{
		Created: make([]*v1.EthernetSegment, 0),
		Errors:  make([]*v1.OperationError, 0),
	}

	for _, e := range req.Msg.Entries {
		esi, err := bpf.ParseESI(e.Esi)
		if err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{TriggerPrefix: e.Esi, Reason: err.Error()})
			continue
		}
		cfg, err := protoToEsiCfg(e)
		if err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{TriggerPrefix: e.Esi, Reason: err.Error()})
			continue
		}
		if err := s.mapOps.CreateEsi(esi, bpf.NewEsiEntry(cfg)); err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{TriggerPrefix: e.Esi, Reason: err.Error()})
			continue
		}
		resp.Created = append(resp.Created, e)
	}

	return connect.NewResponse(resp), nil
}

func (s *EthernetSegmentServer) EsDelete(
	ctx context.Context,
	req *connect.Request[v1.EsDeleteRequest],
) (*connect.Response[v1.EsDeleteResponse], error) {
	resp := &v1.EsDeleteResponse{
		Deleted: make([]string, 0),
		Errors:  make([]*v1.OperationError, 0),
	}

	for _, esiStr := range req.Msg.Esis {
		esi, err := bpf.ParseESI(esiStr)
		if err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{TriggerPrefix: esiStr, Reason: err.Error()})
			continue
		}
		if err := s.mapOps.DeleteEsi(esi); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				continue
			}
			resp.Errors = append(resp.Errors, &v1.OperationError{TriggerPrefix: esiStr, Reason: err.Error()})
			continue
		}
		resp.Deleted = append(resp.Deleted, esiStr)
	}

	return connect.NewResponse(resp), nil
}

func (s *EthernetSegmentServer) EsList(
	ctx context.Context,
	req *connect.Request[v1.EsListRequest],
) (*connect.Response[v1.EsListResponse], error) {
	entries, err := s.mapOps.ListEsi()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	resp := &v1.EsListResponse{Entries: make([]*v1.EthernetSegment, 0, len(entries))}
	for esi, entry := range entries {
		resp.Entries = append(resp.Entries, s.entryToProto(esi, entry))
	}
	return connect.NewResponse(resp), nil
}

func (s *EthernetSegmentServer) EsSetDf(
	ctx context.Context,
	req *connect.Request[v1.EsSetDfRequest],
) (*connect.Response[v1.EsSetDfResponse], error) {
	esi, err := bpf.ParseESI(req.Msg.Esi)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	df, err := bpf.ParseIPv6(req.Msg.DfPeSrcAddr)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("df_pe_src_addr: %w", err))
	}
	entry, err := s.mapOps.SetEsiDfPe(esi, df)
	if err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("ESI %s not found", req.Msg.Esi))
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&v1.EsSetDfResponse{Updated: s.entryToProto(esi, entry)}), nil
}

func (s *EthernetSegmentServer) EsClearDf(
	ctx context.Context,
	req *connect.Request[v1.EsClearDfRequest],
) (*connect.Response[v1.EsClearDfResponse], error) {
	esi, err := bpf.ParseESI(req.Msg.Esi)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	var zero [16]byte
	entry, err := s.mapOps.SetEsiDfPe(esi, zero)
	if err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("ESI %s not found", req.Msg.Esi))
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&v1.EsClearDfResponse{Updated: s.entryToProto(esi, entry)}), nil
}
