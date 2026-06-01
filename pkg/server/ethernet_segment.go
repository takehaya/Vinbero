package server

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	"github.com/cilium/ebpf"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
	"go.uber.org/zap"
)

// EvpnEsHook advertises or withdraws an EVPN RT4 (Ethernet Segment route) as a
// local Ethernet Segment is created or deleted. *pkg/bgp/export.EVPNExporter
// satisfies it; it is nil unless EVPN auto-advertise is on.
type EvpnEsHook interface {
	EnableES(esi [bpf.ESILen]byte, rd string) error
	DisableES(esi [bpf.ESILen]byte)
	// RDForESI returns the RD the ES's RT4 is advertised with so EsList can echo
	// it; the BPF esi_map does not store the RD. ok=false when not advertised.
	RDForESI(esi [bpf.ESILen]byte) (string, bool)
}

type EthernetSegmentServer struct {
	mapOps *bpf.MapOperations
	// reElect re-runs BGP DF election for an ESI after a local attach. It is
	// nil when the in-process BGP speaker is disabled. Without it, an RT4 that
	// arrived before `es create` would never elect a DF (the applier skipped it
	// at receive time because the ESI was not yet locally attached).
	reElect func(esi [bpf.ESILen]byte)
	evpn    EvpnEsHook // RT4 auto-advertise hook; nil when off
	logger  *zap.Logger
}

func NewEthernetSegmentServer(mapOps *bpf.MapOperations, reElect func(esi [bpf.ESILen]byte), evpn EvpnEsHook, logger *zap.Logger) *EthernetSegmentServer {
	return &EthernetSegmentServer{mapOps: mapOps, reElect: reElect, evpn: evpn, logger: logger}
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
	// The RD lives only in the auto-advertise exporter's state (the BPF esi_map
	// carries no RD), so echo it from there when EVPN auto-advertise is on and this
	// ES is advertised. Off / not-advertised leaves rd empty.
	if s.evpn != nil {
		if rd, ok := s.evpn.RDForESI(esi); ok {
			out.Rd = rd
		}
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
		// A local attach is what lets DF election write esi_map. Re-run it now
		// so an RT4 received before this create (recorded in the applier's
		// membership but skipped at the time) elects a DF without waiting for
		// the next BGP event.
		if cfg.LocalAttached && s.reElect != nil {
			s.reElect(esi)
		}
		// If EVPN auto-advertise is on and this ES is locally attached with an RD,
		// originate its RT4 (Ethernet Segment route) for DF election. Non-fatal:
		// the ES data-plane entry is created regardless. EsCreate is an upsert, so
		// re-creating with rd cleared or local_attached=false must withdraw any
		// RT4 previously advertised for this ESI (DisableES is a no-op otherwise).
		if s.evpn != nil {
			if cfg.LocalAttached && e.GetRd() != "" {
				if err := s.evpn.EnableES(esi, e.GetRd()); err != nil {
					s.logger.Warn("enable EVPN RT4 auto-advertise for ethernet segment",
						zap.String("esi", e.Esi), zap.Error(err))
				}
			} else {
				s.evpn.DisableES(esi)
			}
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
		// Withdraw any RT4 auto-advertised for this ES (a no-op if it was not).
		if s.evpn != nil {
			s.evpn.DisableES(esi)
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
