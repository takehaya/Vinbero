package server

import (
	"context"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
)

// PluginNameSource is the minimal surface StatsServer needs from the
// PluginServer: a snapshot of program names keyed by slot for a given
// PROG_ARRAY map type. Declared as an interface so stats tests can stub
// it without pulling the full registration machinery.
type PluginNameSource interface {
	SnapshotNames(mapType string) map[uint32]string
}

type StatsServer struct {
	mapOps  *bpf.MapOperations
	plugins PluginNameSource
}

func NewStatsServer(mapOps *bpf.MapOperations, plugins PluginNameSource) *StatsServer {
	return &StatsServer{mapOps: mapOps, plugins: plugins}
}

// resolveSlotName renders the human-readable label for a slot. Plugin
// entries take precedence ("plugin:<program_name>"), then builtin enum
// names, else empty string for reserved / unassigned slots.
func resolveSlotName(mapType string, slot uint32, plugins map[uint32]string) string {
	if name, ok := plugins[slot]; ok {
		return "plugin:" + name
	}
	switch mapType {
	case bpf.MapTypeEndpoint:
		return bpf.FormatEndpointBuiltinName(slot)
	case bpf.MapTypeHeadendV4, bpf.MapTypeHeadendV6:
		return bpf.FormatHeadendBuiltinName(slot)
	}
	return ""
}

// resolveSlotTargets returns the validated set of map types to operate on.
// Empty input expands to all SlotStatsMapTypes.
func resolveSlotTargets(in []string) ([]string, error) {
	if len(in) == 0 {
		return bpf.SlotStatsMapTypes, nil
	}
	for _, t := range in {
		if err := bpf.ValidateSlotStatsMapType(t); err != nil {
			return nil, err
		}
	}
	return in, nil
}

func (s *StatsServer) StatsShow(
	ctx context.Context,
	req *connect.Request[v1.StatsShowRequest],
) (*connect.Response[v1.StatsShowResponse], error) {
	stats, err := s.mapOps.ReadStats()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	counters := make([]*v1.StatsCounter, len(stats))
	for i, st := range stats {
		counters[i] = &v1.StatsCounter{
			Name:    st.Name,
			Packets: st.Packets,
			Bytes:   st.Bytes,
		}
	}

	return connect.NewResponse(&v1.StatsShowResponse{Counters: counters}), nil
}

func (s *StatsServer) StatsReset(
	ctx context.Context,
	req *connect.Request[v1.StatsResetRequest],
) (*connect.Response[v1.StatsResetResponse], error) {
	if err := s.mapOps.ResetStats(); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&v1.StatsResetResponse{}), nil
}

func (s *StatsServer) StatsSlotShow(
	ctx context.Context,
	req *connect.Request[v1.StatsSlotShowRequest],
) (*connect.Response[v1.StatsSlotShowResponse], error) {
	targets, err := resolveSlotTargets(req.Msg.MapTypes)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	var entries []*v1.SlotStatsEntry
	for _, t := range targets {
		stats, err := s.mapOps.ReadSlotStats(t)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		names := s.plugins.SnapshotNames(t)
		for _, st := range stats {
			if !req.Msg.IncludeEmpty && st.Packets == 0 {
				continue
			}
			entries = append(entries, &v1.SlotStatsEntry{
				MapType: st.MapType,
				Slot:    st.Slot,
				Name:    resolveSlotName(st.MapType, st.Slot, names),
				Packets: st.Packets,
				Bytes:   st.Bytes,
			})
		}
	}
	return connect.NewResponse(&v1.StatsSlotShowResponse{Entries: entries}), nil
}

func (s *StatsServer) StatsSlotReset(
	ctx context.Context,
	req *connect.Request[v1.StatsSlotResetRequest],
) (*connect.Response[v1.StatsSlotResetResponse], error) {
	targets, err := resolveSlotTargets(req.Msg.MapTypes)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	for _, t := range targets {
		if err := s.mapOps.ResetSlotStats(t); err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
	}
	return connect.NewResponse(&v1.StatsSlotResetResponse{}), nil
}
