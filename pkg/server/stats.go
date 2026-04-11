package server

import (
	"context"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
)

type StatsServer struct {
	mapOps *bpf.MapOperations
}

func NewStatsServer(mapOps *bpf.MapOperations) *StatsServer {
	return &StatsServer{mapOps: mapOps}
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
