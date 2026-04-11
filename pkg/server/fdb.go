package server

import (
	"context"
	"net"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
)

type FdbServer struct {
	mapOps *bpf.MapOperations
}

func NewFdbServer(mapOps *bpf.MapOperations) *FdbServer {
	return &FdbServer{mapOps: mapOps}
}

func (s *FdbServer) FdbList(
	ctx context.Context,
	req *connect.Request[v1.FdbListRequest],
) (*connect.Response[v1.FdbListResponse], error) {
	entries, err := s.mapOps.ListFdb()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	resp := &v1.FdbListResponse{
		Entries: make([]*v1.FdbEntry, 0, len(entries)),
	}

	for key, entry := range entries {
		mac := net.HardwareAddr(key.Mac[:])
		resp.Entries = append(resp.Entries, &v1.FdbEntry{
			BdId:     uint32(key.BdId),
			Mac:      mac.String(),
			Oif:      entry.Oif,
			IsRemote: entry.IsRemote != 0,
			IsStatic: entry.IsStatic != 0,
			LastSeen: entry.LastSeen,
		})
	}

	return connect.NewResponse(resp), nil
}
