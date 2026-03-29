package server

import (
	"context"
	"net"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
)

// DmacServer implements the DmacServiceHandler interface
type DmacServer struct {
	mapOps *bpf.MapOperations
}

// NewDmacServer creates a new DmacServer
func NewDmacServer(mapOps *bpf.MapOperations) *DmacServer {
	return &DmacServer{mapOps: mapOps}
}

// DmacList lists all FDB entries from the BPF map
func (s *DmacServer) DmacList(
	ctx context.Context,
	req *connect.Request[v1.DmacListRequest],
) (*connect.Response[v1.DmacListResponse], error) {
	entries, err := s.mapOps.ListFdb()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	resp := &v1.DmacListResponse{
		Entries: make([]*v1.DmacListEntry, 0, len(entries)),
	}

	for key, entry := range entries {
		mac := net.HardwareAddr(key.Mac[:])
		resp.Entries = append(resp.Entries, &v1.DmacListEntry{
			BdId:    uint32(key.BdId),
			Mac:     mac.String(),
			Oif:     entry.Oif,
			IsUntag: entry.IsUntag != 0,
		})
	}

	return connect.NewResponse(resp), nil
}
