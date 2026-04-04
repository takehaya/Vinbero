package server

import (
	"context"
	"net"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
)

type DmacServer struct {
	mapOps *bpf.MapOperations
}

func NewDmacServer(mapOps *bpf.MapOperations) *DmacServer {
	return &DmacServer{mapOps: mapOps}
}

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
			BdId: uint32(key.BdId),
			Mac:  mac.String(),
			Oif:  entry.Oif,
			// TODO: IsUntag is not yet tracked in the BPF fdb_entry struct.
			// Once VLAN-tag stripping on egress is implemented in XDP,
			// populate this from the FDB entry.
		})
	}

	return connect.NewResponse(resp), nil
}
