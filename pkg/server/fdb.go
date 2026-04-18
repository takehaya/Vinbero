package server

import (
	"context"
	"fmt"
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

func (s *FdbServer) FdbCreate(
	ctx context.Context,
	req *connect.Request[v1.FdbCreateRequest],
) (*connect.Response[v1.FdbCreateResponse], error) {
	mac, err := net.ParseMAC(req.Msg.Mac)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid MAC: %w", err))
	}
	entry := &bpf.FdbEntry{
		Oif:      req.Msg.Oif,
		IsStatic: 1,
	}
	if err := s.mapOps.CreateFdb(uint16(req.Msg.BdId), mac, entry); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&v1.FdbCreateResponse{}), nil
}

func (s *FdbServer) FdbDelete(
	ctx context.Context,
	req *connect.Request[v1.FdbDeleteRequest],
) (*connect.Response[v1.FdbDeleteResponse], error) {
	mac, err := net.ParseMAC(req.Msg.Mac)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid MAC: %w", err))
	}
	if err := s.mapOps.DeleteFdb(uint16(req.Msg.BdId), mac); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&v1.FdbDeleteResponse{}), nil
}

// FdbFlush removes FDB entries, optionally scoped to a BD and optionally
// keeping user-configured static entries.
func (s *FdbServer) FdbFlush(
	ctx context.Context,
	req *connect.Request[v1.FdbFlushRequest],
) (*connect.Response[v1.FdbFlushResponse], error) {
	count, err := s.mapOps.FlushFdb(uint16(req.Msg.BdId), req.Msg.KeepStatic)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&v1.FdbFlushResponse{DeletedCount: count}), nil
}
