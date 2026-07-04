package server

import (
	"context"
	"fmt"
	"math"
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
		fdbEntry := &v1.FdbEntry{
			BdId:     uint32(key.BdId),
			Mac:      mac.String(),
			Oif:      entry.Oif,
			IsRemote: entry.IsRemote != 0,
			IsStatic: entry.IsStatic != 0,
			LastSeen: entry.LastSeen,
		}
		if entry.IsRemote != 0 {
			fdbEntry.Esi = bpf.FormatESI(entry.Esi)
		}
		resp.Entries = append(resp.Entries, fdbEntry)
	}

	return connect.NewResponse(resp), nil
}

// checkBdIDRange rejects a wire bd_id past uint16 before the narrowing cast:
// a wrapped value (e.g. 65536 -> 0) would scope the FDB / peer operation to a
// different bridge domain than the caller asked for. Shared by the fdb and
// bd_peer handlers.
func checkBdIDRange(bdID uint32) error {
	if bdID > math.MaxUint16 {
		return connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("bd_id %d out of range (max %d)", bdID, math.MaxUint16))
	}
	return nil
}

func (s *FdbServer) FdbCreate(
	ctx context.Context,
	req *connect.Request[v1.FdbCreateRequest],
) (*connect.Response[v1.FdbCreateResponse], error) {
	if err := checkBdIDRange(req.Msg.BdId); err != nil {
		return nil, err
	}
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
	if err := checkBdIDRange(req.Msg.BdId); err != nil {
		return nil, err
	}
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
	if err := checkBdIDRange(req.Msg.BdId); err != nil {
		return nil, err
	}
	count, err := s.mapOps.FlushFdb(uint16(req.Msg.BdId), req.Msg.KeepStatic)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&v1.FdbFlushResponse{DeletedCount: count}), nil
}
