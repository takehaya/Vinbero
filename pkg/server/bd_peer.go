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

type BdPeerServer struct {
	mapOps *bpf.MapOperations
}

func NewBdPeerServer(mapOps *bpf.MapOperations) *BdPeerServer {
	return &BdPeerServer{mapOps: mapOps}
}

func (s *BdPeerServer) BdPeerCreate(
	ctx context.Context,
	req *connect.Request[v1.BdPeerCreateRequest],
) (*connect.Response[v1.BdPeerCreateResponse], error) {
	resp := &v1.BdPeerCreateResponse{
		Created: make([]*v1.BdPeer, 0),
		Errors:  make([]*v1.OperationError, 0),
	}

	// Track next indexes per BD within this batch.
	// Seed each BD's starting index via O(8) probe instead of full map iteration.
	bdIndexes := make(map[uint32]uint16)

	for _, peer := range req.Msg.Peers {
		bdID := uint16(peer.BdId)

		// Lazily resolve starting index for this BD on first encounter
		if _, ok := bdIndexes[peer.BdId]; !ok {
			bdIndexes[peer.BdId] = s.mapOps.FindFreeBdPeerIndex(bdID)
		}
		index := bdIndexes[peer.BdId]

		if index >= bpf.MaxBumNexthops {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: fmt.Sprintf("bd_%d", peer.BdId),
				Reason:        fmt.Sprintf("maximum number of peers (%d) reached for this BD", bpf.MaxBumNexthops),
			})
			continue
		}

		entry, err := s.protoToEntry(peer)
		if err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: fmt.Sprintf("bd_%d", peer.BdId),
				Reason:        err.Error(),
			})
			continue
		}

		esi, err := bpf.ParseESI(peer.Esi)
		if err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: fmt.Sprintf("bd_%d", peer.BdId),
				Reason:        err.Error(),
			})
			continue
		}

		if err := s.mapOps.CreateBdPeer(bdID, index, entry, esi); err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: fmt.Sprintf("bd_%d", peer.BdId),
				Reason:        err.Error(),
			})
			continue
		}

		bdIndexes[peer.BdId] = index + 1
		resp.Created = append(resp.Created, peer)
	}

	return connect.NewResponse(resp), nil
}

func (s *BdPeerServer) BdPeerDelete(
	ctx context.Context,
	req *connect.Request[v1.BdPeerDeleteRequest],
) (*connect.Response[v1.BdPeerDeleteResponse], error) {
	resp := &v1.BdPeerDeleteResponse{
		DeletedBdIds: make([]uint32, 0),
		Errors:       make([]*v1.OperationError, 0),
	}

	for _, bdID := range req.Msg.BdIds {
		deleted := false
		for i := uint16(0); i < bpf.MaxBumNexthops; i++ {
			err := s.mapOps.DeleteBdPeer(uint16(bdID), i)
			if err == nil {
				deleted = true
			} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
				resp.Errors = append(resp.Errors, &v1.OperationError{
					TriggerPrefix: fmt.Sprintf("bd_%d_idx_%d", bdID, i),
					Reason:        err.Error(),
				})
			}
		}
		if deleted {
			resp.DeletedBdIds = append(resp.DeletedBdIds, bdID)
		}
	}

	return connect.NewResponse(resp), nil
}

// BdPeerFlush removes BD peer entries, optionally scoped to a BD.
func (s *BdPeerServer) BdPeerFlush(
	ctx context.Context,
	req *connect.Request[v1.BdPeerFlushRequest],
) (*connect.Response[v1.BdPeerFlushResponse], error) {
	count, err := s.mapOps.FlushBdPeers(uint16(req.Msg.BdId))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&v1.BdPeerFlushResponse{DeletedCount: count}), nil
}

func (s *BdPeerServer) BdPeerList(
	ctx context.Context,
	req *connect.Request[v1.BdPeerListRequest],
) (*connect.Response[v1.BdPeerListResponse], error) {
	entries, err := s.mapOps.ListBdPeers()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	resp := &v1.BdPeerListResponse{
		Peers: make([]*v1.BdPeer, 0, len(entries)),
	}

	esiByPeer, err := s.mapOps.ListBdPeerEsi()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	for key, entry := range entries {
		if req.Msg.BdId != 0 && uint32(key.BdId) != req.Msg.BdId {
			continue
		}
		peer := &v1.BdPeer{
			BdId:     uint32(key.BdId),
			SrcAddr:  bpf.FormatIPv6(entry.SrcAddr),
			Segments: bpf.FormatSegments(entry.Segments, entry.NumSegments),
			Mode:     v1.Srv6HeadendBehavior(entry.Mode),
		}
		if esi, ok := esiByPeer[bpf.BdPeerEsiKey{BdId: key.BdId, SrcAddr: entry.SrcAddr}]; ok {
			peer.Esi = bpf.FormatESI(esi)
		}
		resp.Peers = append(resp.Peers, peer)
	}

	return connect.NewResponse(resp), nil
}

func (s *BdPeerServer) protoToEntry(peer *v1.BdPeer) (*bpf.HeadendEntry, error) {
	return buildL2HeadendEntry(peer.SrcAddr, peer.Segments, peer.Mode, peer.BdId)
}
