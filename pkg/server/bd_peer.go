package server

import (
	"context"
	"fmt"
	"math"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
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

	for _, peer := range req.Msg.Peers {
		// Range-check before the uint16 cast: a wrapped bd_id would install
		// the peer into a different bridge domain than the caller asked for.
		if peer.BdId > math.MaxUint16 {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: fmt.Sprintf("bd_%d", peer.BdId),
				Reason:        fmt.Sprintf("bd_id %d out of range (max %d)", peer.BdId, math.MaxUint16),
			})
			continue
		}
		bdID := uint16(peer.BdId)

		entry, err := s.protoToEntry(peer)
		if err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: fmt.Sprintf("bd_%d", peer.BdId),
				Reason:        err.Error(),
			})
			continue
		}

		esi, err := bpf.ParseValidESI(peer.Esi)
		if err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: fmt.Sprintf("bd_%d", peer.BdId),
				Reason:        err.Error(),
			})
			continue
		}

		// Operator-created peers carry no advertising-PE source, so key the
		// reverse map on the entry's own SrcAddr (preserving prior behavior).
		// Probe-and-create runs under one critical section so a concurrent
		// writer cannot land on the same index and be silently overwritten.
		if _, err := s.mapOps.CreateBdPeerAtFreeIndex(bdID, entry, esi, entry.SrcAddr, true); err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: fmt.Sprintf("bd_%d", peer.BdId),
				Reason:        err.Error(),
			})
			continue
		}

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
		if bdID > math.MaxUint16 {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: fmt.Sprintf("bd_%d", bdID),
				Reason:        fmt.Sprintf("bd_id %d out of range (max %d)", bdID, math.MaxUint16),
			})
			continue
		}
		deleted := false
		// Only the flood slots, where the operator's peers are. The ES
		// range belongs to the BGP applier's EVPN aliasing state: deleting
		// those entries here would leave the applier's ledger, the FDB
		// pointers and the ECMP group referencing a peer that no longer
		// exists, with nothing to trigger a repair (leftovers in that range
		// are swept by the applier itself at startup). The unicast range
		// holds the RT2 and plugin peers, which the owner check would refuse
		// anyway.
		for i := bpf.FloodPeerRange.Base; i < bpf.FloodPeerRange.End(); i++ {
			existed, err := s.mapOps.DeleteBdPeer(uint16(bdID), i)
			if err != nil {
				resp.Errors = append(resp.Errors, &v1.OperationError{
					TriggerPrefix: fmt.Sprintf("bd_%d_idx_%d", bdID, i),
					Reason:        err.Error(),
				})
			} else if existed {
				deleted = true
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
	if err := checkBdIDRange(req.Msg.BdId); err != nil {
		return nil, err
	}
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

// bdPeerFreedReplay is the hook the map operations call when a bridge
// domain's peer range that was full frees an index: it asks for a replay of
// the EVPN routes, so a route that did not fit is installed. It does not
// block; the replay runs on the replayer's goroutine.
func bdPeerFreedReplay(request func([]bgp.Family)) func() {
	return func() { request([]bgp.Family{bgp.FamilyEVPN}) }
}

func (s *BdPeerServer) protoToEntry(peer *v1.BdPeer) (*bpf.HeadendEntry, error) {
	return buildL2HeadendEntry(peer.SrcAddr, peer.Segments, peer.Mode, peer.BdId)
}
