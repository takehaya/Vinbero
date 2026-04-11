package server

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/netlinkwatch"
	"github.com/takehaya/vinbero/pkg/netresource"
)

type NetworkResourceServer struct {
	resMgr     *netresource.ResourceManager
	fdbWatcher *netlinkwatch.FDBWatcher
	mapOps     *bpf.MapOperations
}

func NewNetworkResourceServer(resMgr *netresource.ResourceManager, fdbWatcher *netlinkwatch.FDBWatcher, mapOps *bpf.MapOperations) *NetworkResourceServer {
	return &NetworkResourceServer{resMgr: resMgr, fdbWatcher: fdbWatcher, mapOps: mapOps}
}

func (s *NetworkResourceServer) BridgeCreate(
	ctx context.Context,
	req *connect.Request[v1.BridgeCreateRequest],
) (*connect.Response[v1.BridgeCreateResponse], error) {
	resp := &v1.BridgeCreateResponse{
		Created: make([]*v1.Bridge, 0),
		Errors:  make([]*v1.OperationError, 0),
	}

	for _, br := range req.Msg.Bridges {
		ifindex, err := s.resMgr.CreateBridge(br.Name, uint16(br.BdId), br.Members)
		if err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: br.Name,
				Reason:        err.Error(),
			})
			continue
		}

		// Register with FDB watcher for dynamic MAC learning
		s.fdbWatcher.RegisterBridge(int(ifindex), uint16(br.BdId))

		resp.Created = append(resp.Created, br)
	}

	return connect.NewResponse(resp), nil
}

func (s *NetworkResourceServer) BridgeDelete(
	ctx context.Context,
	req *connect.Request[v1.BridgeDeleteRequest],
) (*connect.Response[v1.BridgeDeleteResponse], error) {
	resp := &v1.BridgeDeleteResponse{
		DeletedNames: make([]string, 0),
		Errors:       make([]*v1.OperationError, 0),
	}

	for _, name := range req.Msg.Names {
		// Resolve ifindex from ResourceManager cache, falling back to netlink
		var ifindex uint32
		if br, ok := s.resMgr.GetBridgeByName(name); ok {
			ifindex = br.Ifindex
		} else if resolved, err := resolveIfindex(name); err == nil {
			ifindex = resolved
		}

		if ifindex != 0 {
			ref, err := s.findBridgeReference(ifindex)
			if err != nil {
				resp.Errors = append(resp.Errors, &v1.OperationError{
					TriggerPrefix: name,
					Reason:        fmt.Sprintf("failed to check references: %v", err),
				})
				continue
			}
			if ref != "" {
				resp.Errors = append(resp.Errors, &v1.OperationError{
					TriggerPrefix: name,
					Reason:        fmt.Sprintf("bridge is referenced by SID %s", ref),
				})
				continue
			}
			s.fdbWatcher.UnregisterBridge(int(ifindex))
		}

		if err := s.resMgr.DeleteBridge(name); err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: name,
				Reason:        err.Error(),
			})
			continue
		}

		resp.DeletedNames = append(resp.DeletedNames, name)
	}

	return connect.NewResponse(resp), nil
}

func (s *NetworkResourceServer) BridgeList(
	ctx context.Context,
	req *connect.Request[v1.BridgeListRequest],
) (*connect.Response[v1.BridgeListResponse], error) {
	bridges := s.resMgr.ListBridges()
	resp := &v1.BridgeListResponse{
		Bridges: make([]*v1.Bridge, 0, len(bridges)),
	}
	for _, b := range bridges {
		resp.Bridges = append(resp.Bridges, &v1.Bridge{
			Name:    b.Name,
			BdId:    uint32(b.BdID),
			Members: b.Members,
		})
	}
	return connect.NewResponse(resp), nil
}

func (s *NetworkResourceServer) VrfCreate(
	ctx context.Context,
	req *connect.Request[v1.VrfCreateRequest],
) (*connect.Response[v1.VrfCreateResponse], error) {
	resp := &v1.VrfCreateResponse{
		Created: make([]*v1.Vrf, 0),
		Errors:  make([]*v1.OperationError, 0),
	}

	for _, vrf := range req.Msg.Vrfs {
		_, err := s.resMgr.CreateVrf(vrf.Name, vrf.TableId, vrf.Members, vrf.EnableL3MdevRule)
		if err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: vrf.Name,
				Reason:        err.Error(),
			})
			continue
		}
		resp.Created = append(resp.Created, vrf)
	}

	return connect.NewResponse(resp), nil
}

func (s *NetworkResourceServer) VrfDelete(
	ctx context.Context,
	req *connect.Request[v1.VrfDeleteRequest],
) (*connect.Response[v1.VrfDeleteResponse], error) {
	resp := &v1.VrfDeleteResponse{
		DeletedNames: make([]string, 0),
		Errors:       make([]*v1.OperationError, 0),
	}

	for _, name := range req.Msg.Names {
		// Resolve ifindex from ResourceManager cache, falling back to netlink
		var ifindex uint32
		if vrf, ok := s.resMgr.GetVrfByName(name); ok {
			ifindex = vrf.Ifindex
		} else if resolved, err := resolveIfindex(name); err == nil {
			ifindex = resolved
		}

		if ifindex != 0 {
			ref, err := s.findVrfReference(ifindex)
			if err != nil {
				resp.Errors = append(resp.Errors, &v1.OperationError{
					TriggerPrefix: name,
					Reason:        fmt.Sprintf("failed to check references: %v", err),
				})
				continue
			}
			if ref != "" {
				resp.Errors = append(resp.Errors, &v1.OperationError{
					TriggerPrefix: name,
					Reason:        fmt.Sprintf("VRF is referenced by SID %s", ref),
				})
				continue
			}
		}

		if err := s.resMgr.DeleteVrf(name); err != nil {
			resp.Errors = append(resp.Errors, &v1.OperationError{
				TriggerPrefix: name,
				Reason:        err.Error(),
			})
			continue
		}

		resp.DeletedNames = append(resp.DeletedNames, name)
	}

	return connect.NewResponse(resp), nil
}

func (s *NetworkResourceServer) VrfList(
	ctx context.Context,
	req *connect.Request[v1.VrfListRequest],
) (*connect.Response[v1.VrfListResponse], error) {
	vrfs := s.resMgr.ListVrfs()
	resp := &v1.VrfListResponse{
		Vrfs: make([]*v1.Vrf, 0, len(vrfs)),
	}
	for _, v := range vrfs {
		resp.Vrfs = append(resp.Vrfs, &v1.Vrf{
			Name:             v.Name,
			TableId:          v.TableID,
			Members:          v.Members,
			EnableL3MdevRule: v.EnableL3mdevRule,
		})
	}
	return connect.NewResponse(resp), nil
}

// findBridgeReference checks if any SID entry references the given bridge_ifindex.
// Bridge ifindex is stored in the aux map (L2 variant), so we check entries with has_aux.
func (s *NetworkResourceServer) findBridgeReference(ifindex uint32) (string, error) {
	entries, err := s.mapOps.ListSidFunctions()
	if err != nil {
		return "", fmt.Errorf("list SID functions: %w", err)
	}
	for prefix, entry := range entries {
		if entry.HasAux != 0 {
			aux, err := s.mapOps.GetSidAux(entry.AuxIndex)
			if err != nil {
				continue
			}
			_, bridgeIfindex := bpf.SidAuxL2Data(aux)
			if bridgeIfindex == ifindex {
				return prefix, nil
			}
		}
	}
	return "", nil
}

// findVrfReference checks if any SID entry references the given vrf_ifindex.
func (s *NetworkResourceServer) findVrfReference(ifindex uint32) (string, error) {
	entries, err := s.mapOps.ListSidFunctions()
	if err != nil {
		return "", fmt.Errorf("list SID functions: %w", err)
	}
	for prefix, entry := range entries {
		if entry.VrfIfindex == ifindex {
			return prefix, nil
		}
	}
	return "", nil
}
