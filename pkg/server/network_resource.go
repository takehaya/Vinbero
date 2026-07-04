package server

import (
	"context"
	"fmt"
	"slices"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/netlinkwatch"
	"github.com/takehaya/vinbero/pkg/netresource"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
	"go.uber.org/zap"
)

// EvpnBridgeHook enables or disables EVPN auto-advertise (RT2 + RT3) for a bridge
// domain as its bridge is created or deleted. *pkg/bgp/export.EVPNExporter
// satisfies it; it is nil unless EVPN auto-advertise is on.
type EvpnBridgeHook interface {
	EnableBD(b vrfbgp.Binding, bridgeIfindex uint32) error
	DisableBD(bdID uint16)
	// SIDsForBD returns the sid_function_map keys the exporter installed for the
	// bd (End.DT2U + End.DT2M), so BridgeDelete can exclude these lifecycle-owned
	// SIDs from its reference check. nil for a bd that is not enabled.
	SIDsForBD(bdID uint16) []string
}

type NetworkResourceServer struct {
	resMgr     *netresource.ResourceManager
	fdbWatcher *netlinkwatch.FDBWatcher
	mapOps     *bpf.MapOperations
	mgr        *vrfbgp.Manager  // binding registry, to resolve a bd_id to its EVPN binding
	evpn       *EvpnCoordinator // EVPN BD lifecycle (device axis); nil unless auto-advertise is on
	logger     *zap.Logger
}

func NewNetworkResourceServer(resMgr *netresource.ResourceManager, fdbWatcher *netlinkwatch.FDBWatcher, mapOps *bpf.MapOperations, mgr *vrfbgp.Manager, evpn *EvpnCoordinator, logger *zap.Logger) *NetworkResourceServer {
	return &NetworkResourceServer{resMgr: resMgr, fdbWatcher: fdbWatcher, mapOps: mapOps, mgr: mgr, evpn: evpn, logger: logger}
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

		// If EVPN auto-advertise is on and this bd_id has a binding, enable
		// auto-advertise (RT2 + RT3) for the bridge (the device axis). The
		// coordinator's EnableForBridge handles the EnableBD + FDB replay; failures
		// are non-fatal (logged, not returned) so the bridge is created regardless.
		if s.evpn != nil {
			if b, ok := s.mgr.GetByBDID(uint16(br.BdId)); ok {
				s.evpn.EnableForBridge(b, ifindex, br.Name)
			}
		}

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
		// Resolve ifindex (and bd_id) from ResourceManager cache, falling back to
		// netlink for the ifindex.
		var ifindex uint32
		var bdID uint16
		if br, ok := s.resMgr.GetBridgeByName(name); ok {
			ifindex = br.Ifindex
			bdID = br.BdID
		} else if resolved, err := resolveIfindex(name); err == nil {
			ifindex = resolved
		}

		// The EVPN auto-advertise SIDs for this bd (End.DT2U for RT2, End.DT2M for
		// RT3) are lifecycle-tied to the bridge: they are released by DisableBD as
		// part of this delete, so exclude them (selfSIDs) from the reference check
		// below (otherwise they would always report the bridge as referenced and
		// block the delete). On a ResourceManager cache
		// miss (e.g. after a restart) bdID is 0, so recover it from the installed
		// L2 SID's aux. DisableBD itself runs only AFTER the bridge is actually
		// deleted, so a failed reference check or DeleteBridge leaves EVPN
		// auto-advertise intact rather than tearing it down for a surviving bridge.
		if s.evpn != nil && bdID == 0 && ifindex != 0 {
			if bd, ok := s.bdIDForBridge(ifindex); ok {
				bdID = bd
			}
		}
		var selfSIDs []string
		if s.evpn != nil && bdID != 0 {
			selfSIDs = s.evpn.SIDsForBD(bdID)
		}

		if ifindex != 0 {
			ref, err := s.findBridgeReference(ifindex, selfSIDs)
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

		// The bridge is gone; now release the EVPN auto-advertise SID and withdraw
		// its RT2s. Doing it here (not earlier) keeps EVPN intact if the delete
		// above failed. The binding may still exist (only the device left); a later
		// VrfBgpUnbind is a no-op for an already-disabled BD.
		if s.evpn != nil && bdID != 0 {
			s.evpn.Disable(bdID)
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

// bdIDForBridge returns the bd_id of an End.DT2/DT2M SID installed for the given
// bridge ifindex. BridgeDelete uses it to recover the bd_id (and so disable EVPN
// auto-advertise) when the ResourceManager cache has no record of the bridge.
// ok=false when no L2 SID references the bridge. DisableBD is a no-op for a bd_id
// the exporter has not enabled, so a non-exporter L2 SID match is harmless.
func (s *NetworkResourceServer) bdIDForBridge(ifindex uint32) (uint16, bool) {
	entries, err := s.mapOps.ListSidFunctions()
	if err != nil {
		return 0, false
	}
	for _, entry := range entries {
		switch v1.Srv6LocalAction(entry.Action) {
		case v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DT2,
			v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DT2M:
		default:
			continue
		}
		if entry.AuxIndex == 0 {
			continue
		}
		aux, err := s.mapOps.GetSidAux(uint32(entry.AuxIndex))
		if err != nil {
			continue
		}
		bdID, bridgeIfindex := bpf.SidAuxL2Data(aux)
		if bridgeIfindex == ifindex {
			return bdID, true
		}
	}
	return 0, false
}

// findBridgeReference checks if any End.DT2/DT2M SID entry references the given
// bridge_ifindex, returning the first such SID prefix. The exclude prefixes (the
// EVPN auto-advertise SIDs for this bridge, which the delete itself releases) are
// skipped so they do not block the delete. Bridge ifindex is stored in the aux
// map (L2 variant).
func (s *NetworkResourceServer) findBridgeReference(ifindex uint32, exclude []string) (string, error) {
	entries, err := s.mapOps.ListSidFunctions()
	if err != nil {
		return "", fmt.Errorf("list SID functions: %w", err)
	}
	for prefix, entry := range entries {
		if slices.Contains(exclude, prefix) {
			continue
		}
		switch v1.Srv6LocalAction(entry.Action) {
		case v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DT2,
			v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DT2M:
		default:
			continue
		}
		if entry.AuxIndex == 0 {
			continue
		}
		aux, err := s.mapOps.GetSidAux(uint32(entry.AuxIndex))
		if err != nil {
			continue
		}
		_, bridgeIfindex := bpf.SidAuxL2Data(aux)
		if bridgeIfindex == ifindex {
			return prefix, nil
		}
	}
	return "", nil
}
