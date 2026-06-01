package netresource

import (
	"fmt"
	"sync"

	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
)

type ResourceManager struct {
	logger    *zap.Logger
	statePath string
	state     *ManagedState
	mu        sync.RWMutex
}

func NewResourceManager(statePath string, logger *zap.Logger) (*ResourceManager, error) {
	state, err := loadState(statePath)
	if err != nil {
		return nil, fmt.Errorf("load state from %s: %w", statePath, err)
	}

	return &ResourceManager{
		logger:    logger,
		statePath: statePath,
		state:     state,
	}, nil
}

// Reconcile checks that all managed resources exist and recreates any that are missing.
// Called once at startup before any API requests, so no lock contention.
func (m *ResourceManager) Reconcile() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i := range m.state.Bridges {
		b := &m.state.Bridges[i]
		link, err := netlink.LinkByName(b.Name)
		if err != nil {
			m.logger.Info("Reconcile: recreating bridge",
				zap.String("name", b.Name), zap.Uint16("bd_id", b.BdID))
			ifindex, err := createBridgeNetlink(b.Name, b.Members)
			if err != nil {
				m.logger.Error("Reconcile: failed to recreate bridge",
					zap.String("name", b.Name), zap.Error(err))
				continue
			}
			b.Ifindex = ifindex
		} else {
			b.Ifindex = uint32(link.Attrs().Index)
		}
	}

	for i := range m.state.VRFs {
		v := &m.state.VRFs[i]
		link, err := netlink.LinkByName(v.Name)
		if err != nil {
			m.logger.Info("Reconcile: recreating VRF",
				zap.String("name", v.Name), zap.Uint32("table_id", v.TableID))
			ifindex, err := createVrfNetlink(v.Name, v.TableID, v.Members, v.EnableL3mdevRule)
			if err != nil {
				m.logger.Error("Reconcile: failed to recreate VRF",
					zap.String("name", v.Name), zap.Error(err))
				continue
			}
			v.Ifindex = ifindex
		} else {
			v.Ifindex = uint32(link.Attrs().Index)
		}
	}

	return saveState(m.statePath, m.state)
}

// GetBridgeByName returns the managed bridge info by name.
func (m *ResourceManager) GetBridgeByName(name string) (ManagedBridge, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, b := range m.state.Bridges {
		if b.Name == name {
			return b, true
		}
	}
	return ManagedBridge{}, false
}

// BridgeIfindexByBDID returns the Linux bridge ifindex of the managed bridge
// whose bridge domain id is bdID. The EVPN auto-advertise binding axis
// (VrfBgpBind) uses it to enable a bridge domain whose bridge already exists.
// ok=false when no managed bridge claims bdID (bind arrived before the bridge,
// so BridgeCreate will enable it instead) or when bdID is 0.
//
// It REFUSES an ambiguous bd_id (more than one bridge claims it) with ok=false,
// mirroring vrfbgp.Manager.GetByBDID: CreateBridge does not enforce bd_id
// uniqueness, and resolving a duplicate by first match would let the bridge that
// happens to sort first steer which device's FDB/decap target a route advertises.
// Fail closed instead so an ambiguous bd_id originates nothing on either axis.
func (m *ResourceManager) BridgeIfindexByBDID(bdID uint16) (uint32, bool) {
	if bdID == 0 {
		return 0, false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	var ifindex uint32
	n := 0
	for _, b := range m.state.Bridges {
		if b.BdID == bdID {
			ifindex = b.Ifindex
			n++
		}
	}
	if n != 1 {
		return 0, false
	}
	return ifindex, true
}

// GetVrfByName returns the managed VRF info by name.
func (m *ResourceManager) GetVrfByName(name string) (ManagedVrf, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, v := range m.state.VRFs {
		if v.Name == name {
			return v, true
		}
	}
	return ManagedVrf{}, false
}
