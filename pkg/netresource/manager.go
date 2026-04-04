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
