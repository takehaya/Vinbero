package netresource

import (
	"fmt"

	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
)

func (m *ResourceManager) CreateBridge(name string, bdID uint16, members []string) (uint32, error) {
	// Idempotent: return existing ifindex if bridge already exists
	if existing, err := netlink.LinkByName(name); err == nil {
		ifindex := uint32(existing.Attrs().Index)
		m.ensureBridgeInState(name, bdID, members, ifindex)
		return ifindex, nil
	}

	ifindex, err := createBridgeNetlink(name, members)
	if err != nil {
		return 0, err
	}

	m.mu.Lock()
	m.state.Bridges = append(m.state.Bridges, ManagedBridge{
		Name: name, BdID: bdID, Members: members, Ifindex: ifindex,
	})
	m.mu.Unlock()

	if err := saveState(m.statePath, m.state); err != nil {
		m.logger.Warn("failed to save state after bridge creation", zap.Error(err))
	}

	m.logger.Info("Created bridge",
		zap.String("name", name), zap.Uint16("bd_id", bdID), zap.Uint32("ifindex", ifindex))
	return ifindex, nil
}

func (m *ResourceManager) DeleteBridge(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("bridge %s not found: %w", name, err)
	}

	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("delete bridge %s: %w", name, err)
	}

	m.mu.Lock()
	filtered := m.state.Bridges[:0]
	for _, b := range m.state.Bridges {
		if b.Name != name {
			filtered = append(filtered, b)
		}
	}
	m.state.Bridges = filtered
	m.mu.Unlock()

	if err := saveState(m.statePath, m.state); err != nil {
		m.logger.Warn("failed to save state after bridge deletion", zap.Error(err))
	}

	m.logger.Info("Deleted bridge", zap.String("name", name))
	return nil
}

func (m *ResourceManager) ListBridges() []ManagedBridge {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]ManagedBridge, len(m.state.Bridges))
	copy(result, m.state.Bridges)
	return result
}

func (m *ResourceManager) ensureBridgeInState(name string, bdID uint16, members []string, ifindex uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.state.Bridges {
		if m.state.Bridges[i].Name == name {
			m.state.Bridges[i].Ifindex = ifindex
			return
		}
	}
	m.state.Bridges = append(m.state.Bridges, ManagedBridge{
		Name: name, BdID: bdID, Members: members, Ifindex: ifindex,
	})
}

// createBridgeNetlink creates a bridge and enslaves members via netlink.
// Does not touch ResourceManager state — caller is responsible for that.
func createBridgeNetlink(name string, members []string) (uint32, error) {
	bridge := &netlink.Bridge{
		LinkAttrs: netlink.LinkAttrs{Name: name},
	}
	if err := netlink.LinkAdd(bridge); err != nil {
		return 0, fmt.Errorf("create bridge %s: %w", name, err)
	}

	link, err := netlink.LinkByName(name)
	if err != nil {
		return 0, fmt.Errorf("find created bridge %s: %w", name, err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return 0, fmt.Errorf("set bridge %s up: %w", name, err)
	}

	for _, member := range members {
		if err := enslaveInterface(member, link); err != nil {
			return 0, err
		}
	}

	return uint32(link.Attrs().Index), nil
}

func enslaveInterface(memberName string, master netlink.Link) error {
	memberLink, err := netlink.LinkByName(memberName)
	if err != nil {
		return fmt.Errorf("member interface %s not found: %w", memberName, err)
	}
	if err := netlink.LinkSetMaster(memberLink, master); err != nil {
		return fmt.Errorf("enslave %s to %s: %w", memberName, master.Attrs().Name, err)
	}
	return nil
}
