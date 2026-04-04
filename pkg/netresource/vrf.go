package netresource

import (
	"fmt"

	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

func (m *ResourceManager) CreateVrf(name string, tableID uint32, members []string, enableL3mdevRule bool) (uint32, error) {
	// Idempotent: return existing ifindex if VRF already exists
	if existing, err := netlink.LinkByName(name); err == nil {
		ifindex := uint32(existing.Attrs().Index)
		m.ensureVrfInState(name, tableID, members, enableL3mdevRule, ifindex)
		return ifindex, nil
	}

	ifindex, err := createVrfNetlink(name, tableID, members, enableL3mdevRule)
	if err != nil {
		return 0, err
	}

	m.mu.Lock()
	m.state.VRFs = append(m.state.VRFs, ManagedVrf{
		Name: name, TableID: tableID, Members: members,
		EnableL3mdevRule: enableL3mdevRule, Ifindex: ifindex,
	})
	m.mu.Unlock()

	if err := saveState(m.statePath, m.state); err != nil {
		m.logger.Warn("failed to save state after VRF creation", zap.Error(err))
	}

	m.logger.Info("Created VRF",
		zap.String("name", name), zap.Uint32("table_id", tableID), zap.Uint32("ifindex", ifindex))
	return ifindex, nil
}

func (m *ResourceManager) DeleteVrf(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("VRF %s not found: %w", name, err)
	}

	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("delete VRF %s: %w", name, err)
	}

	m.mu.Lock()
	filtered := m.state.VRFs[:0]
	for _, v := range m.state.VRFs {
		if v.Name != name {
			filtered = append(filtered, v)
		}
	}
	m.state.VRFs = filtered
	m.mu.Unlock()

	if err := saveState(m.statePath, m.state); err != nil {
		m.logger.Warn("failed to save state after VRF deletion", zap.Error(err))
	}

	m.logger.Info("Deleted VRF", zap.String("name", name))
	return nil
}

func (m *ResourceManager) ListVrfs() []ManagedVrf {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]ManagedVrf, len(m.state.VRFs))
	copy(result, m.state.VRFs)
	return result
}

func (m *ResourceManager) ensureVrfInState(name string, tableID uint32, members []string, enableL3mdevRule bool, ifindex uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.state.VRFs {
		if m.state.VRFs[i].Name == name {
			m.state.VRFs[i].Ifindex = ifindex
			return
		}
	}
	m.state.VRFs = append(m.state.VRFs, ManagedVrf{
		Name: name, TableID: tableID, Members: members,
		EnableL3mdevRule: enableL3mdevRule, Ifindex: ifindex,
	})
}

// createVrfNetlink creates a VRF and enslaves members via netlink.
func createVrfNetlink(name string, tableID uint32, members []string, enableL3mdevRule bool) (uint32, error) {
	vrf := &netlink.Vrf{
		LinkAttrs: netlink.LinkAttrs{Name: name},
		Table:     tableID,
	}
	if err := netlink.LinkAdd(vrf); err != nil {
		return 0, fmt.Errorf("create VRF %s: %w", name, err)
	}

	link, err := netlink.LinkByName(name)
	if err != nil {
		return 0, fmt.Errorf("find created VRF %s: %w", name, err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return 0, fmt.Errorf("set VRF %s up: %w", name, err)
	}

	for _, member := range members {
		if err := enslaveInterface(member, link); err != nil {
			return 0, err
		}
	}

	if enableL3mdevRule {
		if err := ensureL3mdevRule(); err != nil {
			return 0, fmt.Errorf("add l3mdev rule: %w", err)
		}
	}

	return uint32(link.Attrs().Index), nil
}

func ensureL3mdevRule() error {
	rules, err := netlink.RuleList(unix.AF_INET)
	if err != nil {
		return err
	}
	for _, r := range rules {
		if r.IifName == "" && r.Table == 0 && r.Priority == 1000 {
			return nil
		}
	}
	rule := netlink.NewRule()
	rule.Priority = 1000
	rule.Table = 0
	rule.Family = unix.AF_INET
	return netlink.RuleAdd(rule)
}
