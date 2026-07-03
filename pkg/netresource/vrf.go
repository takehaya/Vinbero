package netresource

import (
	"errors"
	"fmt"

	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

func (m *ResourceManager) CreateVrf(name string, tableID uint32, members []string, enableL3mdevRule bool) (uint32, error) {
	// Idempotent adopt: an existing link is taken over only when it really is
	// a VRF device on the requested table. A bare name match must not adopt —
	// otherwise a typo like --name eth1 would put the NIC into the state file
	// and a later delete would LinkDel it.
	if existing, err := netlink.LinkByName(name); err == nil {
		vrfLink, ok := existing.(*netlink.Vrf)
		if !ok {
			return 0, fmt.Errorf("link %s exists but is %s, not a VRF device", name, existing.Type())
		}
		if vrfLink.Table != tableID {
			return 0, fmt.Errorf("VRF %s exists with table %d, requested %d (delete it first to change tables)", name, vrfLink.Table, tableID)
		}
		// Converge the adopted device on the request: enslave any members it
		// is missing (LinkSetMaster is idempotent for already-enslaved links)
		// and add the l3mdev rule when asked, so an adopt after a config
		// change is not silently weaker than a fresh create.
		for _, member := range members {
			if err := enslaveInterface(member, existing); err != nil {
				return 0, err
			}
		}
		if enableL3mdevRule {
			if err := ensureL3mdevRule(); err != nil {
				return 0, fmt.Errorf("add l3mdev rule: %w", err)
			}
		}
		ifindex := uint32(existing.Attrs().Index)
		m.ensureVrfInState(name, tableID, members, enableL3mdevRule, ifindex)
		if err := saveState(m.statePath, m.state); err != nil {
			m.logger.Warn("failed to save state after VRF idempotent update", zap.Error(err))
		}
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
	switch {
	case err == nil:
		if err := netlink.LinkDel(link); err != nil {
			return fmt.Errorf("delete VRF %s: %w", name, err)
		}
	case errors.As(err, &netlink.LinkNotFoundError{}):
		// The device is already gone (e.g. removed with raw `ip link del`).
		// Fall through to drop the state entry, so a vanished device does not
		// leave an undeletable record behind — delete is idempotent.
		m.logger.Warn("VRF device already absent; removing state entry only", zap.String("name", name))
	default:
		return fmt.Errorf("VRF %s lookup: %w", name, err)
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

// ensureVrfInState upserts the full record: the caller has already verified
// the request against the live device (adopt type/table check), so a tracked
// name refreshes every field — updating only Ifindex would keep stale
// members/l3mdev in the state file after a config change.
func (m *ResourceManager) ensureVrfInState(name string, tableID uint32, members []string, enableL3mdevRule bool, ifindex uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry := ManagedVrf{
		Name: name, TableID: tableID, Members: members,
		EnableL3mdevRule: enableL3mdevRule, Ifindex: ifindex,
	}
	for i := range m.state.VRFs {
		if m.state.VRFs[i].Name == name {
			m.state.VRFs[i] = entry
			return
		}
	}
	m.state.VRFs = append(m.state.VRFs, entry)
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
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		if err := ensureL3mdevRuleForFamily(family); err != nil {
			return err
		}
	}
	return nil
}

func ensureL3mdevRuleForFamily(family int) error {
	rules, err := netlink.RuleList(family)
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
	rule.Family = family
	return netlink.RuleAdd(rule)
}
