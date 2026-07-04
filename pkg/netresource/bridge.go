package netresource

import (
	"errors"
	"fmt"
	"slices"

	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
)

func (m *ResourceManager) CreateBridge(name string, bdID uint16, members []string, ownerVRF string) (uint32, error) {
	// Idempotent adopt: an existing link is taken over only when it really is
	// a bridge device. A bare name match must not adopt — otherwise a typo
	// like --name eth1 would put the NIC into the state file and a later
	// detach would LinkDel it.
	if existing, err := netlink.LinkByName(name); err == nil {
		if _, ok := existing.(*netlink.Bridge); !ok {
			return 0, fmt.Errorf("link %s exists but is %s, not a bridge device", name, existing.Type())
		}
		// bd_id and the owning VRF are not kernel attributes, so identity is
		// verified against the state entry: a tracked bridge cannot silently
		// change bd_id (the data-plane FDB scope) or move to another VRF.
		if tracked, ok := m.GetBridgeByName(name); ok {
			if tracked.BdID != bdID {
				return 0, fmt.Errorf("bridge %s is tracked with bd_id %d, requested %d (detach it first to change bd_id)", name, tracked.BdID, bdID)
			}
			if tracked.VRF != "" && ownerVRF != "" && tracked.VRF != ownerVRF {
				return 0, fmt.Errorf("bridge %s is owned by vrf %q, requested %q", name, tracked.VRF, ownerVRF)
			}
		}
		// Converge the adopted device on the request: bring it up (an
		// operator-created admin-DOWN bridge would blackhole End.DT2 decap
		// behind a successful attach) and enslave any members it is missing
		// (LinkSetMaster is idempotent for already-enslaved links), so an
		// adopt is not silently weaker than a fresh create.
		if err := netlink.LinkSetUp(existing); err != nil {
			return 0, fmt.Errorf("set bridge %s up: %w", name, err)
		}
		for _, member := range members {
			if err := enslaveInterface(member, existing); err != nil {
				return 0, err
			}
		}
		ifindex := uint32(existing.Attrs().Index)
		m.ensureBridgeInState(name, bdID, members, ifindex, ownerVRF)
		if err := saveState(m.statePath, m.state); err != nil {
			m.logger.Warn("failed to save state after bridge idempotent update", zap.Error(err))
		}
		return ifindex, nil
	}

	ifindex, err := createBridgeNetlink(name, members)
	if err != nil {
		return 0, err
	}

	// A fresh create cannot collide with an existing name (createBridgeNetlink
	// would have failed on LinkAdd), so the upsert takes its append branch.
	m.ensureBridgeInState(name, bdID, members, ifindex, ownerVRF)

	if err := saveState(m.statePath, m.state); err != nil {
		m.logger.Warn("failed to save state after bridge creation", zap.Error(err))
	}

	m.logger.Info("Created bridge",
		zap.String("name", name), zap.Uint16("bd_id", bdID), zap.Uint32("ifindex", ifindex),
		zap.String("vrf", ownerVRF))
	return ifindex, nil
}

func (m *ResourceManager) DeleteBridge(name string) error {
	link, err := netlink.LinkByName(name)
	switch {
	case err == nil:
		// Mirror the adopt path's type check: if the managed bridge vanished
		// out-of-band and an unrelated link now bears the name, LinkDel would
		// destroy that interface. Treat it like an absent device instead —
		// the managed bridge is gone either way, so only the state entry goes.
		if _, ok := link.(*netlink.Bridge); !ok {
			m.logger.Warn("link with this name is not a bridge device; removing state entry only",
				zap.String("name", name), zap.String("type", link.Type()))
			break
		}
		if err := netlink.LinkDel(link); err != nil {
			return fmt.Errorf("delete bridge %s: %w", name, err)
		}
	case errors.As(err, &netlink.LinkNotFoundError{}):
		// The device is already gone (e.g. removed with raw `ip link del`).
		// Fall through to drop the state entry, so a vanished device does not
		// leave an undeletable record behind — delete is idempotent.
		m.logger.Warn("bridge device already absent; removing state entry only", zap.String("name", name))
	default:
		return fmt.Errorf("bridge %s lookup: %w", name, err)
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

// ensureBridgeInState upserts the record. For a tracked name the request is
// MERGED into the existing entry (member union, owner filled when empty): the
// runtime only ever converges a bridge upward (enslave missing members, never
// unenslave), so the state must record the union or an adopt with unspecified
// members would silently weaken what Reconcile recreates after a reboot.
// Shrinking a bridge is a detach + re-attach. The caller has already verified
// bd_id / owner identity against the tracked entry.
func (m *ResourceManager) ensureBridgeInState(name string, bdID uint16, members []string, ifindex uint32, ownerVRF string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.state.Bridges {
		if m.state.Bridges[i].Name != name {
			continue
		}
		e := &m.state.Bridges[i]
		e.BdID = bdID // verified against the tracked entry by the adopt check
		e.Ifindex = ifindex
		if e.VRF == "" {
			e.VRF = ownerVRF
		}
		for _, member := range members {
			if !slices.Contains(e.Members, member) {
				e.Members = append(e.Members, member)
			}
		}
		return
	}
	m.state.Bridges = append(m.state.Bridges, ManagedBridge{
		Name: name, BdID: bdID, Members: slices.Clone(members),
		Ifindex: ifindex, VRF: ownerVRF,
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
