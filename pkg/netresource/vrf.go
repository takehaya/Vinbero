package netresource

import (
	"errors"
	"fmt"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
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
		// Converge the adopted device on the request: bring it up (an
		// operator-created admin-DOWN device would blackhole End.DT* decap
		// behind a successful create), enslave any members it is missing
		// (LinkSetMaster is idempotent for already-enslaved links) and add
		// the l3mdev rule when asked, so an adopt is not silently weaker
		// than a fresh create.
		if err := netlink.LinkSetUp(existing); err != nil {
			return 0, fmt.Errorf("set VRF %s up: %w", name, err)
		}
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

	// A fresh create cannot collide with an existing name (createVrfNetlink
	// would have failed on LinkAdd), so the upsert takes its append branch.
	m.ensureVrfInState(name, tableID, members, enableL3mdevRule, ifindex)

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
		// Mirror the adopt path's type check: if the managed VRF vanished
		// out-of-band and an unrelated link now bears the name, LinkDel would
		// destroy that interface. Treat it like an absent device instead —
		// the managed VRF is gone either way, so only the state entry goes.
		if _, ok := link.(*netlink.Vrf); !ok {
			m.logger.Warn("link with this name is not a VRF device; removing state entry only",
				zap.String("name", name), zap.String("type", link.Type()))
			break
		}
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

// l3mdevRulePriority is where the l3mdev rule is installed: after the local
// table (0) and well before main (32766), matching the `ip rule add l3mdev
// ... prio 1000` convention.
const l3mdevRulePriority = 1000

func ensureL3mdevRule() error {
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		if err := ensureL3mdevRuleForFamily(family); err != nil {
			return err
		}
	}
	return nil
}

// ensureL3mdevRuleForFamily installs an l3mdev rule (`from all lookup
// [l3mdev-table]`) at l3mdevRulePriority if none is present. An l3mdev rule
// parses back with no table and no iif, which is what the presence check
// matches (a rule added out-of-band via `ip rule add l3mdev` counts too).
//
// The message is built via the raw nl helpers because the released
// vishvananda/netlink Rule API cannot express FRA_L3MDEV: RuleAdd with a
// plain priority/table rule installs a `lookup <n>` rule that does NOT
// consult the packet's VRF table (and the AF_INET6 variant is rejected with
// EINVAL outright).
func ensureL3mdevRuleForFamily(family int) error {
	rules, err := netlink.RuleList(family)
	if err != nil {
		return err
	}
	for _, r := range rules {
		if r.IifName == "" && r.Table == 0 && r.Priority == l3mdevRulePriority {
			return nil
		}
	}
	req := nl.NewNetlinkRequest(unix.RTM_NEWRULE, unix.NLM_F_CREATE|unix.NLM_F_EXCL|unix.NLM_F_ACK)
	msg := nl.NewRtMsg() // layout-compatible with fib_rule_hdr (Type = action)
	msg.Family = uint8(family)
	msg.Table = 0                 // l3mdev rules carry no fixed table
	msg.Type = unix.FR_ACT_TO_TBL // resolved through the packet's l3mdev at lookup time
	msg.Protocol = 0
	msg.Scope = 0
	req.AddData(msg)
	req.AddData(nl.NewRtAttr(nl.FRA_L3MDEV, []byte{1}))
	req.AddData(nl.NewRtAttr(nl.FRA_PRIORITY, nl.Uint32Attr(l3mdevRulePriority)))
	_, err = req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}
