package netresource

import (
	"errors"
	"fmt"
	"slices"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// CreateVrf creates (or idempotently adopts) the kernel VRF device and
// persists it. On a persist failure the kernel device and the in-memory
// record are NOT rolled back: the error is returned so the caller sees the
// divergence, a retry re-adopts and converges, and the next successful
// persist writes the whole state anyway.
//
// Unless noUnreachableDefault is set, the VRF's table gets an unreachable
// default for IPv4 and IPv6 (see ensureUnreachableDefault), on a fresh create
// and on an adopt alike. The setting of a tracked VRF is not changed here: a
// request that asks for the other one is refused (see
// checkUnreachableDefault).
func (m *ResourceManager) CreateVrf(name string, tableID uint32, members []string, enableL3mdevRule, noUnreachableDefault bool) (uint32, error) {
	if err := m.checkUnreachableDefault(name, noUnreachableDefault); err != nil {
		return 0, err
	}
	records := m.ListVrfs()
	if existing, err := netlink.LinkByName(name); err == nil {
		ifindex, added, err := m.adoptVrfDevice(records, existing, name, tableID, members, enableL3mdevRule, noUnreachableDefault)
		if err != nil {
			return 0, err
		}
		m.ensureVrfInState(name, tableID, members, enableL3mdevRule, noUnreachableDefault, added, ifindex)
		if err := m.persist(); err != nil {
			return 0, fmt.Errorf("persist state after adopting VRF %s: %w", name, err)
		}
		m.warnSharedOptOut(name)
		return ifindex, nil
	}

	ifindex, added, err := m.createVrfNetlink(records, name, tableID, members, enableL3mdevRule, noUnreachableDefault)
	if err != nil {
		return 0, err
	}

	// A fresh create cannot collide with an existing name (createVrfNetlink
	// would have failed on LinkAdd), so the upsert takes its append branch.
	m.ensureVrfInState(name, tableID, members, enableL3mdevRule, noUnreachableDefault, added, ifindex)

	if err := m.persist(); err != nil {
		return 0, fmt.Errorf("persist state after creating VRF %s: %w", name, err)
	}

	m.logger.Info("Created VRF",
		zap.String("name", name), zap.Uint32("table_id", tableID), zap.Uint32("ifindex", ifindex))
	m.warnSharedOptOut(name)
	return ifindex, nil
}

// adoptVrfDevice takes over an existing link as the managed VRF device. The
// link is adopted only when it really is a VRF on the requested table -- a
// bare name match must not adopt, or a typo like --name eth1 would put the
// NIC into the state file and a later delete would LinkDel it. The adopted
// device is converged on the request: brought up (an operator-created
// admin-DOWN device would blackhole End.DT* decap behind a successful
// create), missing members enslaved (LinkSetMaster is idempotent) and the
// l3mdev rule added when asked, so an adopt is not silently weaker than a
// fresh create. The table gets its unreachable default before any member is
// enslaved, so no member's traffic falls through to main in between; a
// failure after that removes the routes this call added. It returns the
// families whose route this call added. Reconcile adopts state entries
// through the same path. records are the tracked VRFs (checkTable).
func (m *ResourceManager) adoptVrfDevice(records []ManagedVrf, link netlink.Link, name string, tableID uint32, members []string, enableL3mdevRule, noUnreachableDefault bool) (uint32, []string, error) {
	vrfLink, ok := link.(*netlink.Vrf)
	if !ok {
		return 0, nil, fmt.Errorf("link %s exists but is %s, not a VRF device", name, link.Type())
	}
	if vrfLink.Table != tableID {
		return 0, nil, fmt.Errorf("VRF %s exists with table %d, requested %d (delete it first to change tables)", name, vrfLink.Table, tableID)
	}
	mayClose, err := m.checkTable(records, name, tableID, members, noUnreachableDefault)
	if err != nil {
		return 0, nil, fmt.Errorf("VRF %s: %w", name, err)
	}
	var added []string
	if !noUnreachableDefault && mayClose {
		if added, err = m.ensureUnreachableDefault(tableID); err != nil {
			return 0, nil, fmt.Errorf("VRF %s: %w", name, err)
		}
	}
	fail := func(err error) (uint32, []string, error) {
		_ = m.removeUnreachableFamilies(tableID, added) // a failure is logged there
		return 0, nil, err
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fail(fmt.Errorf("set VRF %s up: %w", name, err))
	}
	for _, member := range members {
		if err := enslaveInterface(member, link); err != nil {
			return fail(err)
		}
	}
	if enableL3mdevRule {
		if err := ensureL3mdevRule(); err != nil {
			return fail(fmt.Errorf("add l3mdev rule: %w", err))
		}
	}
	return uint32(link.Attrs().Index), added, nil
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

	// The unreachable default stays in the table after the device is gone,
	// so the routes this VRF added are released here, before the state entry
	// that records them goes: a failed removal is retried by the next delete.
	m.mu.Lock()
	idx := slices.IndexFunc(m.state.VRFs, func(v ManagedVrf) bool { return v.Name == name })
	if idx >= 0 {
		if err := m.releaseUnreachableLocked(idx); err != nil {
			m.mu.Unlock()
			return fmt.Errorf("VRF %s: %w", name, err)
		}
	}
	filtered := m.state.VRFs[:0]
	for _, v := range m.state.VRFs {
		if v.Name != name {
			filtered = append(filtered, v)
		}
	}
	m.state.VRFs = filtered
	m.mu.Unlock()

	if err := m.persist(); err != nil {
		// The kernel device is gone and the record is removed in memory; the
		// next successful persist flushes it from disk too. Surface the error
		// so the operator knows disk state is momentarily behind.
		return fmt.Errorf("persist state after deleting VRF %s: %w", name, err)
	}

	m.logger.Info("Deleted VRF", zap.String("name", name))
	return nil
}

func (m *ResourceManager) ListVrfs() []ManagedVrf {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]ManagedVrf, len(m.state.VRFs))
	copy(result, m.state.VRFs)
	for i := range result {
		// Deep-copy the slices: the shallow struct copy would alias the
		// state-owned backing arrays, which ensureVrfInState appends to.
		result[i].Members = slices.Clone(result[i].Members)
		result[i].UnreachableDefaultAdded = slices.Clone(result[i].UnreachableDefaultAdded)
	}
	return result
}

// ensureVrfInState upserts the record. For a tracked name the request is
// MERGED into the existing entry rather than replacing it: the runtime only
// ever converges a device upward (enslave missing members, add the l3mdev
// rule — never unenslave or remove), so the state must record the union or an
// adopt with unspecified members/l3mdev (the CLI defaults) would silently
// weaken what Reconcile recreates after a reboot. Shrinking a device is a
// delete + recreate, same as changing its table. The unreachable-default
// setting is recorded as given (CreateVrf refuses one that differs from a
// tracked VRF's), and added joins the families whose route Vinbero added.
func (m *ResourceManager) ensureVrfInState(name string, tableID uint32, members []string, enableL3mdevRule, noUnreachableDefault bool, added []string, ifindex uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.state.VRFs {
		if m.state.VRFs[i].Name != name {
			continue
		}
		e := &m.state.VRFs[i]
		e.TableID = tableID // verified against the live device by the adopt check
		e.Ifindex = ifindex
		e.EnableL3mdevRule = e.EnableL3mdevRule || enableL3mdevRule
		e.setNoUnreachableDefault(noUnreachableDefault)
		e.addUnreachableFamilies(added)
		for _, member := range members {
			if !slices.Contains(e.Members, member) {
				e.Members = append(e.Members, member)
			}
		}
		m.openHeldTablesLocked()
		return
	}
	v := ManagedVrf{
		Name: name, TableID: tableID, Members: slices.Clone(members),
		EnableL3mdevRule: enableL3mdevRule, Ifindex: ifindex,
	}
	v.setNoUnreachableDefault(noUnreachableDefault)
	v.addUnreachableFamilies(added)
	m.state.VRFs = append(m.state.VRFs, v)
	m.openHeldTablesLocked()
}

// createVrfNetlink creates a VRF and enslaves members via netlink. Like the
// adopt, it adds the unreachable default before enslaving any member. A
// failure after the device exists removes the routes this call added and the
// device itself, so a failed create leaves nothing behind. It returns the
// families whose route it added. records are the tracked VRFs
// (checkTable, which runs before the device is made).
func (m *ResourceManager) createVrfNetlink(records []ManagedVrf, name string, tableID uint32, members []string, enableL3mdevRule, noUnreachableDefault bool) (uint32, []string, error) {
	mayClose, err := m.checkTable(records, name, tableID, members, noUnreachableDefault)
	if err != nil {
		return 0, nil, fmt.Errorf("VRF %s: %w", name, err)
	}
	vrf := &netlink.Vrf{
		LinkAttrs: netlink.LinkAttrs{Name: name},
		Table:     tableID,
	}
	if err := netlink.LinkAdd(vrf); err != nil {
		return 0, nil, fmt.Errorf("create VRF %s: %w", name, err)
	}

	var added []string
	fail := func(err error) (uint32, []string, error) {
		_ = m.removeUnreachableFamilies(tableID, added) // a failure is logged there
		if link, lerr := netlink.LinkByName(name); lerr == nil {
			if derr := netlink.LinkDel(link); derr != nil {
				m.logger.Warn("cannot remove the VRF device of a failed create",
					zap.String("name", name), zap.Error(derr))
			}
		}
		return 0, nil, err
	}

	link, err := netlink.LinkByName(name)
	if err != nil {
		return fail(fmt.Errorf("find created VRF %s: %w", name, err))
	}

	if !noUnreachableDefault && mayClose {
		if added, err = m.ensureUnreachableDefault(tableID); err != nil {
			return fail(fmt.Errorf("VRF %s: %w", name, err))
		}
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fail(fmt.Errorf("set VRF %s up: %w", name, err))
	}

	for _, member := range members {
		if err := enslaveInterface(member, link); err != nil {
			return fail(err)
		}
	}

	if enableL3mdevRule {
		if err := ensureL3mdevRule(); err != nil {
			return fail(fmt.Errorf("add l3mdev rule: %w", err))
		}
	}

	return uint32(link.Attrs().Index), added, nil
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
