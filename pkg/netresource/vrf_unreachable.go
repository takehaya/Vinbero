package netresource

import (
	"errors"
	"fmt"
	"net"
	"slices"

	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// unreachableDefaultMetric is the metric of a VRF table's unreachable
// default: near the top of the metric range, the value the Linux VRF
// documentation uses, so every other route in the table is preferred.
const unreachableDefaultMetric = 4278198272

const (
	familyIPv4 = "ipv4"
	familyIPv6 = "ipv6"
)

// The route calls, replaced by tests that cannot reach the kernel.
var (
	routeAdd = netlink.RouteAdd
	routeDel = netlink.RouteDel
)

// unreachableDefault is the unreachable default of one family for a VRF
// table. A lookup in the table that matches nothing else ends on it (the
// packet is dropped with an ICMP unreachable) instead of the l3mdev rule
// missing and the kernel going on to the main table. It carries
// RTPROT_BOOT, the protocol of a plain `ip route add`, which the route
// watcher never redistributes.
func unreachableDefault(tableID uint32, family string) *netlink.Route {
	r := &netlink.Route{
		Table: int(tableID), Type: unix.RTN_UNREACHABLE, Priority: unreachableDefaultMetric,
		Protocol: unix.RTPROT_BOOT,
	}
	if family == familyIPv4 {
		r.Dst = &net.IPNet{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)}
	} else {
		r.Dst = &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}
	}
	return r
}

// ensureUnreachableDefault adds the unreachable defaults to the table and
// returns the families whose route it added. The add never replaces a
// route: a default the operator put in the table at a better metric is a
// different route and stays the one lookups use, and a route already at this
// metric (the operator's own unreachable default, or one added before a
// restart) is kept as it is and not counted as added. A host without IPv6
// (ipv6.disable=1) gets the IPv4 route only, with one log line. Its only
// callers, the create and the adopt, run checkTable first.
func (m *ResourceManager) ensureUnreachableDefault(tableID uint32) ([]string, error) {
	if m.tablesOpen {
		return nil, nil
	}
	var added []string
	for _, family := range []string{familyIPv4, familyIPv6} {
		r := unreachableDefault(tableID, family)
		err := routeAdd(r)
		switch {
		case err == nil:
			added = append(added, family)
		case errors.Is(err, unix.EEXIST):
		case family == familyIPv6 && (errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EAFNOSUPPORT)):
			// ipv6.disable=1 registers no IPv6 route handlers, and rtnetlink
			// answers EOPNOTSUPP; EAFNOSUPPORT covers a kernel without the
			// family altogether.
			if !m.noIPv6Logged.Swap(true) {
				m.logger.Info("IPv6 is not available on this host; VRF tables get no IPv6 unreachable default",
					zap.Uint32("table_id", tableID))
			}
		default:
			_ = m.removeUnreachableFamilies(tableID, added) // a failure is logged there
			return nil, fmt.Errorf("add unreachable default %s to table %d: %w", r.Dst, tableID, err)
		}
	}
	return added, nil
}

// removeUnreachableFamilies removes the unreachable defaults of the given
// families from the table. One already gone is not an error; any other
// failure is logged and returned.
func (m *ResourceManager) removeUnreachableFamilies(tableID uint32, families []string) error {
	var errs []error
	for _, family := range families {
		r := unreachableDefault(tableID, family)
		if err := routeDel(r); err != nil && !errors.Is(err, unix.ESRCH) {
			m.logger.Warn("cannot remove an unreachable default",
				zap.Uint32("table_id", tableID), zap.String("family", family), zap.Error(err))
			errs = append(errs, fmt.Errorf("remove unreachable default %s from table %d: %w", r.Dst, tableID, err))
		}
	}
	return errors.Join(errs...)
}

// listVrfDevices returns the kernel's VRF devices; tests replace it.
var listVrfDevices = func() ([]*netlink.Vrf, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	var vrfs []*netlink.Vrf
	for _, l := range links {
		if v, ok := l.(*netlink.Vrf); ok {
			vrfs = append(vrfs, v)
		}
	}
	return vrfs, nil
}

// releaseUnreachableLocked gives up the routes the VRF at idx added, for a
// delete or for an opt-out. Other users of the table decide what happens to
// them:
//
//   - another tracked VRF on the table that did not opt out still wants the
//     routes: they stay, and that VRF's record takes them over;
//   - a VRF device on the table that Vinbero does not track: the routes stay
//     (Vinbero cannot know whether it relies on them) and are no longer
//     Vinbero's;
//   - otherwise they are removed.
//
// The record at idx no longer lists them afterwards, unless the removal
// failed. Callers hold m.mu.
func (m *ResourceManager) releaseUnreachableLocked(idx int) error {
	v := &m.state.VRFs[idx]
	if len(v.UnreachableDefaultAdded) == 0 {
		return nil
	}
	for i := range m.state.VRFs {
		o := &m.state.VRFs[i]
		if !m.tablesOpen && i != idx && o.TableID == v.TableID && !o.OptedOut() {
			o.addUnreachableFamilies(v.UnreachableDefaultAdded)
			m.logger.Info("unreachable default stays: another VRF uses the table",
				zap.String("vrf", v.Name), zap.String("kept_for", o.Name), zap.Uint32("table_id", v.TableID))
			v.UnreachableDefaultAdded = nil
			return nil
		}
	}
	devices, err := listVrfDevices()
	if err != nil {
		return fmt.Errorf("list VRF devices: %w", err)
	}
	for _, d := range devices {
		if d.Table != v.TableID || d.Attrs().Name == v.Name {
			continue
		}
		if slices.ContainsFunc(m.state.VRFs, func(t ManagedVrf) bool { return t.Name == d.Attrs().Name }) {
			continue // tracked, and opted out (checked above)
		}
		m.logger.Info("unreachable default stays: a VRF device Vinbero does not manage uses the table",
			zap.String("vrf", v.Name), zap.String("device", d.Attrs().Name), zap.Uint32("table_id", v.TableID))
		v.UnreachableDefaultAdded = nil
		return nil
	}
	if err := m.removeUnreachableFamilies(v.TableID, v.UnreachableDefaultAdded); err != nil {
		return err
	}
	v.UnreachableDefaultAdded = nil
	return nil
}

// checkUnreachableDefault refuses a create that asks a tracked VRF for the
// other unreachable-default setting. Changing it at runtime is not
// supported: the config's setting takes effect at the next start
// (Reconcile), otherwise the VRF is deleted and created again.
func (m *ResourceManager) checkUnreachableDefault(name string, noUnreachableDefault bool) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	idx := slices.IndexFunc(m.state.VRFs, func(v ManagedVrf) bool { return v.Name == name })
	if idx < 0 || m.state.VRFs[idx].NoUnreachableDefault == nil {
		return nil
	}
	if cur := *m.state.VRFs[idx].NoUnreachableDefault; cur != noUnreachableDefault {
		return fmt.Errorf("VRF %s has no_unreachable_default=%t: the setting cannot be changed on an existing VRF "+
			"(set it in the config's vrfs.entries[], which applies at the next start, or delete and create the VRF again)", name, cur)
	}
	return nil
}

// warnSharedOptOut warns when a VRF that opted out shares its table with a
// tracked VRF that did not: the table holds that VRF's unreachable default,
// so the opt-out has no effect while it exists.
func (m *ResourceManager) warnSharedOptOut(name string) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	idx := slices.IndexFunc(m.state.VRFs, func(v ManagedVrf) bool { return v.Name == name })
	if idx < 0 || !m.state.VRFs[idx].OptedOut() {
		return
	}
	v := m.state.VRFs[idx]
	for _, o := range m.state.VRFs {
		if o.Name != name && o.TableID == v.TableID && !o.OptedOut() {
			m.logger.Warn("VRF opts out of the unreachable default but shares its table with a VRF that has it; the table keeps the route",
				zap.String("vrf", name), zap.String("shared_with", o.Name), zap.Uint32("table_id", v.TableID))
			return
		}
	}
}

// L2CircuitOnTable is an L2 headend circuit on a port of a VRF table: a
// port of a VRF device on the table, or one a VRF on it is to enslave. Its
// encapsulations and BUM copies are looked up on the port, so the table's
// unreachable default would drop them.
type L2CircuitOnTable struct {
	Port string // the port the circuit is on
	VLAN uint16 // the circuit's VLAN (0: untagged)
	VRF  string // the VRF the port is, or is to be, enslaved to
}

func (c L2CircuitOnTable) String() string {
	return fmt.Sprintf("L2 headend circuit {%s, vlan %d} on a port of VRF %s", c.Port, c.VLAN, c.VRF)
}

// TableCloseGuard returns an L2 headend circuit that the unreachable
// default of table would cut off, or nil: one on a port of any VRF device
// on the table now (managed by Vinbero or not), or on one of members, the
// ports VRFs on the table are to have (by name, with the VRF's name).
type TableCloseGuard func(table uint32, members map[string]string) (*L2CircuitOnTable, error)

// SetTableCloseGuard installs the L2 circuit check (checkTable). Call it
// before Reconcile.
func (m *ResourceManager) SetTableCloseGuard(g TableCloseGuard) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closeGuard = g
}

// ConfigVrfDevice is a VRF device the config declares.
type ConfigVrfDevice struct {
	Name    string
	TableID uint32
	Members []string
}

// SetConfigVrfDevices records the config's VRF devices, so the boot checks
// each table over the members the config gives the VRFs on it before it
// applies the config. Call it before Reconcile.
func (m *ResourceManager) SetConfigVrfDevices(devices []ConfigVrfDevice) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.configDevices = devices
}

// FinishBoot ends the boot: from then on a create or adopt that would put
// a table's unreachable default over an L2 headend circuit is refused.
// During the boot, where nothing can be refused, the table is held open
// instead (checkTable).
func (m *ResourceManager) FinishBoot() {
	m.heldMu.Lock()
	defer m.heldMu.Unlock()
	m.running = true
}

// TablesHeldOpen returns the tables the boot left open for an L2 headend
// circuit, each with that circuit: those whose unreachable defaults are
// gone (openHeldTablesLocked).
func (m *ResourceManager) TablesHeldOpen() map[uint32]string {
	m.heldMu.Lock()
	defer m.heldMu.Unlock()
	out := make(map[uint32]string, len(m.heldOpen))
	for t, c := range m.heldOpen {
		out[t] = c.String()
	}
	return out
}

// checkTable runs before the VRF name is created on table or adopted with
// members, and before anything is added or enslaved. It reports whether the
// table may end in the unreachable default.
//
// A table is checked when it ends in the unreachable default with the VRF
// on it: the VRF asks for the routes, or a tracked VRF on the table does.
// So a port enslaved into a VRF on a closed table is checked as a close is.
// The ports looked at are the same whichever VRF on the table comes first:
// those of every VRF device on the table now, the members every tracked VRF
// on it records (records), those the config declares for VRFs on it, and
// members. During the boot a table with an L2 headend circuit on one of
// them wants to stay open: nothing is added to it, and
// openHeldTablesLocked removes what Vinbero added. After the boot the call
// is refused.
func (m *ResourceManager) checkTable(records []ManagedVrf, name string, table uint32, members []string, noUnreachableDefault bool) (bool, error) {
	if m.tablesOpen {
		return false, nil
	}
	closes := !noUnreachableDefault
	ports := map[string]string{}
	for _, v := range records {
		if v.TableID != table {
			continue
		}
		closes = closes || (v.Name != name && !v.OptedOut())
		for _, p := range v.Members {
			ports[p] = v.Name
		}
	}
	if !closes {
		return false, nil
	}
	for _, d := range m.configDevices {
		if d.TableID == table {
			for _, p := range d.Members {
				ports[p] = d.Name
			}
		}
	}
	for _, p := range members {
		ports[p] = name
	}
	m.heldMu.Lock()
	_, wanted := m.wantOpen[table]
	running := m.running
	m.heldMu.Unlock()
	if wanted {
		return false, nil
	}
	if m.closeGuard == nil {
		return true, nil
	}
	c, err := m.closeGuard(table, ports)
	if err != nil {
		return false, fmt.Errorf("check table %d for L2 headend circuits: %w", table, err)
	}
	if c == nil {
		return true, nil
	}
	if running {
		return false, fmt.Errorf("table %d would end in the unreachable default and drop the encapsulations and BUM copies of the %s; "+
			"delete the circuit, or set no_unreachable_default on every VRF on the table", table, c)
	}
	m.heldMu.Lock()
	if m.wantOpen == nil {
		m.wantOpen = map[uint32]L2CircuitOnTable{}
	}
	m.wantOpen[table] = *c
	m.heldMu.Unlock()
	return false, nil
}

// openHeldTablesLocked removes the unreachable defaults Vinbero added to
// the tables the boot wants open, as SetTablesClosed(false) does for every
// table. A table counts as held open (TablesHeldOpen) only once it has no
// unreachable default left; then one warning names the table and the
// circuit. If a removal fails or another unreachable default is in the
// table, it counts as closed: an error is logged once, the records keep the
// routes they own, and the next call (the next create or adopt, or the next
// start) tries again. Callers hold m.mu.
func (m *ResourceManager) openHeldTablesLocked() {
	m.heldMu.Lock()
	want := map[uint32]L2CircuitOnTable{}
	for t, c := range m.wantOpen {
		if _, done := m.heldOpen[t]; !done {
			want[t] = c
		}
	}
	m.heldMu.Unlock()
	for table, c := range want {
		var failed error
		for i := range m.state.VRFs {
			v := &m.state.VRFs[i]
			if v.TableID != table || len(v.UnreachableDefaultAdded) == 0 {
				continue
			}
			var kept []string // the families whose removal failed
			for _, family := range v.UnreachableDefaultAdded {
				if err := m.removeUnreachableFamilies(table, []string{family}); err != nil {
					failed = err
					kept = append(kept, family)
				}
			}
			v.UnreachableDefaultAdded = kept
		}
		if failed == nil {
			failed = unreachableDefaultLeft(table)
		}
		fields := []zap.Field{zap.Uint32("table_id", table), zap.String("port", c.Port), zap.Uint16("vlan", c.VLAN),
			zap.String("vrf", c.VRF), zap.String("circuit", c.String())}
		m.heldMu.Lock()
		first := !m.openFailed[table]
		if failed == nil {
			if m.heldOpen == nil {
				m.heldOpen = map[uint32]L2CircuitOnTable{}
			}
			m.heldOpen[table] = c
		} else {
			if m.openFailed == nil {
				m.openFailed = map[uint32]bool{}
			}
			m.openFailed[table] = true
		}
		m.heldMu.Unlock()
		switch {
		case failed == nil:
			m.logger.Warn("VRF table left open, without the unreachable default: an L2 headend circuit is on one of its ports, "+
				"and the route would drop the circuit's encapsulations and BUM copies; delete the circuit and restart to close the table, "+
				"or set no_unreachable_default on every VRF on the table to keep it open", fields...)
		case first:
			m.logger.Error("cannot leave a VRF table open for an L2 headend circuit on one of its ports: its unreachable default "+
				"stays and drops the circuit's encapsulations and BUM copies; the next create on the table or the next start tries again",
				append(fields, zap.Error(failed))...)
		}
	}
}

// listTableRoutes lists a table's routes of one family; tests replace it.
var listTableRoutes = func(table uint32, family int) ([]netlink.Route, error) {
	return netlink.RouteListFiltered(family, &netlink.Route{Table: int(table)}, netlink.RT_FILTER_TABLE)
}

// dumpAttempts is how many times a route dump the kernel interrupted (a
// route changed while it ran) is tried.
const dumpAttempts = 5

// listTableRoutesRetried is listTableRoutes, tried again while the kernel
// interrupts the dump.
func listTableRoutesRetried(table uint32, family int) ([]netlink.Route, error) {
	var err error
	for range dumpAttempts {
		var routes []netlink.Route
		if routes, err = listTableRoutes(table, family); !errors.Is(err, netlink.ErrDumpInterrupted) {
			return routes, err
		}
	}
	return nil, err
}

// unreachableDefaultLeft returns an error when table still has an
// unreachable default route in either family.
func unreachableDefaultLeft(table uint32) error {
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := listTableRoutesRetried(table, family)
		if err != nil {
			if family == netlink.FAMILY_V6 && (errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EAFNOSUPPORT)) {
				continue // no IPv6 on the host
			}
			return fmt.Errorf("list the routes of table %d: %w", table, err)
		}
		for _, r := range routes {
			if r.Type != unix.RTN_UNREACHABLE {
				continue
			}
			if ones, _ := r.Dst.Mask.Size(); r.Dst == nil || ones == 0 {
				return fmt.Errorf("table %d still has an unreachable default (%s)", table, r.Dst)
			}
		}
	}
	return nil
}

// SetTablesClosed says whether VRF tables may be closed with the unreachable
// default. The data plane needs BPF_FIB_LOOKUP_TBID to look a tenant
// encapsulation's outer header up past a closed table; without it the tables
// stay open: nothing is added, and Reconcile gives back the routes a previous
// run added. Call it before Reconcile; the default is closed.
func (m *ResourceManager) SetTablesClosed(closed bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tablesOpen = !closed
}

// SetConfigUnreachableDefault records the config's no_unreachable_default
// for each VRF it declares with a kernel device, by name. Reconcile applies
// it to the state's records before it touches any table, so a setting in
// the config takes effect on the first start after it is written, over
// whatever the state file recorded. Call it before Reconcile.
func (m *ResourceManager) SetConfigUnreachableDefault(noUnreachableDefault map[string]bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.configNoUnreachable = noUnreachableDefault
}

// decideUnreachableLocked settles the record's unreachable-default setting
// at boot: the config's when it declares the VRF, else the recorded one,
// else (a record from before the setting existed) the default, which adds
// the routes. A record that now opts out releases the routes it added.
// Callers hold m.mu.
func (m *ResourceManager) decideUnreachableLocked(idx int) error {
	v := &m.state.VRFs[idx]
	no, declared := m.configNoUnreachable[v.Name]
	switch {
	case declared:
	case v.NoUnreachableDefault != nil:
		no = *v.NoUnreachableDefault
	default:
		no = false
	}
	if v.NoUnreachableDefault != nil && *v.NoUnreachableDefault != no {
		m.logger.Info("VRF unreachable-default setting changed by the config",
			zap.String("vrf", v.Name), zap.Bool("no_unreachable_default", no))
	}
	v.setNoUnreachableDefault(no)
	if no || m.tablesOpen {
		return m.releaseUnreachableLocked(idx)
	}
	return nil
}
