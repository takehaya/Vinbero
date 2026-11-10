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

// ensureUnreachableDefault adds the unreachable defaults to the table of
// the VRF name, which is created or adopted with members, and returns the
// families whose route it added. The add never replaces a route: a default
// the operator put in the table at a better metric is a different route and
// stays the one lookups use, and a route already at this metric (the
// operator's own unreachable default, or one added before a restart) is
// kept as it is and not counted as added. A host without IPv6
// (ipv6.disable=1) gets the IPv4 route only, with one log line. Every route
// Vinbero adds goes through here, so the L2 circuit check (tableMayClose)
// cannot be skipped.
func (m *ResourceManager) ensureUnreachableDefault(name string, tableID uint32, members []string) ([]string, error) {
	if m.tablesOpen {
		return nil, nil
	}
	if ok, err := m.tableMayClose(name, tableID, members); err != nil || !ok {
		return nil, err
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
// on the table (managed by Vinbero or not), of the VRF device vrf, or on
// one of members, the ports vrf is to enslave.
type TableCloseGuard func(vrf string, table uint32, members []string) (*L2CircuitOnTable, error)

// SetTableCloseGuard installs the L2 circuit check every unreachable
// default goes through. Call it before Reconcile.
func (m *ResourceManager) SetTableCloseGuard(g TableCloseGuard) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closeGuard = g
}

// FinishBoot ends the boot: from then on a create or adopt that would close
// a table under an L2 headend circuit is refused. During the boot, where
// nothing can be refused, the table is held open instead (tableMayClose).
func (m *ResourceManager) FinishBoot() {
	m.heldMu.Lock()
	defer m.heldMu.Unlock()
	m.running = true
}

// TablesHeldOpen returns the tables the boot left open for an L2 headend
// circuit, each with that circuit.
func (m *ResourceManager) TablesHeldOpen() map[uint32]string {
	m.heldMu.Lock()
	defer m.heldMu.Unlock()
	out := make(map[uint32]string, len(m.heldOpen))
	for t, c := range m.heldOpen {
		out[t] = c.String()
	}
	return out
}

// tableMayClose reports whether table may get the unreachable default for
// the VRF name created or adopted with members. A table the boot holds open
// may not, until the next start. Otherwise the guard looks for an L2
// headend circuit the routes would cut off. During the boot such a table is
// held open: one warning names it, the routes Vinbero added to it are
// removed (openHeldTablesLocked) and the daemon goes on. After the boot the
// create is refused. Callers may hold m.mu.
func (m *ResourceManager) tableMayClose(name string, table uint32, members []string) (bool, error) {
	m.heldMu.Lock()
	_, held := m.heldOpen[table]
	running := m.running
	m.heldMu.Unlock()
	if held {
		return false, nil
	}
	if m.closeGuard == nil {
		return true, nil
	}
	c, err := m.closeGuard(name, table, members)
	if err != nil {
		return false, fmt.Errorf("check table %d for L2 headend circuits: %w", table, err)
	}
	if c == nil {
		return true, nil
	}
	if running {
		return false, fmt.Errorf("table %d would end in the unreachable default and drop the encapsulations and BUM copies of the %s; "+
			"delete the circuit, or set no_unreachable_default on the VRF", table, c)
	}
	m.heldMu.Lock()
	if m.heldOpen == nil {
		m.heldOpen = map[uint32]L2CircuitOnTable{}
	}
	m.heldOpen[table] = *c
	m.heldMu.Unlock()
	m.logger.Warn("VRF table left open, without the unreachable default: an L2 headend circuit is on one of its ports, "+
		"and the route would drop the circuit's encapsulations and BUM copies; delete the circuit and restart to close the table, "+
		"or set no_unreachable_default on every VRF on the table to keep it open",
		zap.Uint32("table_id", table), zap.String("port", c.Port), zap.Uint16("vlan", c.VLAN), zap.String("vrf", c.VRF),
		zap.String("circuit", c.String()))
	return false, nil
}

// openHeldTablesLocked removes the unreachable defaults Vinbero added to a
// table the boot holds open, as SetTablesClosed(false) does for every
// table. Callers hold m.mu.
func (m *ResourceManager) openHeldTablesLocked() {
	m.heldMu.Lock()
	held := make(map[uint32]bool, len(m.heldOpen))
	for t := range m.heldOpen {
		held[t] = true
	}
	m.heldMu.Unlock()
	for i := range m.state.VRFs {
		v := &m.state.VRFs[i]
		if !held[v.TableID] || len(v.UnreachableDefaultAdded) == 0 {
			continue
		}
		if err := m.removeUnreachableFamilies(v.TableID, v.UnreachableDefaultAdded); err != nil {
			continue // logged there; the record keeps them, and the next start retries
		}
		v.UnreachableDefaultAdded = nil
	}
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
