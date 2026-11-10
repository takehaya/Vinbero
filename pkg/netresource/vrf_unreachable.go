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
// (ipv6.disable=1) gets the IPv4 route only, with one log line.
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
