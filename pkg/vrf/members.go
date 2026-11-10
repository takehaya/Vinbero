package vrf

import (
	"fmt"
	"slices"

	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
)

// LinkInfo is what the member and L2-circuit checks need of one interface.
type LinkInfo struct {
	Name    string
	Master  uint32 // ifindex of the master device, 0 for none
	XDP     bool   // an XDP program is attached
	VLANOf  uint32 // a VLAN subinterface: the parent's ifindex (0 otherwise)
	VLANID  uint16
	IsVrf   bool
	VrfName string
	// VrfTable is a VRF device's routing table (0 for other links).
	VrfTable uint32
}

// Links is one snapshot of the host's interfaces, by ifindex.
type Links map[uint32]LinkInfo

// SnapshotLinks reads every interface once.
func SnapshotLinks() (Links, error) {
	all, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("list links: %w", err)
	}
	out := make(Links, len(all))
	for _, l := range all {
		a := l.Attrs()
		info := LinkInfo{Name: a.Name, Master: uint32(a.MasterIndex)}
		if a.Xdp != nil && a.Xdp.Attached {
			info.XDP = true
		}
		if v, ok := l.(*netlink.Vlan); ok {
			info.VLANOf = uint32(a.ParentIndex)
			info.VLANID = uint16(v.VlanId)
		}
		if v, ok := l.(*netlink.Vrf); ok {
			info.IsVrf = true
			info.VrfTable = v.Table
		}
		out[uint32(a.Index)] = info
	}
	return out, nil
}

// SetTablesClosed says whether the managed VRF tables end in the
// unreachable default (the data plane can look tenant encapsulations up in
// the main table). The member and L2-circuit checks only matter when they
// do. The default is closed.
func (m *Manager) SetTablesClosed(closed bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tablesOpen = !closed
}

// TablesClosed reports whether the managed VRF tables end in the
// unreachable default (SetTablesClosed).
func (m *Manager) TablesClosed() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return !m.tablesOpen
}

// closedTablesLocked returns the tables that end in the unreachable default:
// a table some managed VRF on it did not opt out of. Closedness belongs to
// the table, not the VRF: a VRF that opted out but shares a table with one
// that did not is closed all the same. Callers hold m.mu.
func (m *Manager) closedTablesLocked() map[uint32]bool {
	out := map[uint32]bool{}
	if m.tablesOpen {
		return out
	}
	for _, v := range m.byName {
		if v.Device != nil && v.Device.TableID != 0 && !v.Device.NoUnreachableDefault {
			out[v.Device.TableID] = true
		}
	}
	return out
}

// closedVRFs returns the managed VRFs whose kernel device's table ends in
// the unreachable default (closedTablesLocked), by device ifindex.
func (m *Manager) closedVRFs() map[uint32]VRF {
	m.mu.RLock()
	closed := m.closedTablesLocked()
	m.mu.RUnlock()
	out := map[uint32]VRF{}
	if len(closed) == 0 {
		return out
	}
	for _, v := range m.List() {
		if v.Device != nil && v.Device.Ifindex != 0 && closed[v.Device.TableID] {
			out[v.Device.Ifindex] = v
		}
	}
	return out
}

// TableClosedAfterCreate reports whether table ends in the unreachable
// default once a VRF with this setting is created on it: it asks for the
// routes, or another managed VRF on the table has them.
func (m *Manager) TableClosedAfterCreate(table uint32, noUnreachableDefault bool) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.tablesOpen {
		return false
	}
	return !noUnreachableDefault || m.closedTablesLocked()[table]
}

// ClosedVRFOfPort returns the VRF device the port with this ifindex is
// enslaved to and whether that device's table is closed
// (closedTablesLocked). The device may be one Vinbero does not manage: its
// table is closed all the same when a managed VRF on it did not opt out.
func (m *Manager) ClosedVRFOfPort(links Links, ifindex uint32) (string, bool) {
	l, ok := links[ifindex]
	if !ok || l.Master == 0 {
		return "", false
	}
	master, ok := links[l.Master]
	if !ok || !master.IsVrf {
		return "", false
	}
	m.mu.RLock()
	closed := m.closedTablesLocked()[master.VrfTable]
	m.mu.RUnlock()
	return master.Name, closed
}

// TableClosed reports whether table ends in the unreachable default now.
func (m *Manager) TableClosed(table uint32) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.closedTablesLocked()[table]
}

// MemberWithoutAC is a port of a VRF's kernel device, attached to the data
// plane, whose packets are not classified to that VRF.
type MemberWithoutAC struct {
	VRF       string
	Interface string
	// AC is the access circuit that would cover it: {Interface, 0} for a
	// port XDP runs on, {parent, VLAN} for a VLAN subinterface of one.
	AC AC
}

// MembersWithoutAC returns, for every VRF whose table ends in the
// unreachable default, the member ports the data plane classifies to
// another VRF: a member XDP runs on without the AC {member, 0}, or a VLAN
// subinterface of a port XDP runs on without the AC {parent, VLAN}. Their
// packets are in the global VRF, so their encapsulation looks the outer
// header up on the port, which goes to the VRF table and stops at the
// unreachable default. Members XDP never sees (a dummy, a bridge, an SVI)
// are not reported. only, when set, limits the check to that VRF.
func (m *Manager) MembersWithoutAC(links Links, only string) []MemberWithoutAC {
	var out []MemberWithoutAC
	closed := m.closedVRFs()
	ifindexes := make([]uint32, 0, len(links))
	for i := range links {
		ifindexes = append(ifindexes, i)
	}
	slices.Sort(ifindexes)
	for _, i := range ifindexes {
		l := links[i]
		v, ok := closed[l.Master]
		if !ok || (only != "" && v.Name != only) {
			continue
		}
		var want AC
		switch {
		case l.XDP:
			want = AC{Interface: l.Name}
		case l.VLANOf != 0 && links[l.VLANOf].XDP:
			want = AC{Interface: links[l.VLANOf].Name, VLAN: l.VLANID}
		default:
			continue
		}
		if !slices.Contains(v.ACs, want) {
			out = append(out, MemberWithoutAC{VRF: v.Name, Interface: l.Name, AC: want})
		}
	}
	return out
}

// WarnMembersWithoutAC logs one warning per member reported by
// MembersWithoutAC.
func (m *Manager) WarnMembersWithoutAC(links Links, only string, lg *zap.Logger) {
	for _, f := range m.MembersWithoutAC(links, only) {
		lg.Warn("VRF member port is not an access circuit of its VRF: packets from it are in the global VRF, "+
			"and their encapsulation is dropped at the VRF table's unreachable default; "+
			"make the port an AC of the VRF (vbctl vrf ac-add / vrfs.entries[].acs) or opt the VRF out (no_unreachable_default)",
			zap.String("vrf", f.VRF), zap.String("interface", f.Interface),
			zap.String("ac_interface", f.AC.Interface), zap.Uint16("ac_vlan", f.AC.VLAN))
	}
}

// L2CircuitOnClosedVRF is an L2 headend circuit on a port of a VRF whose
// table ends in the unreachable default.
type L2CircuitOnClosedVRF struct {
	VRF       string
	Interface string
}

// L2CircuitsOnClosedVRFs returns the L2 circuit ports (by ifindex) that are
// enslaved to a VRF whose table ends in the unreachable default. Their
// encapsulations and BUM copies are looked up on the port, so in the VRF
// table, where they stop.
func (m *Manager) L2CircuitsOnClosedVRFs(links Links, circuitPorts []uint32) []L2CircuitOnClosedVRF {
	var out []L2CircuitOnClosedVRF
	seen := map[uint32]bool{}
	for _, p := range circuitPorts {
		if seen[p] {
			continue
		}
		seen[p] = true
		if name, ok := m.ClosedVRFOfPort(links, p); ok {
			out = append(out, L2CircuitOnClosedVRF{VRF: name, Interface: links[p].Name})
		}
	}
	return out
}

// WarnL2CircuitsOnClosedVRFs logs one warning per port reported by
// L2CircuitsOnClosedVRFs (ports enslaved outside Vinbero; Vinbero refuses
// to make such a port itself).
func (m *Manager) WarnL2CircuitsOnClosedVRFs(links Links, circuitPorts []uint32, lg *zap.Logger) {
	for _, c := range m.L2CircuitsOnClosedVRFs(links, circuitPorts) {
		lg.Warn("L2 headend circuit on a port of a VRF whose table ends in the unreachable default: its encapsulations "+
			"and BUM copies are looked up in the VRF table and dropped; move the circuit to a port in no VRF (or a bridge port), "+
			"or opt the VRF out (no_unreachable_default)",
			zap.String("vrf", c.VRF), zap.String("interface", c.Interface))
	}
}
