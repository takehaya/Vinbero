// Package vrf is the first-class VRF object: one identity that owns a numeric
// vrf_id (the ingress classification / MUP F-TEID scope; 0 = the global/default
// VRF, i.e. the underlay), the ingress access-circuit membership
// ({interface, VLAN} that belong to the VRF), the optional kernel-device facet
// (the Linux VRF device End.DT4/DT6/DT46 deliver into), and the global
// default-deny policy. BGP (pkg/vrfbgp), MUP and EVPN are facets attached to a
// VRF by name; ingress classification is just the VRF's membership, not a
// separate concept. The manager owns the ingress_vrf_map (single writer,
// programmed from every VRF's ACs on Reconcile) and drives the kernel device
// lifecycle through DeviceOps (netlink + persistence stay in pkg/netresource,
// the mechanics layer).
package vrf

import (
	"fmt"
	"net"
	"slices"
	"sort"
	"sync"

	"github.com/takehaya/vinbero/pkg/bpf"
)

// DenyAction values mirror INGRESS_DENY_* in src/core/xdp_prog.h.
const (
	DenyActionDrop uint8 = 0
	DenyActionPass uint8 = 1
)

// GlobalVRFID is the reserved id of the global/default VRF (the underlay).
// Named VRFs are allocated 1..N. A packet whose AC is unmapped resolves to it
// (or is dropped under default-deny).
const GlobalVRFID uint32 = 0

// GlobalVRFName is the reserved VRF name that maps to GlobalVRFID. The global/
// underlay VRF is a real (reserved) VRF: adding an ingress AC to it programs an
// explicit {ifindex, vlan} -> 0 entry, which under default-deny lets the
// underlay / control-plane interfaces through (an unmapped AC is dropped). It
// is reserved — a tenant VRF cannot take this name, and it is never assigned a
// non-zero id.
const GlobalVRFName = "global"

// Policy is the global ingress policy.
type Policy struct {
	DefaultDeny bool
	DenyAction  uint8
}

// AC is one ingress access circuit: {interface, VLAN} (VLAN 0 = untagged).
type AC struct {
	Interface string
	VLAN      uint16
}

// Device is the kernel-device facet of a VRF: the Linux VRF device (and its
// routing table) that End.DT4/DT6/DT46 deliver decapsulated traffic into.
// Ifindex is filled by the mechanics layer at create/adopt time.
type Device struct {
	TableID          uint32
	Members          []string
	EnableL3mdevRule bool
	Ifindex          uint32
}

// Bridge is the L2 bridge-domain facet of a VRF: the Linux bridge End.DT2 /
// End.DT2M deliver decapsulated frames into, plus the bd_id that scopes its
// FDB and EVPN advertisements. The device name may differ from the VRF name
// (an EVI named "evi-100" typically carries a bridge named "br100"). Ifindex
// is filled by the mechanics layer at create/adopt time.
type Bridge struct {
	Name    string
	BdID    uint16
	Members []string
	Ifindex uint32
}

// VRF is a routing/forwarding instance identity. ID is its data-plane id
// (ingress classification + MUP F-TEID scope). ACs is its ingress membership.
// Device is the kernel-device facet and Bridge the L2 bridge-domain facet;
// either may be nil (e.g. a MUP gateway VRF that only classifies ingress, or
// an L2-only EVI without an L3 table).
type VRF struct {
	Name   string
	ID     uint32
	ACs    []AC
	Device *Device
	Bridge *Bridge
}

// Manager owns the VRF objects, the id allocator (free list; 0 reserved for the
// global VRF), the global policy, and the ingress_vrf_map programming.
type Manager struct {
	mu      sync.RWMutex
	byName  map[string]*VRF
	byID    map[uint32]string
	freeIDs []uint32
	nextID  uint32
	policy  Policy
}

// NewManager returns an empty manager. The global VRF (id 0) is implicit.
func NewManager() *Manager {
	return &Manager{
		byName: make(map[string]*VRF),
		byID:   make(map[uint32]string),
		nextID: 1,
	}
}

// allocIDLocked returns a recycled or fresh vrf_id (>= 1). Deleted ids are
// recycled via the free list, so nextID only advances for genuinely-new VRFs.
// Wraparound of the uint32 counter is not guarded: reaching it needs ~4 billion
// concurrently-live VRFs (deletes recycle), which exhausts the byName map's
// memory — and the data-plane ingress_vrf_map (4096 entries) — long before the
// counter could overflow.
func (m *Manager) allocIDLocked() uint32 {
	if n := len(m.freeIDs); n > 0 {
		id := m.freeIDs[n-1]
		m.freeIDs = m.freeIDs[:n-1]
		return id
	}
	id := m.nextID
	m.nextID++
	return id
}

// clone returns a copy of v that shares no mutable backing storage with the
// stored VRF (the ACs slice, the Device / Bridge structs and their Members
// slices), so a caller mutating the returned value cannot corrupt internal
// state (or race a concurrent mutation that re-slices it).
func (v *VRF) clone() VRF {
	out := VRF{Name: v.Name, ID: v.ID, ACs: append([]AC(nil), v.ACs...)}
	if v.Device != nil {
		d := *v.Device
		d.Members = append([]string(nil), v.Device.Members...)
		out.Device = &d
	}
	if v.Bridge != nil {
		b := *v.Bridge
		b.Members = append([]string(nil), v.Bridge.Members...)
		out.Bridge = &b
	}
	return out
}

// Ensure returns the VRF for name, creating it (allocating an id) if absent.
// Facets (a BGP binding, MUP uplink) call this so a referenced VRF always has
// a stable id even before any AC is configured. The returned VRF's ACs are a
// copy (see clone).
func (m *Manager) Ensure(name string) VRF {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ensureLocked(name).clone()
}

func (m *Manager) ensureLocked(name string) *VRF {
	if v, ok := m.byName[name]; ok {
		return v
	}
	// The reserved global VRF keeps id 0; everything else allocates 1..N.
	id := GlobalVRFID
	if name != GlobalVRFName {
		id = m.allocIDLocked()
	}
	v := &VRF{Name: name, ID: id}
	m.byName[name] = v
	m.byID[v.ID] = name
	return v
}

// IDForName returns the vrf_id assigned to name. ok=false when no VRF by that
// name exists (the caller should treat that as the global VRF / id 0).
func (m *Manager) IDForName(name string) (uint32, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if v, ok := m.byName[name]; ok {
		return v.ID, true
	}
	return GlobalVRFID, false
}

// ByID returns the VRF holding id. The returned VRF's ACs are a copy (see clone).
func (m *Manager) ByID(id uint32) (VRF, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	name, ok := m.byID[id]
	if !ok {
		return VRF{}, false
	}
	return m.byName[name].clone(), true
}

// Get returns the VRF for name without creating it. The delete flow uses it
// to read the device facet and the AC membership in one atomic snapshot.
func (m *Manager) Get(name string) (VRF, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.byName[name]
	if !ok {
		return VRF{}, false
	}
	return v.clone(), true
}

// AddAC adds an ingress access circuit to a VRF (creating the VRF if absent).
// An AC belongs to exactly one VRF: adding one already owned by a different VRF
// is rejected here, the only mutation entry point, so the {ifindex, vlan} ->
// vrf_id map Reconcile programs can never have a colliding key (which would
// otherwise resolve by map-iteration order and flap classification).
//
// added reports whether this call actually appended the AC: false (with a nil
// error) means it was already present (idempotent no-op). Callers that roll
// back on a later failure must undo only when added is true, or an idempotent
// re-add whose reconcile fails would remove a pre-existing AC.
func (m *Manager) AddAC(name string, ac AC) (added bool, err error) {
	if name == "" {
		return false, fmt.Errorf("vrf: name is required")
	}
	if ac.Interface == "" {
		return false, fmt.Errorf("vrf: ac interface is required")
	}
	if ac.VLAN > 4095 {
		return false, fmt.Errorf("vrf: ac vlan %d out of range (0..4095)", ac.VLAN)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, other := range m.byName {
		if other.Name == name {
			continue
		}
		if slices.Contains(other.ACs, ac) {
			return false, fmt.Errorf("vrf %q: ac {interface %q, vlan %d} already belongs to vrf %q",
				name, ac.Interface, ac.VLAN, other.Name)
		}
	}
	v := m.ensureLocked(name)
	for _, e := range v.ACs {
		if e == ac {
			return false, nil // idempotent: already present, nothing added
		}
	}
	v.ACs = append(v.ACs, ac)
	return true, nil
}

// RemoveAC removes an ingress access circuit from a VRF and reports whether it
// actually removed one (idempotent: false when the VRF or AC was already
// absent). Callers that roll back on a later failure must re-add only when
// removed is true, or an idempotent no-op whose reconcile fails would create an
// AC that never existed.
func (m *Manager) RemoveAC(name string, ac AC) (removed bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.byName[name]
	if !ok {
		return false
	}
	out := v.ACs[:0]
	for _, e := range v.ACs {
		if e != ac {
			out = append(out, e)
		} else {
			removed = true
		}
	}
	v.ACs = out
	return removed
}

// Delete removes a VRF and recycles its id. A no-op when absent. The reserved
// global VRF's id (0) is never recycled — it must never be handed to a tenant.
func (m *Manager) Delete(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.byName[name]
	if !ok {
		return
	}
	delete(m.byName, name)
	delete(m.byID, v.ID)
	if v.ID != GlobalVRFID {
		m.freeIDs = append(m.freeIDs, v.ID)
	}
}

// DeviceOps is the kernel mechanics + persistence surface the device facet is
// driven through (netlink device create/delete plus the JSON state file that
// recreates devices across restarts). *netresource.ResourceManager satisfies
// it; tests use a fake. Like Reconcile's resolve/prog, ops is passed per call
// rather than stored so NewManager stays dependency-free.
type DeviceOps interface {
	CreateVrf(name string, tableID uint32, members []string, enableL3mdevRule bool) (uint32, error)
	DeleteVrf(name string) error
}

// validateDeviceName rejects the names a kernel-device facet may never carry:
// the reserved global VRF is the main table (no device), and an empty name
// cannot address a netlink device.
func validateDeviceName(name string) error {
	if name == "" {
		return fmt.Errorf("vrf: name is required")
	}
	if name == GlobalVRFName {
		return fmt.Errorf("vrf: the reserved global VRF is the main table and cannot carry a kernel device")
	}
	return nil
}

// SetDevice attaches (or replaces) the kernel-device facet on a VRF, creating
// the VRF if absent. Pure state: no netlink happens here — boot seeding uses
// it to mirror devices the mechanics layer already reconciled from its state
// file. The stored Device shares no backing storage with d.
func (m *Manager) SetDevice(name string, d Device) (VRF, error) {
	if err := validateDeviceName(name); err != nil {
		return VRF{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	v := m.ensureLocked(name)
	dd := d
	dd.Members = append([]string(nil), d.Members...)
	v.Device = &dd
	return v.clone(), nil
}

// CreateDevice creates (or adopts) the kernel VRF device through ops and
// attaches the facet with the resulting ifindex. The netlink call runs before
// any identity is allocated and outside m.mu (the same rule as Reconcile's
// resolve: netlink can block and must not stall other mutations), so an ops
// failure leaves the manager untouched. Callers serialize concurrent device
// mutations (VrfServer.mu); the manager lock alone does not order two
// CreateDevice calls' netlink phases.
func (m *Manager) CreateDevice(name string, d Device, ops DeviceOps) (VRF, error) {
	if err := validateDeviceName(name); err != nil {
		return VRF{}, err
	}
	if d.TableID == 0 {
		return VRF{}, fmt.Errorf("vrf %q: device table_id is required", name)
	}
	ifindex, err := ops.CreateVrf(name, d.TableID, d.Members, d.EnableL3mdevRule)
	if err != nil {
		return VRF{}, fmt.Errorf("vrf %q: create device: %w", name, err)
	}
	d.Ifindex = ifindex
	return m.SetDevice(name, d)
}

// BridgeOps is the kernel mechanics + persistence surface the bridge facet is
// driven through (netlink bridge create/delete plus the JSON state file that
// recreates bridges across restarts and records the owning VRF).
// *netresource.ResourceManager satisfies it; tests use a fake. Passed per call
// like DeviceOps.
type BridgeOps interface {
	CreateBridge(name string, bdID uint16, members []string, ownerVRF string) (uint32, error)
	DeleteBridge(name string) error
}

// validateBridgeFacet rejects what an L2 facet may never carry: the reserved
// global VRF (the underlay has no bridge domain), an empty VRF name, an empty
// device name, and bd_id 0 (the data-plane sentinel for "no BD").
func validateBridgeFacet(name string, b Bridge) error {
	if name == "" {
		return fmt.Errorf("vrf: name is required")
	}
	if name == GlobalVRFName {
		return fmt.Errorf("vrf: the reserved global VRF is the underlay and cannot carry a bridge domain")
	}
	if b.Name == "" {
		return fmt.Errorf("vrf %q: bridge device name is required", name)
	}
	if b.BdID == 0 {
		return fmt.Errorf("vrf %q: bridge bd_id must be 1..65535 (0 = no BD)", name)
	}
	return nil
}

// bridgeConflictLocked reports the uniqueness violations an L2 facet must
// never create: a bridge device or a bd_id belongs to exactly one VRF (a
// duplicate bd_id would make the EVPN binding-axis resolution ambiguous — the
// pre-facet code failed closed on it; the facet model prevents it up front),
// and one VRF carries at most one bridge (1 binding = 1 BD).
func (m *Manager) bridgeConflictLocked(name string, b Bridge) error {
	for _, other := range m.byName {
		if other.Bridge == nil {
			continue
		}
		if other.Name == name {
			if other.Bridge.Name != b.Name {
				return fmt.Errorf("vrf %q already carries bridge %q; detach it first", name, other.Bridge.Name)
			}
			continue
		}
		if other.Bridge.Name == b.Name {
			return fmt.Errorf("vrf %q: bridge %q already belongs to vrf %q", name, b.Name, other.Name)
		}
		if other.Bridge.BdID == b.BdID {
			return fmt.Errorf("vrf %q: bd_id %d already belongs to vrf %q (bridge %q)", name, b.BdID, other.Name, other.Bridge.Name)
		}
	}
	return nil
}

// SetBridge attaches (or replaces) the L2 bridge-domain facet on a VRF,
// creating the VRF if absent. Pure state: no netlink happens here — boot
// seeding uses it to mirror bridges the mechanics layer already reconciled
// from its state file. The stored Bridge shares no backing storage with b.
func (m *Manager) SetBridge(name string, b Bridge) (VRF, error) {
	if err := validateBridgeFacet(name, b); err != nil {
		return VRF{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.bridgeConflictLocked(name, b); err != nil {
		return VRF{}, err
	}
	v := m.ensureLocked(name)
	bb := b
	bb.Members = append([]string(nil), b.Members...)
	v.Bridge = &bb
	return v.clone(), nil
}

// AttachBridge creates (or adopts) the kernel bridge through ops and attaches
// the facet with the resulting ifindex. Validation and the uniqueness
// pre-check run BEFORE the netlink call so a rejected attach creates no
// device; ops runs outside m.mu (CreateDevice's rule). The uniqueness
// re-check inside SetBridge cannot fail in practice because VrfServer.mu
// serializes all facet mutations; if it ever did, CreateBridge's
// adopt-idempotency makes the attach retryable.
func (m *Manager) AttachBridge(name string, b Bridge, ops BridgeOps) (VRF, error) {
	if err := validateBridgeFacet(name, b); err != nil {
		return VRF{}, err
	}
	m.mu.RLock()
	err := m.bridgeConflictLocked(name, b)
	m.mu.RUnlock()
	if err != nil {
		return VRF{}, err
	}
	ifindex, err := ops.CreateBridge(b.Name, b.BdID, b.Members, name)
	if err != nil {
		return VRF{}, fmt.Errorf("vrf %q: create bridge: %w", name, err)
	}
	b.Ifindex = ifindex
	return m.SetBridge(name, b)
}

// RemoveBridge clears the L2 facet and reports whether one was attached
// (idempotent). Pure state: the caller tears the kernel bridge down through
// BridgeOps first (device teardown before identity removal).
func (m *Manager) RemoveBridge(name string) (removed bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.byName[name]
	if !ok || v.Bridge == nil {
		return false
	}
	v.Bridge = nil
	return true
}

// List returns a snapshot of the VRFs (both facets) sorted by name, each with
// ACs sorted by {interface, vlan} so output and tests are deterministic.
func (m *Manager) List() []VRF {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]VRF, 0, len(m.byName))
	for _, v := range m.byName {
		c := v.clone()
		sort.Slice(c.ACs, func(i, j int) bool {
			if c.ACs[i].Interface != c.ACs[j].Interface {
				return c.ACs[i].Interface < c.ACs[j].Interface
			}
			return c.ACs[i].VLAN < c.ACs[j].VLAN
		})
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// SetPolicy replaces the global ingress policy.
func (m *Manager) SetPolicy(p Policy) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.policy = p
}

// Policy returns the current global policy.
func (m *Manager) Policy() Policy {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.policy
}

// Programmer is the data-plane surface the reconciler writes. *bpf.MapOperations
// satisfies it; tests use a fake.
type Programmer interface {
	SetIngressVrf(mapping map[bpf.IngressACKey]uint32) error
	SetIngressPolicy(enabled, defaultDeny bool, denyAction uint8) error
}

// enabledLocked reports whether the data-plane front door should be active:
// any VRF has an AC, or default-deny is on.
func (m *Manager) enabledLocked() bool {
	if m.policy.DefaultDeny {
		return true
	}
	for _, v := range m.byName {
		if len(v.ACs) > 0 {
			return true
		}
	}
	return false
}

// Reconcile resolves every VRF's AC interface names to ifindexes and programs
// ingress_vrf_map ({ifindex, vlan} -> vrf_id) plus the global policy. As the
// single owner of ingress_vrf_map it does a full make-before-break replace
// without colliding with other writers. An unresolvable interface is fatal so
// a misconfigured AC surfaces rather than silently disappearing.
func (m *Manager) Reconcile(resolve func(string) (uint32, error), prog Programmer) error {
	// Snapshot the VRFs (in name order), their ACs, and the policy under the
	// read lock, then release it before resolving interface names. resolve is
	// net.InterfaceByName in production — a netlink/sysfs call that can block —
	// and holding the lock across it would stall AddAC / RemoveAC / SetPolicy
	// writers. Name order makes a duplicate-key error name the same pair every
	// time (map iteration order is otherwise random).
	type vrfSnapshot struct {
		name string
		id   uint32
		acs  []AC
	}
	m.mu.RLock()
	names := make([]string, 0, len(m.byName))
	for name := range m.byName {
		names = append(names, name)
	}
	sort.Strings(names)
	snaps := make([]vrfSnapshot, 0, len(names))
	for _, name := range names {
		v := m.byName[name]
		snaps = append(snaps, vrfSnapshot{name: v.Name, id: v.ID, acs: append([]AC(nil), v.ACs...)})
	}
	pol := m.policy
	enabled := m.enabledLocked()
	m.mu.RUnlock()

	mapping := make(map[bpf.IngressACKey]uint32)
	for _, s := range snaps {
		for _, ac := range s.acs {
			idx, err := resolve(ac.Interface)
			if err != nil {
				return fmt.Errorf("vrf %q: resolve %q: %w", s.name, ac.Interface, err)
			}
			// AddAC blocks the same {interface, vlan} across VRFs, but two
			// distinct interface names can still resolve to one ifindex; surface
			// that as a fatal config error rather than letting classification
			// depend on iteration order.
			key := bpf.IngressACKey{Ifindex: idx, VlanId: ac.VLAN}
			if owner, dup := mapping[key]; dup && owner != s.id {
				return fmt.Errorf("vrf %q: ingress {ifindex %d, vlan %d} already claimed by vrf_id %d (two interfaces resolve to the same ifindex)",
					s.name, idx, ac.VLAN, owner)
			}
			mapping[key] = s.id
		}
	}

	if err := prog.SetIngressVrf(mapping); err != nil {
		return err
	}
	return prog.SetIngressPolicy(enabled, pol.DefaultDeny, pol.DenyAction)
}

// ResolveByName is the production interface-name resolver (net.InterfaceByName).
func ResolveByName(name string) (uint32, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return uint32(ifi.Index), nil
}
