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
	"errors"
	"fmt"
	"math"
	"slices"
	"sort"
	"sync"

	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
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
// is filled by the mechanics layer at create/adopt time. ConfigMembers are
// the members the config file declares for this bridge (set through
// SetConfigBridgeMembers); the config enslaves them again on every start,
// so RemoveBridgeMember refuses them.
type Bridge struct {
	Name          string
	BdID          uint16
	Members       []string
	Ifindex       uint32
	ConfigMembers []string
}

// ErrConfigMember: the bridge member is declared in the config file.
var ErrConfigMember = errors.New("bridge member is declared in the config file")

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

// Manager owns the VRF objects, the id allocator (monotonic; 0 reserved for the
// global VRF), the global policy, and the ingress_vrf_map programming.
type Manager struct {
	mu     sync.RWMutex
	byName map[string]*VRF
	byID   map[uint32]string
	nextID uint32
	policy Policy
	// runtimeACs are the ACs added over the API that have resolved at least
	// once (MarkRuntimeAC). Unlike config-declared ACs, one whose interface
	// disappears is skipped by Reconcile, and they are what Save persists.
	runtimeACs map[runtimeACKey]struct{}
	logger     *zap.Logger
	// store receives the persistent state on Save; nil until SetStore. dirty
	// says the state changed since the last successful Save, guarded by mu.
	// saveMu spans the snapshot and the write so an older snapshot cannot
	// overwrite a newer one.
	store  StateStore
	dirty  bool
	saveMu sync.Mutex
	// unsavedDeletes are the VRFs deleted since the last successful Save, so
	// a retried delete can tell "already deleted, not yet saved" from an
	// unknown name. Guarded by mu.
	unsavedDeletes map[string]struct{}
	// configOrigin are the VRFs the boot-time load created (the config, or a
	// device or bridge record) rather than the API. FinishRestore drops one
	// the config no longer declares once nothing holds it. Guarded by mu.
	configOrigin map[string]struct{}
	// restored are the names Restore loaded; FinishRestore clears it and
	// sets restoreDone. Guarded by mu.
	restored    map[string]struct{}
	restoreDone bool
	// goneMu guards goneACs, the runtime ACs Reconcile has already warned
	// about, so a stale AC is reported once rather than on every reconcile.
	goneMu  sync.Mutex
	goneACs map[runtimeACKey]struct{}
}

type runtimeACKey struct {
	vrf string
	ac  AC
}

// NewManager returns an empty manager. The global VRF (id 0) is implicit.
func NewManager() *Manager {
	return &Manager{
		byName: make(map[string]*VRF),
		byID:   make(map[uint32]string),
		nextID: 1,

		runtimeACs: make(map[runtimeACKey]struct{}),
		logger:     zap.NewNop(),

		unsavedDeletes: make(map[string]struct{}),
		configOrigin:   make(map[string]struct{}),
		goneACs:        make(map[runtimeACKey]struct{}),
	}
}

// SetLogger sets the logger Reconcile warns through. Call it before the
// manager is shared.
func (m *Manager) SetLogger(logger *zap.Logger) {
	m.logger = logger
}

// MaxNextID is the highest allocator watermark (next_vrf_id). Ids are handed
// out below it, so the counter never wraps onto the global VRF's id 0, and
// Restore refuses a saved watermark above it.
const MaxNextID uint32 = math.MaxUint32 - 1

// ErrIDsExhausted: every vrf_id below MaxNextID has been handed out.
var ErrIDsExhausted = errors.New("vrf: no vrf_id left to allocate")

// allocIDLocked returns a fresh vrf_id (>= 1). An id is never handed out twice,
// not even after its VRF is deleted: state keyed by a vrf_id can outlive the
// VRF, and a reused id would point that state at another tenant. Once the
// watermark reaches MaxNextID it refuses rather than wrapping.
func (m *Manager) allocIDLocked() (uint32, error) {
	if m.nextID >= MaxNextID {
		return 0, ErrIDsExhausted
	}
	id := m.nextID
	m.nextID++
	return id, nil
}

// allocatableLocked reports why name could not get a VRF, nil when it already
// has one or an id is left. Callers check it before a netlink call that would
// otherwise create a device no VRF can carry.
func (m *Manager) allocatableLocked(name string) error {
	if _, ok := m.byName[name]; ok || name == GlobalVRFName || m.nextID < MaxNextID {
		return nil
	}
	return fmt.Errorf("vrf %q: %w", name, ErrIDsExhausted)
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
		b.ConfigMembers = append([]string(nil), v.Bridge.ConfigMembers...)
		out.Bridge = &b
	}
	return out
}

// Ensure returns the VRF for name, creating it (allocating an id) if absent.
// Facets (a BGP binding, MUP uplink) call this so a referenced VRF always has
// a stable id even before any AC is configured. The returned VRF's ACs are a
// copy (see clone). It fails only when a new VRF finds no id left.
func (m *Manager) Ensure(name string) (VRF, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, err := m.ensureLocked(name)
	if err != nil {
		return VRF{}, err
	}
	return v.clone(), nil
}

func (m *Manager) ensureLocked(name string) (*VRF, error) {
	if v, ok := m.byName[name]; ok {
		return v, nil
	}
	// The reserved global VRF keeps id 0; everything else allocates 1..N.
	id := GlobalVRFID
	if name != GlobalVRFName {
		var err error
		if id, err = m.allocIDLocked(); err != nil {
			return nil, fmt.Errorf("vrf %q: %w", name, err)
		}
	}
	v := &VRF{Name: name, ID: id}
	m.byName[name] = v
	m.byID[v.ID] = name
	delete(m.unsavedDeletes, name)
	m.dirty = true
	return v, nil
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
	v, err := m.ensureLocked(name)
	if err != nil {
		return false, err
	}
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
	if _, ok := m.runtimeACs[runtimeACKey{name, ac}]; ok {
		delete(m.runtimeACs, runtimeACKey{name, ac})
		m.dirty = true
	}
	m.goneMu.Lock()
	delete(m.goneACs, runtimeACKey{name, ac})
	m.goneMu.Unlock()
	return removed
}

// MarkRuntimeAC records that an AC added over the API has resolved: a pod veth
// behind such an AC can vanish before its owner removes the AC, and that must
// not fail every other VRF's reconcile. Config-declared ACs are never marked.
func (m *Manager) MarkRuntimeAC(name string, ac AC) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.runtimeACs[runtimeACKey{name, ac}] = struct{}{}
	m.dirty = true
}

// IsRuntimeAC reports whether MarkRuntimeAC recorded the AC.
func (m *Manager) IsRuntimeAC(name string, ac AC) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.runtimeACs[runtimeACKey{name, ac}]
	return ok
}

// Delete removes a VRF. A no-op when absent. Its id is not used again.
func (m *Manager) Delete(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.byName[name]
	if !ok {
		return
	}
	delete(m.byName, name)
	delete(m.byID, v.ID)
	for _, ac := range v.ACs {
		delete(m.runtimeACs, runtimeACKey{name, ac})
	}
	delete(m.configOrigin, name)
	m.unsavedDeletes[name] = struct{}{}
	m.dirty = true
}

// UnsavedDelete reports whether name was deleted and the deletion has not been
// saved yet. A retried delete uses it to save instead of reporting an unknown
// VRF.
func (m *Manager) UnsavedDelete(name string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.unsavedDeletes[name]
	return ok
}

// PersistedVRF is what survives a restart of one VRF object: its identity and
// the ACs added over the API. The other facets have their own records.
type PersistedVRF struct {
	Name       string
	ID         uint32
	RuntimeACs []AC
	// Config: the boot-time load created the VRF, not the API (see
	// FinishRestore).
	Config bool
}

// State is the persistent part of the Manager.
type State struct {
	NextID uint32
	VRFs   []PersistedVRF
}

// StateStore keeps the Manager's State across restarts.
// *netresource.ResourceManager satisfies it; tests use a fake.
type StateStore interface {
	SaveVRFState(State) error
}

// SetStore sets where Save writes. Set it after the boot-time load, so a
// deployment with an unwritable state directory still starts.
func (m *Manager) SetStore(store StateStore) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.store = store
}

// Save writes the state if it changed since the last successful Save. Without
// a store it does nothing. A failed Save leaves the state in memory and dirty,
// so the next Save writes all of it.
func (m *Manager) Save() error {
	m.saveMu.Lock()
	defer m.saveMu.Unlock()
	m.mu.Lock()
	store := m.store
	if store == nil {
		// No file, so no deletion is missing from one.
		clear(m.unsavedDeletes)
	}
	if store == nil || !m.dirty {
		m.mu.Unlock()
		return nil
	}
	state := m.stateLocked()
	deleted := make([]string, 0, len(m.unsavedDeletes))
	for name := range m.unsavedDeletes {
		deleted = append(deleted, name)
	}
	m.dirty = false
	m.mu.Unlock()

	if err := store.SaveVRFState(state); err != nil {
		m.mu.Lock()
		m.dirty = true
		m.mu.Unlock()
		return fmt.Errorf("save vrf state: %w", err)
	}
	m.mu.Lock()
	for _, name := range deleted {
		delete(m.unsavedDeletes, name)
	}
	m.mu.Unlock()
	return nil
}

// TrySave is Save for a caller whose own result does not depend on the state
// file. A failure is logged; the state stays dirty and the next successful
// Save writes it.
func (m *Manager) TrySave() {
	if err := m.Save(); err != nil {
		m.logger.Warn("VRF state not saved; the next successful save writes it, a restart before that loses the change", zap.Error(err))
	}
}

// stateLocked snapshots the persistent state, sorted so equal states encode
// the same way.
func (m *Manager) stateLocked() State {
	s := State{NextID: m.nextID, VRFs: make([]PersistedVRF, 0, len(m.byName))}
	for _, v := range m.byName {
		_, config := m.configOrigin[v.Name]
		p := PersistedVRF{Name: v.Name, ID: v.ID, Config: config}
		for _, ac := range v.ACs {
			if _, ok := m.runtimeACs[runtimeACKey{v.Name, ac}]; ok {
				p.RuntimeACs = append(p.RuntimeACs, ac)
			}
		}
		sortACs(p.RuntimeACs)
		s.VRFs = append(s.VRFs, p)
	}
	sort.Slice(s.VRFs, func(i, j int) bool { return s.VRFs[i].Name < s.VRFs[j].Name })
	return s
}

// Restore loads a saved state into an empty Manager. It runs before anything
// can allocate an id. A state that breaks the Manager's invariants is refused
// rather than repaired: guessing would put an AC or an id in the wrong tenant.
// That includes a saved id at or above NextID, which the allocator would hand
// out again. The zero State (nothing saved yet) is valid.
func (m *Manager) Restore(s State) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.byName) != 0 || m.restoreDone {
		return errors.New("vrf: Restore needs an empty manager")
	}
	names := make(map[string]struct{}, len(s.VRFs))
	ids := make(map[uint32]string, len(s.VRFs))
	owners := make(map[AC]string)
	for _, p := range s.VRFs {
		if p.Name == "" {
			return errors.New("vrf: saved state has a VRF without a name")
		}
		if (p.Name == GlobalVRFName) != (p.ID == GlobalVRFID) {
			return fmt.Errorf("vrf %q: saved id %d: id %d belongs to the %q VRF only", p.Name, p.ID, GlobalVRFID, GlobalVRFName)
		}
		if _, dup := names[p.Name]; dup {
			return fmt.Errorf("vrf %q: saved twice", p.Name)
		}
		names[p.Name] = struct{}{}
		if other, dup := ids[p.ID]; dup {
			return fmt.Errorf("vrf %q: saved id %d is also held by vrf %q", p.Name, p.ID, other)
		}
		ids[p.ID] = p.Name
		for _, ac := range p.RuntimeACs {
			if ac.Interface == "" || ac.VLAN > 4095 {
				return fmt.Errorf("vrf %q: saved ac {interface %q, vlan %d} is invalid", p.Name, ac.Interface, ac.VLAN)
			}
			if other, dup := owners[ac]; dup {
				return fmt.Errorf("vrf %q: saved ac {interface %q, vlan %d} is also held by vrf %q", p.Name, ac.Interface, ac.VLAN, other)
			}
			owners[ac] = p.Name
		}
	}
	if s.NextID > MaxNextID {
		return fmt.Errorf("vrf: saved next_vrf_id %d is above the highest watermark %d", s.NextID, MaxNextID)
	}
	for _, p := range s.VRFs {
		if p.ID >= s.NextID {
			return fmt.Errorf("vrf %q: saved id %d is not below next_vrf_id %d, so it could be handed out again", p.Name, p.ID, s.NextID)
		}
	}
	m.restored = make(map[string]struct{}, len(s.VRFs))
	for _, p := range s.VRFs {
		m.byName[p.Name] = &VRF{Name: p.Name, ID: p.ID, ACs: slices.Clone(p.RuntimeACs)}
		m.byID[p.ID] = p.Name
		for _, ac := range p.RuntimeACs {
			m.runtimeACs[runtimeACKey{p.Name, ac}] = struct{}{}
		}
		if p.Config {
			m.configOrigin[p.Name] = struct{}{}
		}
		m.restored[p.Name] = struct{}{}
	}
	m.nextID = max(s.NextID, 1)
	return nil
}

// FinishRestore ends the boot-time load. declared are the VRF names the
// config declares (vrfs.entries and bgp.vrf_bindings). Every VRF the load
// created, and every declared one, is marked as config-origin. A restored
// config-origin VRF that is no longer declared and holds no AC, device or
// bridge is dropped and its id stays retired: nothing refers to it any more,
// and keeping it would bring it back on every boot. A VRF created over the API
// stays until it is deleted. It returns the dropped names. Only the first call
// does anything.
func (m *Manager) FinishRestore(declared []string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.restoreDone {
		return nil
	}
	decl := make(map[string]struct{}, len(declared))
	for _, name := range declared {
		decl[name] = struct{}{}
	}
	var dropped []string
	for name, v := range m.byName {
		_, wasRestored := m.restored[name]
		_, isConfig := m.configOrigin[name]
		_, isDeclared := decl[name]
		if wasRestored && isConfig && !isDeclared && len(v.ACs) == 0 && v.Device == nil && v.Bridge == nil {
			delete(m.byName, name)
			delete(m.byID, v.ID)
			delete(m.configOrigin, name)
			m.dirty = true
			dropped = append(dropped, name)
			continue
		}
		if !isConfig && (!wasRestored || isDeclared) {
			m.configOrigin[name] = struct{}{}
			m.dirty = true
		}
	}
	m.restored = nil
	m.restoreDone = true
	sort.Strings(dropped)
	return dropped
}

// RestoreDone reports whether FinishRestore ran: the VRF objects, with every
// facet the boot-time load gives them, are in place.
func (m *Manager) RestoreDone() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.restoreDone
}

// ReleaseRuntimeAC drops the runtime record of ac under whichever VRF holds
// it, and reports that VRF. The config uses it to take an AC over: from then
// on the AC is config-declared, so an interface that does not resolve is an
// error again, and it can move to the VRF the config names.
func (m *Manager) ReleaseRuntimeAC(ac AC) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for key := range m.runtimeACs {
		if key.ac != ac {
			continue
		}
		delete(m.runtimeACs, key)
		v := m.byName[key.vrf]
		v.ACs = slices.DeleteFunc(v.ACs, func(a AC) bool { return a == ac })
		m.dirty = true
		return key.vrf, true
	}
	return "", false
}

func sortACs(acs []AC) {
	sort.Slice(acs, func(i, j int) bool {
		if acs[i].Interface != acs[j].Interface {
			return acs[i].Interface < acs[j].Interface
		}
		return acs[i].VLAN < acs[j].VLAN
	})
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
	v, err := m.ensureLocked(name)
	if err != nil {
		return VRF{}, err
	}
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
	m.mu.RLock()
	err := m.allocatableLocked(name)
	m.mu.RUnlock()
	if err != nil {
		return VRF{}, err
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
	// AddBridgeMember / RemoveBridgeMember enslave and release one port of
	// an existing bridge; both are idempotent.
	AddBridgeMember(bridge, member string) error
	RemoveBridgeMember(bridge, member string) error
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
			if other.Bridge.BdID != b.BdID {
				// A re-attach must not change the bd under an attached facet:
				// the EVPN exporter keys its per-BD state (advertised RT2s,
				// the DT2U/DT2M SIDs) by the bd, so a silent change would
				// strand the old bd's advertisements. The mechanics layer
				// rejects this via its state record too; this keeps the
				// invariant self-contained in the facet model.
				return fmt.Errorf("vrf %q: bridge %q is attached with bd_id %d; detach it before changing the bd (got %d)", name, b.Name, other.Bridge.BdID, b.BdID)
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
	v, err := m.ensureLocked(name)
	if err != nil {
		return VRF{}, err
	}
	bb := b
	bb.Members = append([]string(nil), b.Members...)
	bb.ConfigMembers = append([]string(nil), b.ConfigMembers...)
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
	if err == nil {
		err = m.allocatableLocked(name)
	}
	m.mu.RUnlock()
	if err != nil {
		return VRF{}, err
	}
	ifindex, err := ops.CreateBridge(b.Name, b.BdID, b.Members, name)
	if err != nil {
		return VRF{}, fmt.Errorf("vrf %q: create bridge: %w", name, err)
	}
	b.Ifindex = ifindex
	// A re-attach keeps the members the bridge already has (the kernel
	// bridge keeps them too, and its state record is the union).
	// It keeps the config's claim on its members too.
	if cur, ok := m.Get(name); ok && cur.Bridge != nil && cur.Bridge.Name == b.Name {
		members := cur.Bridge.Members
		for _, mb := range b.Members {
			if !slices.Contains(members, mb) {
				members = append(members, mb)
			}
		}
		b.Members = members
		b.ConfigMembers = cur.Bridge.ConfigMembers
	}
	return m.SetBridge(name, b)
}

// SetConfigBridgeMembers records the members the config file declares for
// the VRF's bridge, replacing what an earlier apply recorded. The claim is
// tied to that bridge: it is dropped with the facet on detach, and a
// different bridge attached later carries none.
func (m *Manager) SetConfigBridgeMembers(name, bridge string, members []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.byName[name]
	if !ok || v.Bridge == nil || v.Bridge.Name != bridge {
		return fmt.Errorf("vrf %q carries no bridge %q", name, bridge)
	}
	v.Bridge.ConfigMembers = append([]string(nil), members...)
	return nil
}

// AddBridgeMember enslaves one port to the VRF's attached bridge through ops
// and adds it to the facet's members. Adding a current member is a no-op
// apart from the (idempotent) ops call.
func (m *Manager) AddBridgeMember(name, member string, ops BridgeOps) (VRF, error) {
	return m.changeBridgeMember(name, member, true, ops)
}

// RemoveBridgeMember releases one port from the VRF's attached bridge
// through ops and removes it from the facet's members.
func (m *Manager) RemoveBridgeMember(name, member string, ops BridgeOps) (VRF, error) {
	return m.changeBridgeMember(name, member, false, ops)
}

// changeBridgeMember runs ops outside m.mu, like AttachBridge; VrfServer.mu
// serializes facet mutations, so the facet read before the call is still
// the one updated after it.
func (m *Manager) changeBridgeMember(name, member string, add bool, ops BridgeOps) (VRF, error) {
	if member == "" {
		return VRF{}, fmt.Errorf("vrf %q: member interface name is required", name)
	}
	v, ok := m.Get(name)
	if !ok {
		return VRF{}, fmt.Errorf("unknown VRF %q", name)
	}
	if v.Bridge == nil {
		return VRF{}, fmt.Errorf("vrf %q carries no bridge facet", name)
	}
	if v.Bridge.Name == member {
		return VRF{}, fmt.Errorf("vrf %q: bridge %q cannot be its own member", name, member)
	}
	if !add && slices.Contains(v.Bridge.ConfigMembers, member) {
		return VRF{}, fmt.Errorf("%w: %s is in vrfs.entries[].bridge.members of vrf %q and is enslaved to %s again on every start; remove it there and restart",
			ErrConfigMember, member, name, v.Bridge.Name)
	}
	if add {
		if err := ops.AddBridgeMember(v.Bridge.Name, member); err != nil {
			return VRF{}, fmt.Errorf("vrf %q: add bridge member: %w", name, err)
		}
	} else if err := ops.RemoveBridgeMember(v.Bridge.Name, member); err != nil {
		return VRF{}, fmt.Errorf("vrf %q: remove bridge member: %w", name, err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.byName[name]
	if !ok || cur.Bridge == nil {
		return VRF{}, fmt.Errorf("vrf %q lost its bridge facet during the member change", name)
	}
	switch has := slices.Contains(cur.Bridge.Members, member); {
	case add && !has:
		cur.Bridge.Members = append(slices.Clone(cur.Bridge.Members), member)
	case !add && has:
		cur.Bridge.Members = slices.DeleteFunc(slices.Clone(cur.Bridge.Members), func(n string) bool { return n == member })
	}
	return cur.clone(), nil
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
		sortACs(c.ACs)
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
		// runtime marks the ACs a vanished interface does not make fatal.
		runtime map[AC]bool
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
		runtime := make(map[AC]bool)
		for _, ac := range v.ACs {
			if _, ok := m.runtimeACs[runtimeACKey{v.Name, ac}]; ok {
				runtime[ac] = true
			}
		}
		snaps = append(snaps, vrfSnapshot{name: v.Name, id: v.ID, acs: append([]AC(nil), v.ACs...), runtime: runtime})
	}
	pol := m.policy
	enabled := m.enabledLocked()
	m.mu.RUnlock()

	mapping := make(map[bpf.IngressACKey]uint32)
	for _, s := range snaps {
		for _, ac := range s.acs {
			idx, err := resolve(ac.Interface)
			if errors.Is(err, ErrInterfaceGone) && s.runtime[ac] {
				if m.noteGone(runtimeACKey{s.name, ac}, true) {
					m.logger.Warn("Skipping AC whose interface is gone until it is removed (vbctl vrf ac-remove)",
						zap.String("vrf", s.name), zap.String("interface", ac.Interface), zap.Uint16("vlan", ac.VLAN))
				}
				continue
			}
			if err != nil {
				return fmt.Errorf("vrf %q: resolve %q: %w", s.name, ac.Interface, err)
			}
			m.noteGone(runtimeACKey{s.name, ac}, false)
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

// noteGone records whether a runtime AC's interface is gone and reports
// whether that is news, so Reconcile warns once per disappearance.
func (m *Manager) noteGone(key runtimeACKey, gone bool) bool {
	m.goneMu.Lock()
	defer m.goneMu.Unlock()
	_, known := m.goneACs[key]
	if gone {
		m.goneACs[key] = struct{}{}
	} else {
		delete(m.goneACs, key)
	}
	return gone && !known
}

// ResolveByName is the production interface-name resolver (net.InterfaceByName).
func ResolveByName(name string) (uint32, error) {
	l, err := netlink.LinkByName(name)
	if errors.As(err, &netlink.LinkNotFoundError{}) {
		return 0, fmt.Errorf("%w: %s", ErrInterfaceGone, name)
	}
	if err != nil {
		return 0, err
	}
	return uint32(l.Attrs().Index), nil
}

// ErrInterfaceGone: no interface has the name (ResolveByName). Other resolve
// failures say nothing about whether the interface exists.
var ErrInterfaceGone = errors.New("no such interface")
