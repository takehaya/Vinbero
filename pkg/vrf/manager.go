// Package vrf is the first-class VRF object: one identity that owns a numeric
// vrf_id (the ingress classification / MUP F-TEID scope; 0 = the global/default
// VRF, i.e. the underlay), the ingress access-circuit membership
// ({interface, VLAN} that belong to the VRF), and the global default-deny
// policy. BGP (pkg/vrfbgp), MUP, EVPN and L3 are facets attached to a VRF by
// name; ingress classification is just the VRF's membership, not a separate
// concept. The manager owns the ingress_vrf_map (single writer) and programs
// it from every VRF's ACs on Reconcile.
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

// VRF is a routing/forwarding instance identity. ID is its data-plane id
// (ingress classification + MUP F-TEID scope). ACs is its ingress membership.
type VRF struct {
	Name string
	ID   uint32
	ACs  []AC
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

// clone returns a copy of v whose ACs slice shares no backing array with the
// stored VRF, so a caller mutating the returned ACs cannot corrupt internal
// state (or race a concurrent AddAC/RemoveAC that re-slices it).
func (v *VRF) clone() VRF {
	return VRF{Name: v.Name, ID: v.ID, ACs: append([]AC(nil), v.ACs...)}
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
	v := &VRF{Name: name, ID: m.allocIDLocked()}
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

// Delete removes a VRF and recycles its id. A no-op when absent.
func (m *Manager) Delete(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.byName[name]
	if !ok {
		return
	}
	delete(m.byName, name)
	delete(m.byID, v.ID)
	m.freeIDs = append(m.freeIDs, v.ID)
}

// List returns a snapshot of the VRFs sorted by name, each with ACs sorted by
// {interface, vlan} so output and tests are deterministic.
func (m *Manager) List() []VRF {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]VRF, 0, len(m.byName))
	for _, v := range m.byName {
		acs := append([]AC(nil), v.ACs...)
		sort.Slice(acs, func(i, j int) bool {
			if acs[i].Interface != acs[j].Interface {
				return acs[i].Interface < acs[j].Interface
			}
			return acs[i].VLAN < acs[j].VLAN
		})
		out = append(out, VRF{Name: v.Name, ID: v.ID, ACs: acs})
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
