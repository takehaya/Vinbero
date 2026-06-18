// Package ingressvrf holds the ingress VRF front-door table: the
// {interface, VLAN} -> vrf_id classification that the XDP entry resolves once
// per packet. vrf_id 0 is the global/default VRF (underlay); tenant VRFs are
// 1..N. The manager keeps the operator-facing state keyed by interface NAME
// (ifindex is resolved at reconcile time, since it can change), plus the
// global default-deny policy, and programs the data-plane maps through a
// Programmer on Reconcile.
package ingressvrf

import (
	"fmt"
	"net"
	"sort"
	"sync"

	"github.com/takehaya/vinbero/pkg/bpf"
)

// DenyAction values mirror INGRESS_DENY_* in src/core/xdp_prog.h.
const (
	DenyActionDrop uint8 = 0
	DenyActionPass uint8 = 1
)

// Policy is the global ingress policy.
type Policy struct {
	DefaultDeny bool
	DenyAction  uint8
}

// Entry is one {interface, VLAN} -> vrf_id binding.
type Entry struct {
	Interface string
	VLAN      uint16
	VRFID     uint32
}

type acKey struct {
	iface string
	vlan  uint16
}

// Programmer is the data-plane surface the reconciler writes. *bpf.MapOperations
// satisfies it; tests use a fake.
type Programmer interface {
	SetIngressVrf(mapping map[bpf.IngressACKey]uint32) error
	SetIngressPolicy(enabled, defaultDeny bool, denyAction uint8) error
}

// Manager is the in-memory ingress VRF table + policy.
type Manager struct {
	mu      sync.RWMutex
	entries map[acKey]uint32 // {iface, vlan} -> vrf_id
	policy  Policy
}

// NewManager returns an empty manager (no entries, default-deny off).
func NewManager() *Manager {
	return &Manager{entries: make(map[acKey]uint32)}
}

// Bind registers (or replaces) the {iface, vlan} -> vrfID binding.
func (m *Manager) Bind(iface string, vlan uint16, vrfID uint32) error {
	if iface == "" {
		return fmt.Errorf("ingress vrf: interface is required")
	}
	if vlan > 4095 {
		return fmt.Errorf("ingress vrf: vlan %d out of range (0..4095)", vlan)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[acKey{iface, vlan}] = vrfID
	return nil
}

// Unbind removes the {iface, vlan} binding. A missing binding is not an error
// (idempotent unbind).
func (m *Manager) Unbind(iface string, vlan uint16) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.entries, acKey{iface, vlan})
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

// List returns a snapshot of the entries sorted by {interface, vlan} so the
// output (and any test) is deterministic.
func (m *Manager) List() []Entry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Entry, 0, len(m.entries))
	for k, vrf := range m.entries {
		out = append(out, Entry{Interface: k.iface, VLAN: k.vlan, VRFID: vrf})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Interface != out[j].Interface {
			return out[i].Interface < out[j].Interface
		}
		return out[i].VLAN < out[j].VLAN
	})
	return out
}

// enabled reports whether the data-plane front door should be active: any
// entry exists, or default-deny is on (so the entry-less default-deny posture
// still gates traffic).
func (m *Manager) enabled() bool {
	return len(m.entries) > 0 || m.policy.DefaultDeny
}

// Reconcile resolves every binding's interface name to an ifindex via resolve
// and programs prog (the ingress_vrf_map + the global policy, including the
// enabled gate). An interface that does not resolve is skipped with a logged
// warning by the caller's resolve func returning an error; such entries simply
// do not appear in the data plane until the next reconcile. Safe to call from
// RPC goroutines.
func (m *Manager) Reconcile(resolve func(string) (uint32, error), prog Programmer) error {
	m.mu.RLock()
	mapping := make(map[bpf.IngressACKey]uint32, len(m.entries))
	for k, vrf := range m.entries {
		idx, err := resolve(k.iface)
		if err != nil {
			m.mu.RUnlock()
			return fmt.Errorf("ingress vrf: resolve %q: %w", k.iface, err)
		}
		mapping[bpf.IngressACKey{Ifindex: idx, VlanId: k.vlan}] = vrf
	}
	pol := m.policy
	enabled := m.enabled()
	m.mu.RUnlock()

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
