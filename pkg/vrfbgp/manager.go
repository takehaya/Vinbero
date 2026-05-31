// Package vrfbgp holds VRF <-> BGP route-target bindings. The RPC handler
// (pkg/server) and the BGP route applier (pkg/bgp/apply) share one
// Manager so a received route's route targets can be resolved to a VRF
// consistently.
package vrfbgp

import (
	"errors"
	"fmt"
	"slices"
	"sync"
)

// ErrEmptyVRFName is returned by Bind when the binding has no VRF name.
var ErrEmptyVRFName = errors.New("vrfbgp: vrf_name must be non-empty")

// ErrBindingNotFound is returned by Unbind for an unknown VRF.
var ErrBindingNotFound = errors.New("vrfbgp: binding not found")

// Binding is one VRF's BGP route-target policy.
type Binding struct {
	VRFName string
	// RD is the route distinguisher this VRF advertises its local prefixes
	// under (RFC 4364). It is empty for receive-only bindings; the auto
	// advertise path (pkg/bgp/export) requires it to be non-empty before it
	// will export a prefix, so a binding without an RD simply never exports.
	RD        string
	ImportRTs []string
	ExportRTs []string
	// Redistribute lists the route protocols ("connected" / "static") whose
	// VRF-local prefixes the auto-advertise path (pkg/bgp/export) exports.
	// Empty means the binding is receive-only.
	Redistribute []string
	// MaxPrefixes caps how many prefixes the auto-advertise path originates for
	// this VRF (0 = unlimited). It bounds the blast radius of a misbehaving or
	// hostile VRF-route writer flooding the VPN.
	MaxPrefixes    uint32
	DefaultLocator string
	// BDID is the bridge domain a received EVPN route (RT2/3/4) installs
	// into when its route targets match ImportRTs. It is 0 for L3VPN-only
	// bindings; EVPN reception requires a non-zero BDID.
	BDID uint16
}

// Manager holds VRF<->RT bindings. Safe for concurrent use.
type Manager struct {
	mu       sync.RWMutex
	bindings map[string]Binding
}

// NewManager returns an empty Manager.
func NewManager() *Manager {
	return &Manager{bindings: make(map[string]Binding)}
}

// Bind registers (or replaces) the binding for b.VRFName.
func (m *Manager) Bind(b Binding) error {
	if b.VRFName == "" {
		return ErrEmptyVRFName
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bindings[b.VRFName] = b
	return nil
}

// Unbind removes the binding for vrfName.
func (m *Manager) Unbind(vrfName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.bindings[vrfName]; !ok {
		return fmt.Errorf("%w: %q", ErrBindingNotFound, vrfName)
	}
	delete(m.bindings, vrfName)
	return nil
}

// Get returns the binding for vrfName and ok=false if none is registered.
func (m *Manager) Get(vrfName string) (Binding, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	b, ok := m.bindings[vrfName]
	return b, ok
}

// GetByBDID returns the binding whose BDID matches bdID, for the EVPN
// auto-advertise path to resolve a bridge domain back to its binding. bdID 0
// (L3VPN-only bindings) never matches.
func (m *Manager) GetByBDID(bdID uint16) (Binding, bool) {
	if bdID == 0 {
		return Binding{}, false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, b := range m.bindings {
		if b.BDID == bdID {
			return b, true
		}
	}
	return Binding{}, false
}

// List returns a snapshot of every binding.
func (m *Manager) List() []Binding {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Binding, 0, len(m.bindings))
	for _, b := range m.bindings {
		out = append(out, b)
	}
	return out
}

// MatchImport returns the name of the VRF whose import_rts contains any
// of rts. ok=false means no registered VRF imports the route, so the
// caller should drop it.
func (m *Manager) MatchImport(rts []string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, b := range m.bindings {
		for _, want := range b.ImportRTs {
			if slices.Contains(rts, want) {
				return b.VRFName, true
			}
		}
	}
	return "", false
}

// MatchImportBD returns the bridge domain of the EVPN binding whose
// import_rts contain any of rts. ok=false means no binding with a
// non-zero BDID imports the route, so the EVPN applier drops it (an EVPN
// route can only install into an explicitly bound bridge domain).
func (m *Manager) MatchImportBD(rts []string) (uint16, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, b := range m.bindings {
		if b.BDID == 0 {
			continue
		}
		for _, want := range b.ImportRTs {
			if slices.Contains(rts, want) {
				return b.BDID, true
			}
		}
	}
	return 0, false
}

// Empty reports whether no bindings are registered. This accept-all fallback
// is for the L3VPN receive path only: the applier treats an empty Manager as
// "accept every route" so VPNv4/VPNv6 works before any VrfBgpBind call, and
// import_rts filtering takes effect once a binding exists. EVPN does NOT use
// this -- MatchImportBD always requires a non-zero-BDID binding, so an EVPN
// route is dropped until its bridge domain is explicitly bound (there is no
// bridge domain to install into otherwise).
func (m *Manager) Empty() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.bindings) == 0
}
