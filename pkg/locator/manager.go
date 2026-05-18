package locator

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
)

// ErrLocatorExists is returned by Manager.Add when a locator name is
// already registered.
var ErrLocatorExists = errors.New("locator: already registered")

// ErrLocatorNotFound is returned when an operation references an unknown
// locator name.
var ErrLocatorNotFound = errors.New("locator: not found")

// ErrLocatorInUse is returned by Manager.Delete when bindings still
// reference the locator and force=false.
var ErrLocatorInUse = errors.New("locator: still referenced by SID bindings")

// Manager owns the runtime state of the locator subsystem: registered
// locators, their per-locator allocators, and the SID binding table. It
// is the single object the RPC handler and the SidFunction handler talk
// to.
type Manager struct {
	mu         sync.RWMutex
	locators   map[string]*Locator
	allocators map[string]FunctionAllocator
	bindings   BindingTable
}

// NewManager returns a manager backed by an in-memory binding table.
func NewManager() *Manager {
	return &Manager{
		locators:   make(map[string]*Locator),
		allocators: make(map[string]FunctionAllocator),
		bindings:   NewBindingTable(),
	}
}

// Add registers a new locator. Validation failures and duplicate names
// surface before the allocator is constructed so partial registrations
// never leak.
func (m *Manager) Add(loc *Locator) error {
	if err := loc.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.locators[loc.Name]; ok {
		return fmt.Errorf("%w: %q", ErrLocatorExists, loc.Name)
	}
	alloc, err := NewBitmapAllocator(loc)
	if err != nil {
		return err
	}
	// Copy so external callers cannot mutate the registered definition
	// out from under the allocator.
	copyLoc := *loc
	m.locators[loc.Name] = &copyLoc
	m.allocators[loc.Name] = alloc
	return nil
}

// Delete removes a locator. With force=false the call fails if any
// bindings still reference it (returning ErrLocatorInUse). With
// force=true the manager only drops its own state; the caller is
// responsible for tearing down the upstream SIDs first.
func (m *Manager) Delete(name string, force bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.locators[name]; !ok {
		return fmt.Errorf("%w: %q", ErrLocatorNotFound, name)
	}
	if !force {
		if used := m.bindings.ListByLocator(name); len(used) > 0 {
			return fmt.Errorf("%w: %q has %d active bindings", ErrLocatorInUse, name, len(used))
		}
	}
	delete(m.locators, name)
	delete(m.allocators, name)
	return nil
}

// Get returns a copy of the registered locator.
func (m *Manager) Get(name string) (Locator, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	loc, ok := m.locators[name]
	if !ok {
		return Locator{}, false
	}
	return *loc, true
}

// List returns a snapshot of every registered locator.
func (m *Manager) List() []Locator {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Locator, 0, len(m.locators))
	for _, loc := range m.locators {
		out = append(out, *loc)
	}
	return out
}

// AllocateSID reserves a function in locatorName and returns the
// materialized SID together with the binding that the caller must keep
// alive until ReleaseSID is called. requested=nil triggers
// auto-allocation, otherwise the value is pinned manually.
func (m *Manager) AllocateSID(locatorName string, requested *uint32) (netip.Addr, Binding, error) {
	m.mu.RLock()
	loc, ok := m.locators[locatorName]
	alloc := m.allocators[locatorName]
	m.mu.RUnlock()
	if !ok {
		return netip.Addr{}, Binding{}, fmt.Errorf("%w: %q", ErrLocatorNotFound, locatorName)
	}
	fn, err := alloc.Allocate(requested)
	if err != nil {
		return netip.Addr{}, Binding{}, err
	}
	sid, err := loc.BuildSID(fn)
	if err != nil {
		alloc.Release(fn)
		return netip.Addr{}, Binding{}, err
	}
	b := Binding{LocatorName: locatorName, Function: fn}
	if err := m.bindings.Record(sid, b); err != nil {
		alloc.Release(fn)
		return netip.Addr{}, Binding{}, fmt.Errorf("record binding: %w", err)
	}
	return sid, b, nil
}

// ReleaseSID returns the function value behind sid (if known) to the
// locator's allocator. Unknown sids (manual / direct-prefix SIDs that
// were never recorded) are silent no-ops so SidFunctionDelete can call
// this unconditionally.
func (m *Manager) ReleaseSID(sid netip.Addr) {
	b, ok := m.bindings.Forget(sid)
	if !ok {
		return
	}
	m.mu.RLock()
	alloc := m.allocators[b.LocatorName]
	m.mu.RUnlock()
	if alloc != nil {
		alloc.Release(b.Function)
	}
}

// BindingOf returns the recorded (locator, function) for a sid, if any.
// Used by /vbctl sid list to render the locator origin of each entry.
func (m *Manager) BindingOf(sid netip.Addr) (Binding, bool) {
	return m.bindings.Lookup(sid)
}
