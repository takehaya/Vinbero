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

// ErrLocatorPrefixInUse is returned by Manager.Add when the requested
// prefix is already covered by another registered locator. Sharing a
// prefix across two names would produce SID collisions at the byte
// level, so the manager rejects it up front.
var ErrLocatorPrefixInUse = errors.New("locator: prefix already registered under another name")

// ErrLocatorNotFound is returned when an operation references an unknown
// locator name.
var ErrLocatorNotFound = errors.New("locator: not found")

// ErrLocatorInUse is returned by Manager.Delete when bindings still
// reference the locator and force=false.
var ErrLocatorInUse = errors.New("locator: still referenced by SID bindings")

// managerEntry groups a locator with its dedicated allocator so the two
// can never drift out of sync (e.g. allocator handed back for a name
// whose locator definition was just deleted). The manager only stores
// pointers to entries; the locator value is copied on registration so
// external mutation cannot reach the allocator state.
type managerEntry struct {
	loc   *Locator
	alloc FunctionAllocator
}

// Manager owns the runtime state of the locator subsystem: registered
// locators with their per-locator allocators, plus the SID binding
// table. It is the single object the RPC handler and the SidFunction
// handler talk to.
type Manager struct {
	mu       sync.RWMutex
	entries  map[string]*managerEntry
	bindings BindingTable
}

// NewManager returns a manager backed by an in-memory binding table.
func NewManager() *Manager {
	return &Manager{
		entries:  make(map[string]*managerEntry),
		bindings: NewBindingTable(),
	}
}

// Add registers a new locator. Returns ErrLocatorExists when the name is
// taken, ErrLocatorPrefixInUse when another locator already owns the
// prefix, and the underlying Validate error when the definition itself
// is malformed.
func (m *Manager) Add(loc *Locator) error {
	if err := loc.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.entries[loc.Name]; ok {
		return fmt.Errorf("%w: %q", ErrLocatorExists, loc.Name)
	}
	for _, e := range m.entries {
		if e.loc.Prefix == loc.Prefix {
			return fmt.Errorf("%w: %s already used by %q", ErrLocatorPrefixInUse, loc.Prefix, e.loc.Name)
		}
	}
	// Copy so external callers cannot mutate the registered definition
	// out from under the allocator.
	copyLoc := *loc
	m.entries[loc.Name] = &managerEntry{loc: &copyLoc, alloc: NewBitmapAllocator(&copyLoc)}
	return nil
}

// Delete removes a locator. With force=false the call fails if any
// bindings still reference it (returning ErrLocatorInUse). With
// force=true the manager only drops its own state; the caller is
// responsible for tearing down the upstream SIDs (sid_function_map
// entries) first.
func (m *Manager) Delete(name string, force bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.entries[name]; !ok {
		return fmt.Errorf("%w: %q", ErrLocatorNotFound, name)
	}
	if !force {
		if used := m.bindings.ListByLocator(name); len(used) > 0 {
			return fmt.Errorf("%w: %q has %d active bindings", ErrLocatorInUse, name, len(used))
		}
	}
	delete(m.entries, name)
	return nil
}

// Get returns a copy of the registered locator.
func (m *Manager) Get(name string) (Locator, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.entries[name]
	if !ok {
		return Locator{}, false
	}
	return *e.loc, true
}

// FindByContaining returns the registered locator whose Prefix covers addr,
// or ok=false when no locator owns it. Used at BGP advertise time to derive
// the SRv6 SID Structure Sub-Sub-TLV (RFC 9252 §3.2.1.1) for a SID that
// originated locally.
func (m *Manager) FindByContaining(addr netip.Addr) (Locator, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, e := range m.entries {
		if e.loc.Prefix.Contains(addr) {
			return *e.loc, true
		}
	}
	return Locator{}, false
}

// List returns a snapshot of every registered locator.
func (m *Manager) List() []Locator {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Locator, 0, len(m.entries))
	for _, e := range m.entries {
		out = append(out, *e.loc)
	}
	return out
}

// AllocateSID reserves a function in locatorName and returns the
// materialized SID together with the binding that the caller must keep
// alive until ReleaseSID is called. requested=nil triggers
// auto-allocation, otherwise the value is pinned manually.
func (m *Manager) AllocateSID(locatorName string, requested *uint32) (netip.Addr, Binding, error) {
	m.mu.RLock()
	e, ok := m.entries[locatorName]
	m.mu.RUnlock()
	if !ok {
		return netip.Addr{}, Binding{}, fmt.Errorf("%w: %q", ErrLocatorNotFound, locatorName)
	}
	fn, err := e.alloc.Allocate(requested)
	if err != nil {
		return netip.Addr{}, Binding{}, err
	}
	sid, err := e.loc.BuildSID(fn)
	if err != nil {
		e.alloc.Release(fn)
		return netip.Addr{}, Binding{}, err
	}
	b := Binding{LocatorName: locatorName, Function: fn}
	// Record cannot fail today (in-memory BindingTable). Phase 2 swaps in
	// a BPF-backed implementation whose write can fail, so the rollback
	// path is wired up now.
	if err := m.bindings.Record(sid, b); err != nil {
		e.alloc.Release(fn)
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
	e := m.entries[b.LocatorName]
	m.mu.RUnlock()
	if e != nil {
		e.alloc.Release(b.Function)
	}
}

// BindingOf returns the recorded (locator, function) for a sid, if any.
// Used by /vbctl sid list to render the locator origin of each entry.
func (m *Manager) BindingOf(sid netip.Addr) (Binding, bool) {
	return m.bindings.Lookup(sid)
}
