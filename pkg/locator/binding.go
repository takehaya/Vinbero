package locator

import (
	"net/netip"
	"sync"
)

// Binding records which (locator, function) pair minted a given SID, so
// SidFunctionDelete can return the function to the allocator. Phase 1
// stores bindings in memory only; daemon restart loses them and the
// operator is expected to re-create locators and SIDs via the control
// plane. Phase 2 persists them through a BPF map (see plan §6-13).
type Binding struct {
	LocatorName string
	Function    uint32
}

// ListAll returns every recorded sid. Reserved for Phase 2 persistence
// recovery (rebuild allocator bitmaps from the materialized bindings
// after daemon restart). Implementation lives on the concrete type so
// the interface stays minimal; callers go through *Manager.

// BindingTable is the lookup surface used by the SID delete path. Safe
// for concurrent use.
type BindingTable interface {
	Record(sid netip.Addr, b Binding) error
	Lookup(sid netip.Addr) (Binding, bool)
	Forget(sid netip.Addr) (Binding, bool)
	// ListByLocator returns every binding minted from locatorName. Used
	// by the LocatorDelete dependency check.
	ListByLocator(locatorName string) []netip.Addr
}

type inMemoryBindings struct {
	mu       sync.RWMutex
	bindings map[netip.Addr]Binding
}

// NewBindingTable returns an in-memory BindingTable.
func NewBindingTable() BindingTable {
	return &inMemoryBindings{bindings: make(map[netip.Addr]Binding)}
}

func (b *inMemoryBindings) Record(sid netip.Addr, binding Binding) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.bindings[sid] = binding
	return nil
}

func (b *inMemoryBindings) Lookup(sid netip.Addr) (Binding, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	v, ok := b.bindings[sid]
	return v, ok
}

func (b *inMemoryBindings) Forget(sid netip.Addr) (Binding, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	v, ok := b.bindings[sid]
	if !ok {
		return Binding{}, false
	}
	delete(b.bindings, sid)
	return v, true
}

func (b *inMemoryBindings) ListByLocator(locatorName string) []netip.Addr {
	b.mu.RLock()
	defer b.mu.RUnlock()
	var out []netip.Addr
	for sid, binding := range b.bindings {
		if binding.LocatorName == locatorName {
			out = append(out, sid)
		}
	}
	return out
}
