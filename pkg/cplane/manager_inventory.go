package cplane

import (
	"fmt"

	"github.com/takehaya/vinbero/pkg/bpf"
)

// Called under registerMu. No guest is instantiated: all cleanup surfaces know
// their owner independently of executable WASM or a currently granted scope.
func (m *Manager) unregisterUnrestored(name string) error {
	m.unrestoredMu.Lock()
	_, held := m.unrestored[name]
	m.unrestoredMu.Unlock()
	if !held {
		return fmt.Errorf("cplane: %w: %q", ErrPluginNotRegistered, name)
	}
	ops, err := NewPluginOps(PluginOpsConfig{
		Owner: bpf.OwnerPluginBundle(name), HeadendReconciler: m.headend,
		Advertise: m.advertise, LocalSIDs: m.localSIDs, Leases: m.leases,
		ApplyMutex: &m.applyMu,
	})
	if err != nil {
		return err
	}
	if err := ops.Flush(); err != nil {
		return fmt.Errorf("cplane: flush unrestored plugin %q: %w", name, err)
	}
	if err := m.store.Remove(name); err != nil {
		return err
	}
	if m.claims != nil {
		m.claims.Release(name)
	}
	m.clearUnrestored(name)
	return nil
}
