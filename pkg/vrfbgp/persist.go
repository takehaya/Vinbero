package vrfbgp

import (
	"errors"
	"fmt"
	"slices"
	"sort"
)

// BindingStore keeps the bindings made over the API across restarts. The
// daemon's adapter over the resource manager's state file satisfies it; tests
// use a fake. SaveBindings gets every saved binding, ordered by VRF name, and
// must leave the previous record in place when it fails.
type BindingStore interface {
	SaveBindings([]Binding) error
}

// SetStore sets where the saves write. Set it once the boot-time load is
// done; without a store nothing is saved.
func (m *Manager) SetStore(store BindingStore) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.store = store
}

// SetConfigDeclared records the VRF names the config file binds. Their
// bindings belong to the config: a change made over the API applies until the
// next start, which binds them from the config again, so they are never
// saved. Set it at boot, before any save.
func (m *Manager) SetConfigDeclared(names []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.configDeclared = make(map[string]struct{}, len(names))
	for _, name := range names {
		m.configDeclared[name] = struct{}{}
	}
}

// ConfigDeclared reports whether the config file binds vrfName.
func (m *Manager) ConfigDeclared(vrfName string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.configDeclared[vrfName]
	return ok
}

// Restored reports whether the binding of vrfName came back from the state
// file at boot (Restore).
func (m *Manager) Restored(vrfName string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.restored[vrfName]
	return ok
}

// Restore puts the saved bindings back, as they were saved: they are not
// normalized again, so the legacy route-target lists keep their order. It
// runs at boot, before the bindings are shared. A record that could not have
// been saved (no name, a name twice or already bound, an unknown family or
// direction, legacy lists that disagree with the families) is refused rather
// than repaired, like the rest of the state file. Route-target strings are
// not checked: the API stores some unchecked, and refusing them would stop
// a start the previous run accepted. Each binding's VRF is Ensured, as Bind
// does.
func (m *Manager) Restore(bindings []Binding) error {
	seen := make(map[string]struct{}, len(bindings))
	out := make([]Binding, 0, len(bindings))
	for _, b := range bindings {
		if b.VRFName == "" {
			return errors.New("vrfbgp: saved binding without a vrf_name")
		}
		if _, dup := seen[b.VRFName]; dup {
			return fmt.Errorf("vrfbgp: binding of vrf %q saved twice", b.VRFName)
		}
		seen[b.VRFName] = struct{}{}
		r, err := restorable(b)
		if err != nil {
			return fmt.Errorf("vrfbgp: saved binding of vrf %q: %w", b.VRFName, err)
		}
		out = append(out, r)
	}
	m.mu.RLock()
	for _, b := range out {
		if _, bound := m.bindings[b.VRFName]; bound {
			m.mu.RUnlock()
			return fmt.Errorf("vrfbgp: saved binding of vrf %q: the vrf is already bound", b.VRFName)
		}
	}
	m.mu.RUnlock()
	for _, b := range out {
		if _, err := m.vrf.Ensure(b.VRFName); err != nil {
			return fmt.Errorf("vrfbgp: saved binding of vrf %q: %w", b.VRFName, err)
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, b := range out {
		m.bindings[b.VRFName] = b
		m.restored[b.VRFName] = struct{}{}
	}
	return nil
}

// restorable checks one saved binding and returns it as Bind would have
// stored it.
func restorable(b Binding) (Binding, error) {
	for fam, fp := range b.Families {
		if err := ValidateFamily(string(fam)); err != nil {
			return Binding{}, err
		}
		for _, rt := range fp.RouteTargets {
			if d := rt.Direction; d != DirectionImport && d != DirectionExport && d != DirectionBoth {
				return Binding{}, fmt.Errorf("family %q rt %q: invalid direction", fam, rt.RT)
			}
		}
	}
	n := b.Normalize()
	if b.Families == nil {
		// Families derived from the legacy lists, as for any Bind of them.
		return n, nil
	}
	if !sameSet(n.ImportRTs, b.ImportRTs) || !sameSet(n.ExportRTs, b.ExportRTs) {
		return Binding{}, errors.New("import_rts / export_rts disagree with the route targets of its families")
	}
	n.ImportRTs = slices.Clone(b.ImportRTs)
	n.ExportRTs = slices.Clone(b.ExportRTs)
	return n, nil
}

func sameSet(a, b []string) bool {
	as, bs := slices.Clone(a), slices.Clone(b)
	slices.Sort(as)
	slices.Sort(bs)
	return slices.Equal(slices.Compact(as), slices.Compact(bs))
}

// Save writes every binding the config file does not declare.
func (m *Manager) Save() error {
	return m.save(nil)
}

// SaveWith writes the bindings as they will be once b is bound, before it is:
// a caller that publishes b only after this succeeds never has a binding in
// use that the state file does not hold. The VRF state is saved first, so a
// saved binding's VRF keeps its vrf_id. b's VRF must exist (Ensure). A binding
// the config file declares is not written.
func (m *Manager) SaveWith(b Binding) error {
	if b.VRFName == "" {
		return ErrEmptyVRFName
	}
	if m.ConfigDeclared(b.VRFName) {
		return nil
	}
	if err := m.vrf.Save(); err != nil {
		return err
	}
	b = b.Normalize()
	return m.save(func(set map[string]Binding) { set[b.VRFName] = b })
}

// SaveWithout writes the bindings as they will be once vrfName is unbound,
// before it is, so a binding removed from the state file is never left in
// use. A binding the config file declares is not in the file, so nothing is
// written.
func (m *Manager) SaveWithout(vrfName string) error {
	if m.ConfigDeclared(vrfName) {
		return nil
	}
	return m.save(func(set map[string]Binding) { delete(set, vrfName) })
}

// save snapshots the bindings, lets edit change the snapshot, and writes the
// ones the config file does not declare, ordered by name.
func (m *Manager) save(edit func(map[string]Binding)) error {
	m.saveMu.Lock()
	defer m.saveMu.Unlock()
	m.mu.RLock()
	store := m.store
	if store == nil {
		m.mu.RUnlock()
		return nil
	}
	set := make(map[string]Binding, len(m.bindings))
	for name, b := range m.bindings {
		set[name] = b
	}
	declared := m.configDeclared
	m.mu.RUnlock()
	if edit != nil {
		edit(set)
	}
	out := make([]Binding, 0, len(set))
	for name, b := range set {
		if _, ok := declared[name]; !ok {
			out = append(out, b)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].VRFName < out[j].VRFName })
	if err := store.SaveBindings(out); err != nil {
		return fmt.Errorf("save vrf bindings: %w", err)
	}
	return nil
}
