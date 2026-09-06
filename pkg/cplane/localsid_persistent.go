package cplane

import (
	"fmt"
	"sort"

	"github.com/takehaya/vinbero/pkg/bpf"
)

func (l *LocalSIDSet) enablePersistence(store *Store) error {
	if store == nil {
		return nil
	}
	records, err := store.sids.load()
	if err != nil {
		return err
	}
	alloc, ok := l.alloc.(PersistentSIDAllocator)
	if !ok && (l.alloc != nil || len(records) > 0) {
		return fmt.Errorf("local SID inventory requires a persistent allocator")
	}
	if err := ReserveStoredLocalSIDs(store, alloc); err != nil {
		return err
	}
	l.inventory, l.persistentAlloc = store.sids, alloc
	for _, r := range records {
		if l.live[r.Owner] == nil {
			l.live[r.Owner] = make(map[string]AllocatedSID)
		}
		l.live[r.Owner][r.Name] = AllocatedSID{
			Name: r.Name, SID: r.SID, Locator: r.Locator.Name, slot: r.Slot,
			auxRaw: append([]byte(nil), r.AuxRaw...), decapVRF: r.DecapVRF,
			reservation: r.reservation(), stranded: true, recoverOwnerless: true,
		}
	}
	return nil
}

func (l *LocalSIDSet) inventoryRecords(skipOwner bpf.OwnerTag, skipName string) []sidRecord {
	l.mu.Lock()
	defer l.mu.Unlock()
	var records []sidRecord
	for owner, held := range l.live {
		for name, got := range held {
			if owner == skipOwner && name == skipName {
				continue
			}
			records = append(records, sidRecord{
				Owner: owner, Name: name, SID: got.SID, Locator: got.reservation.Locator,
				Function: got.reservation.Function, Slot: got.slot,
				AuxRaw: got.auxRaw, DecapVRF: got.decapVRF,
			})
		}
	}
	return records
}

// Keep the candidate in memory even if saving fails: rename may already have
// happened. A retry persists the allocation before installing its entry.
func (l *LocalSIDSet) saveSID(owner bpf.OwnerTag, got AllocatedSID) error {
	l.mu.Lock()
	if l.live[owner] == nil {
		l.live[owner] = make(map[string]AllocatedSID)
	}
	l.live[owner][got.Name] = got
	l.mu.Unlock()
	return l.inventory.save(l.inventoryRecords("", ""))
}

func (l *LocalSIDSet) applyPersistent(owner bpf.OwnerTag, byName map[string]LocalSID, names []string) ([]AllocatedSID, ApplyResult, error) {
	var res ApplyResult
	l.mu.Lock()
	var stale []AllocatedSID
	for name, got := range l.live[owner] {
		if _, ok := byName[name]; !ok {
			stale = append(stale, got)
		}
	}
	l.mu.Unlock()
	sort.Slice(stale, func(i, j int) bool { return stale[i].Name < stale[j].Name })
	for _, got := range stale {
		if err := l.removePersistent(owner, got); err != nil {
			return nil, res, err
		}
		res.Pruned++
	}
	sort.Strings(names)
	out := make([]AllocatedSID, 0, len(names))
	for _, name := range names {
		want := byName[name]
		l.mu.Lock()
		got, held := l.live[owner][name]
		l.mu.Unlock()
		if held && got.Locator != want.Locator {
			if err := l.removePersistent(owner, got); err != nil {
				return nil, res, err
			}
			held = false
		}
		if l.persistentAlloc == nil {
			return nil, res, fmt.Errorf("local SID inventory requires a persistent allocator")
		}
		sid, reservation, err := l.persistentAlloc.AllocateReservedSID(sidReservationKey(owner, name), want.Locator)
		if err != nil {
			return nil, res, fmt.Errorf("local sid %q: reserve: %w", name, err)
		}
		if held && got.matches(want) {
			out = append(out, got)
			res.Updated++
			continue
		}
		if !held {
			// Do not persist a new claim over an existing dispatch. Otherwise
			// an error followed by a restart could turn that new record into
			// authority to recover somebody else's ownerless entry.
			if err := l.checkSIDAvailable(sid.String() + "/128"); err != nil {
				l.persistentAlloc.ReleaseReservedSID(reservation.Key)
				return nil, res, err
			}
		}
		if held {
			// The previous durable record remains authoritative while its
			// entry is removed. Only then may the replacement be persisted.
			l.markSIDUnconfirmed(owner, got)
			if err := l.removePersistentEntry(owner, got); err != nil {
				return nil, res, err
			}
		}
		pending := AllocatedSID{Name: name, SID: sid, Locator: want.Locator,
			slot: want.Slot, auxRaw: append([]byte(nil), want.AuxRaw...), decapVRF: want.DecapVRF,
			reservation: reservation, stranded: true,
		}
		if err := l.saveSID(owner, pending); err != nil {
			return nil, res, err
		}
		// A partial map write can leave dispatch without its owner row. The
		// durable record now authorizes recovery of this install attempt too.
		pending.recoverOwnerless = true
		l.mu.Lock()
		l.live[owner][name] = pending
		l.mu.Unlock()
		// Rebuild using the current map's aux index and current VRF resolver.
		// Even an installed record loaded from disk is unconfirmed this run.
		auxIndex, err := l.install(owner, sid, want)
		if err != nil {
			return nil, res, err
		}
		installed := pending
		installed.auxIndex = auxIndex
		installed.stranded = false
		installed.recoverOwnerless = false
		l.mu.Lock()
		l.live[owner][name] = installed
		l.mu.Unlock()
		out = append(out, installed)
		if held {
			res.Updated++
		} else {
			res.Created++
		}
	}
	return out, res, nil
}

// The daemon supplies an exact lookup; embedders implementing only the
// original SIDFunctionOps surface retain the full-snapshot fallback.
type exactSIDFunctionOps interface {
	GetSidFunctionExact(string) (*bpf.SidFunctionEntry, bool, error)
}

func (l *LocalSIDSet) exactSIDEntry(prefix string) (*bpf.SidFunctionEntry, bool, error) {
	if exact, ok := l.sids.(exactSIDFunctionOps); ok {
		return exact.GetSidFunctionExact(prefix)
	}
	entries, err := l.sids.ListSidFunctions()
	if err != nil {
		return nil, false, err
	}
	entry, exists := entries[prefix]
	return entry, exists, nil
}

func (l *LocalSIDSet) checkSIDAvailable(prefix string) error {
	_, owned, err := l.sids.GetSidFunctionOwner(prefix)
	if err != nil {
		return err
	}
	if owned {
		return fmt.Errorf("local sid %s is already owned: %w", prefix, bpf.ErrEntryOwnerMismatch)
	}
	_, exists, err := l.exactSIDEntry(prefix)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("local sid %s is already present: %w", prefix, bpf.ErrEntryOwnerMismatch)
	}
	return nil
}

func (l *LocalSIDSet) removePersistentEntry(owner bpf.OwnerTag, got AllocatedSID) error {
	if l.sids == nil {
		return fmt.Errorf("local sid %q: SID maps unavailable for cleanup", got.Name)
	}
	prefix := got.SID.String() + "/128"
	actual, owned, err := l.sids.GetSidFunctionOwner(prefix)
	if err != nil {
		return err
	}
	if owned && actual != owner {
		return fmt.Errorf("local sid %q at %s: %w", got.Name, prefix, bpf.ErrEntryOwnerMismatch)
	}
	if !owned {
		entry, exists, err := l.exactSIDEntry(prefix)
		if err != nil {
			return err
		}
		if !exists {
			return nil
		}
		// Only a durable install attempt can identify ownerless state.
		if entry == nil || !got.recoverOwnerless {
			return fmt.Errorf("local sid %q: %w", got.Name, bpf.ErrEntryOwnerMismatch)
		}
		plain := *entry
		plain.AuxIndex = 0
		if plain != (bpf.SidFunctionEntry{Action: uint8(got.slot)}) {
			return fmt.Errorf("local sid %q: unowned dispatch differs from inventory", got.Name)
		}
	}
	// The map layer checks ownership again, resolves the exact entry and
	// removes its grant before freeing aux. Do not walk the map again here
	// or attempt grant cleanup with a separately observed, possibly stale index.
	if err := l.sids.DeleteSidFunction(prefix, owner); err != nil {
		return fmt.Errorf("local sid %q: remove %s: %w", got.Name, prefix, err)
	}
	return nil
}

func (l *LocalSIDSet) removePersistent(owner bpf.OwnerTag, got AllocatedSID) error {
	l.markSIDUnconfirmed(owner, got)
	if err := l.removePersistentEntry(owner, got); err != nil {
		return err
	}
	if err := l.inventory.save(l.inventoryRecords(owner, got.Name)); err != nil {
		return err
	}
	l.persistentAlloc.ReleaseReservedSID(got.reservation.Key)
	l.mu.Lock()
	delete(l.live[owner], got.Name)
	l.mu.Unlock()
	return nil
}

func (l *LocalSIDSet) markSIDUnconfirmed(owner bpf.OwnerTag, got AllocatedSID) {
	got.stranded, got.auxIndex = true, 0
	l.mu.Lock()
	l.live[owner][got.Name] = got
	l.mu.Unlock()
}

func (l *LocalSIDSet) inventoryScopes() map[string]Scope {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make(map[string]Scope)
	if l.inventory == nil {
		return out
	}
	for owner, held := range l.live {
		plugin, _, _ := bpf.ParsePluginOwnerTag(string(owner))
		scope := Scope{}
		for _, got := range held {
			scope.Locators = append(scope.Locators, got.Locator)
			scope.EndpointSlots = append(scope.EndpointSlots, got.slot)
			if got.decapVRF != "" {
				scope.VRFs = append(scope.VRFs, got.decapVRF)
			}
		}
		out[plugin.Bundle] = scope
	}
	return out
}

// PruneExcept only retires removed names; retained records are not declarations
// to reinstall. Restore-time scope pruning can therefore complete while a kept
// SID is still waiting for its locator or VRF to be registered.
func (l *LocalSIDSet) PruneExcept(owner bpf.OwnerTag, keep []LocalSID) (ApplyResult, error) {
	l.opMu.Lock()
	defer l.opMu.Unlock()
	var res ApplyResult
	names := make(map[string]bool, len(keep))
	for _, s := range keep {
		names[s.Name] = true
	}
	l.mu.Lock()
	var stale []AllocatedSID
	for name, got := range l.live[owner] {
		if !names[name] {
			stale = append(stale, got)
		}
	}
	l.mu.Unlock()
	sort.Slice(stale, func(i, j int) bool { return stale[i].Name < stale[j].Name })
	for _, got := range stale {
		remove := l.remove
		if l.inventory != nil {
			remove = l.removePersistent
		}
		if err := remove(owner, got); err != nil {
			return res, err
		}
		l.mu.Lock()
		delete(l.live[owner], got.Name)
		l.mu.Unlock()
		res.Pruned++
	}
	return res, nil
}
