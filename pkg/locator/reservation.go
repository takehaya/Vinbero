package locator

import (
	"fmt"
	"net/netip"
)

// SIDReservation keeps an allocation tied to a caller's durable identity. The
// caller persists it before installing forwarding state and releases it only
// after both that state and its durable record have been removed.
type SIDReservation struct {
	Key      string  `json:"key"`
	Locator  Locator `json:"locator"`
	Function uint32  `json:"function"`
}

// SameSIDLayout compares the address format, excluding the auto-allocation
// range. A restored manual reservation remains valid when that range changes.
func (l Locator) SameSIDLayout(other Locator) bool {
	return l.Name == other.Name && l.Prefix.Masked() == other.Prefix.Masked() &&
		l.BlockLen == other.BlockLen && l.NodeLen == other.NodeLen &&
		l.FunctionLen == other.FunctionLen && l.ArgumentLen == other.ArgumentLen &&
		l.Behavior == other.Behavior
}

func (m *Manager) checkReservationLocatorLocked(loc Locator) error {
	for _, r := range m.reservations {
		if r.Locator.Name == loc.Name && !loc.SameSIDLayout(r.Locator) {
			return fmt.Errorf("locator %q differs from SID reservation %q", loc.Name, r.Key)
		}
		if r.Locator.Name != loc.Name && r.Locator.Prefix.Masked() == loc.Prefix.Masked() {
			return fmt.Errorf("%w: %s reserved by %q", ErrLocatorPrefixInUse, loc.Prefix, r.Locator.Name)
		}
	}
	return nil
}

// RestoreSIDReservations reserves the complete batch before ordinary allocation
// can run. Locators may be absent: their bindings are held immediately and Add
// restores their function bitmaps before publishing them. An identical batch
// may be replayed; conflicting records leave the manager unchanged.
func (m *Manager) RestoreSIDReservations(records []SIDReservation) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	added := make([]SIDReservation, 0, len(records))
	rollback := func() {
		for _, r := range added {
			m.releaseReservationLocked(r.Key)
		}
	}
	for _, r := range records {
		_, existed := m.reservations[r.Key]
		if err := m.restoreReservationLocked(r); err != nil {
			rollback()
			return err
		}
		if !existed {
			added = append(added, r)
		}
	}
	return nil
}

func (m *Manager) restoreReservationLocked(r SIDReservation) error {
	if r.Key == "" {
		return fmt.Errorf("SID reservation: empty key")
	}
	if err := r.Locator.Validate(); err != nil {
		return err
	}
	r.Locator.Prefix = r.Locator.Prefix.Masked()
	sid, err := r.Locator.BuildSID(r.Function)
	if err != nil {
		return err
	}
	if old, ok := m.reservations[r.Key]; ok {
		if old.Function == r.Function && old.Locator.SameSIDLayout(r.Locator) {
			return nil
		}
		return fmt.Errorf("SID reservation %q already names another allocation", r.Key)
	}
	if err := m.checkReservationLocatorLocked(r.Locator); err != nil {
		return err
	}
	for _, e := range m.entries {
		if e.loc.Name == r.Locator.Name && !e.loc.SameSIDLayout(r.Locator) {
			return fmt.Errorf("SID reservation %q differs from locator %q", r.Key, e.loc.Name)
		}
		if e.loc.Name != r.Locator.Name && e.loc.Prefix.Masked() == r.Locator.Prefix {
			return fmt.Errorf("%w: SID reservation %q", ErrLocatorPrefixInUse, r.Key)
		}
	}
	if _, ok := m.bindings.Lookup(sid); ok {
		return fmt.Errorf("%w: SID reservation %q at %s", ErrBindingExists, r.Key, sid)
	}
	e := m.entries[r.Locator.Name]
	if e != nil {
		if _, err := e.alloc.Allocate(&r.Function); err != nil {
			return err
		}
	}
	if err := m.bindings.Record(sid, Binding{LocatorName: r.Locator.Name, Function: r.Function}); err != nil {
		if e != nil {
			e.alloc.Release(r.Function)
		}
		return err
	}
	m.reservations[r.Key] = r
	m.reservedSIDs[sid] = r.Key
	return nil
}

// AllocateReservedSID returns the allocation already held by key, or allocates
// and reserves a new one atomically. It never creates a missing locator.
func (m *Manager) AllocateReservedSID(key, locatorName string) (netip.Addr, SIDReservation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if key == "" {
		return netip.Addr{}, SIDReservation{}, fmt.Errorf("SID reservation: empty key")
	}
	if _, ok := m.entries[locatorName]; !ok {
		return netip.Addr{}, SIDReservation{}, fmt.Errorf("%w: %q", ErrLocatorNotFound, locatorName)
	}
	if r, ok := m.reservations[key]; ok {
		if r.Locator.Name != locatorName {
			return netip.Addr{}, SIDReservation{}, fmt.Errorf("SID reservation %q belongs to locator %q", key, r.Locator.Name)
		}
		sid, err := r.Locator.BuildSID(r.Function)
		return sid, r, err
	}
	sid, b, err := m.allocateSIDLocked(locatorName, nil)
	if err != nil {
		return netip.Addr{}, SIDReservation{}, err
	}
	r := SIDReservation{Key: key, Locator: *m.entries[locatorName].loc, Function: b.Function}
	m.reservations[key] = r
	m.reservedSIDs[sid] = key
	return sid, r, nil
}

// ReleaseReservedSID gives up key after the caller's durable cleanup. Ordinary
// ReleaseSID and even a forced locator deletion cannot drop these reservations.
func (m *Manager) ReleaseReservedSID(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.releaseReservationLocked(key)
}

func (m *Manager) releaseReservationLocked(key string) {
	r, ok := m.reservations[key]
	if !ok {
		return
	}
	sid, _ := r.Locator.BuildSID(r.Function)
	delete(m.reservations, key)
	delete(m.reservedSIDs, sid)
	m.releaseSIDLocked(sid)
}
