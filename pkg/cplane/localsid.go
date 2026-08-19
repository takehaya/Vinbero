package cplane

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"sync"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/locator"
)

// SIDAllocator hands out SRv6 SIDs from the configured locators.
// *locator.Manager satisfies it.
type SIDAllocator interface {
	AllocateSID(locatorName string, requested *uint32) (netip.Addr, locator.Binding, error)
	ReleaseSID(sid netip.Addr)
}

// SIDFunctionOps is the sid_function surface a local-SID reconcile needs.
// *bpf.MapOperations satisfies it.
type SIDFunctionOps interface {
	CreateSidFunction(triggerPrefix string, entry *bpf.SidFunctionEntry, aux *bpf.SidAuxEntry, owner bpf.OwnerTag) error
	DeleteSidFunction(triggerPrefix string, requester bpf.OwnerTag) error
	ListSidFunctions() (map[string]*bpf.SidFunctionEntry, error)
	GetSidFunctionOwner(triggerPrefix string) (bpf.OwnerTag, bool, error)
}

// LocalSID is one SID a plugin wants to exist, pointing at its own
// data-plane half.
type LocalSID struct {
	// Name is the plugin's own name for this SID. The host chooses the
	// address, so the name is how the plugin recognizes what it got, and
	// how a redeclaration after a restart is known to mean the same SID.
	Name string
	// Locator is the pool to allocate from.
	Locator string
	// Slot is the endpoint PROG_ARRAY slot the SID dispatches to.
	Slot uint32
	// AuxRaw is the per-SID configuration the data-plane half reads.
	AuxRaw []byte
}

// AllocatedSID is what a declared local SID turned into.
type AllocatedSID struct {
	Name    string
	SID     netip.Addr
	Locator string
	// slot and auxRaw record what was installed for it, so a redeclaration
	// that changes nothing can be recognised and skipped.
	slot   uint32
	auxRaw []byte
}

// matches reports whether an installed SID already carries what a
// declaration asks for.
func (a AllocatedSID) matches(want LocalSID) bool {
	return a.Locator == want.Locator && a.slot == want.Slot && bytes.Equal(a.auxRaw, want.AuxRaw)
}

// LocalSIDSet reconciles the local SIDs one owner has declared.
//
// It is where the two halves of a plugin meet: the control-plane half says
// which behaviors it wants reachable and in which slot its data-plane half
// lives, and the host allocates an address, installs the dispatch entry,
// and tells the plugin the address so it can advertise it.
//
// Allocation is the one part of the capability surface that is not purely
// declarative -- an address has to come from somewhere and be remembered.
// Naming each SID is what keeps even that idempotent within a daemon run:
// a plugin instance that comes back with no memory declares the same names
// and is handed the same addresses, because the host still holds them.
//
// A daemon restart is different. The names live only here, in memory, so
// nothing can map a surviving pinned entry back to the name it was
// installed for. What the host does instead is sweep: the first time an
// owner declares anything, entries under that owner which this run did not
// install are removed, and the plugin is handed fresh addresses. Leaving
// them would be worse -- nothing dispatches to them and nothing can ever
// remove them again.
type LocalSIDSet struct {
	alloc SIDAllocator
	sids  SIDFunctionOps

	mu sync.Mutex
	// live maps owner -> name -> what was allocated for it.
	live map[bpf.OwnerTag]map[string]AllocatedSID
	// swept records the owners whose leftovers from a previous daemon run
	// have already been cleared.
	swept map[bpf.OwnerTag]bool
}

// NewLocalSIDSet builds the tracker. Either dependency may be nil, in
// which case declaring a local SID reports that this daemon cannot serve
// one.
func NewLocalSIDSet(alloc SIDAllocator, sids SIDFunctionOps) *LocalSIDSet {
	return &LocalSIDSet{
		alloc: alloc,
		sids:  sids,
		live:  make(map[bpf.OwnerTag]map[string]AllocatedSID),
		swept: make(map[bpf.OwnerTag]bool),
	}
}

// Apply makes owner's local SIDs match desired exactly, returning what
// every declared SID resolved to.
//
// Releases run first: a name dropped from the set gives its address back
// before any new one is taken, so a plugin cycling through names does not
// hold two allocations for one purpose.
func (l *LocalSIDSet) Apply(owner bpf.OwnerTag, desired []LocalSID, quota int) ([]AllocatedSID, ApplyResult, error) {
	var res ApplyResult
	if owner == "" {
		return nil, res, bpf.ErrEmptyOwner
	}
	if len(desired) > 0 && (l.alloc == nil || l.sids == nil) {
		return nil, res, errors.New("local sid: this daemon cannot allocate SIDs")
	}

	byName := make(map[string]LocalSID, len(desired))
	names := make([]string, 0, len(desired))
	for _, s := range desired {
		if err := validateLocalSID(s); err != nil {
			return nil, res, err
		}
		if _, dup := byName[s.Name]; dup {
			return nil, res, fmt.Errorf("local sid: %q declared twice", s.Name)
		}
		byName[s.Name] = s
		names = append(names, s.Name)
	}

	if cap, bounded := limitOf(quota); bounded && len(names) > cap {
		return nil, res, &QuotaError{What: "local SIDs", Declared: len(names), Quota: cap}
	}

	if err := l.sweepLeftovers(owner); err != nil {
		return nil, res, err
	}

	l.mu.Lock()
	current := l.live[owner]
	if current == nil {
		current = make(map[string]AllocatedSID)
		l.live[owner] = current
	}
	stale := make([]string, 0, len(current))
	for name := range current {
		if _, keep := byName[name]; !keep {
			stale = append(stale, name)
		}
	}
	l.mu.Unlock()
	sort.Strings(stale)

	for _, name := range stale {
		l.mu.Lock()
		got := current[name]
		l.mu.Unlock()
		if err := l.remove(owner, got); err != nil {
			return nil, res, err
		}
		l.mu.Lock()
		delete(current, name)
		l.mu.Unlock()
		res.Pruned++
	}

	sort.Strings(names)
	out := make([]AllocatedSID, 0, len(names))
	for _, name := range names {
		want := byName[name]
		l.mu.Lock()
		got, held := current[name]
		l.mu.Unlock()

		if held && got.matches(want) {
			// Nothing about it changed, so nothing is written. Rewriting
			// would not be free: installing an entry with aux allocates a
			// fresh aux index every time and never frees the previous one,
			// so a plugin redeclaring its set on every event -- which is
			// exactly what the desired-set model asks for -- would leak an
			// index per apply until the allocator gave out.
			out = append(out, got)
			res.Updated++
			continue
		}
		if held && got.Locator == want.Locator {
			// Same address, different contents. The entry is removed
			// before the new one is written so the aux index the old one
			// held is freed rather than orphaned by the rebind -- but the
			// address itself stays, because it is still this plugin's and
			// may already have been advertised.
			if err := l.removeEntry(owner, got); err != nil {
				return nil, res, err
			}
			if err := l.install(owner, got.SID, want); err != nil {
				l.alloc.ReleaseSID(got.SID)
				l.mu.Lock()
				delete(current, name)
				l.mu.Unlock()
				return nil, res, err
			}
			updated := AllocatedSID{
				Name: name, SID: got.SID, Locator: want.Locator,
				slot: want.Slot, auxRaw: append([]byte(nil), want.AuxRaw...),
			}
			l.mu.Lock()
			current[name] = updated
			l.mu.Unlock()
			out = append(out, updated)
			res.Updated++
			continue
		}
		if held {
			// It moved to another locator, which is a different address.
			if err := l.remove(owner, got); err != nil {
				return nil, res, err
			}
			l.mu.Lock()
			delete(current, name)
			l.mu.Unlock()
		}

		sid, _, err := l.alloc.AllocateSID(want.Locator, nil)
		if err != nil {
			return nil, res, fmt.Errorf("local sid %q: allocate from %q: %w", name, want.Locator, err)
		}
		if err := l.install(owner, sid, want); err != nil {
			// Give the address back rather than leaking it: nothing points
			// at it, and the pool is finite.
			l.alloc.ReleaseSID(sid)
			return nil, res, err
		}
		allocated := AllocatedSID{
			Name: name, SID: sid, Locator: want.Locator,
			slot: want.Slot, auxRaw: append([]byte(nil), want.AuxRaw...),
		}
		l.mu.Lock()
		current[name] = allocated
		l.mu.Unlock()
		out = append(out, allocated)
		res.Created++
	}
	return out, res, nil
}

// sweepLeftovers removes dispatch entries under an owner that this daemon
// run did not install, once per owner.
//
// With pinned maps a previous run's entries survive, and their names do
// not: nothing here can tell which declaration installed a given address.
// A plugin redeclaring the same names is therefore handed new addresses,
// and the old entries would sit in the map with nothing dispatching to
// them and nothing able to remove them.
func (l *LocalSIDSet) sweepLeftovers(owner bpf.OwnerTag) error {
	if l.sids == nil {
		// A daemon that cannot install entries has none to sweep.
		return nil
	}
	l.mu.Lock()
	if l.swept[owner] {
		l.mu.Unlock()
		return nil
	}
	held := make(map[string]struct{}, len(l.live[owner]))
	for _, got := range l.live[owner] {
		held[got.SID.String()+"/128"] = struct{}{}
	}
	l.mu.Unlock()

	entries, err := l.sids.ListSidFunctions()
	if err != nil {
		return fmt.Errorf("local sid: list existing entries: %w", err)
	}
	prefixes := make([]string, 0, len(entries))
	for prefix := range entries {
		prefixes = append(prefixes, prefix)
	}
	sort.Strings(prefixes)

	for _, prefix := range prefixes {
		if _, ours := held[prefix]; ours {
			continue
		}
		got, ok, err := l.sids.GetSidFunctionOwner(prefix)
		if err != nil {
			return fmt.Errorf("local sid: read owner of %s: %w", prefix, err)
		}
		if !ok || got != owner {
			continue
		}
		if err := l.sids.DeleteSidFunction(prefix, owner); err != nil {
			return fmt.Errorf("local sid: sweep %s: %w", prefix, err)
		}
	}

	// Marked done only now. Setting it up front would turn one transient
	// map error into a permanent one: the sweep would be skipped from then
	// on, and the previous run's pinned entries would sit there for the
	// life of the daemon with nothing able to remove them.
	l.mu.Lock()
	l.swept[owner] = true
	l.mu.Unlock()
	return nil
}

// ReleaseOwner removes every local SID an owner holds. It is what
// unregistering runs.
func (l *LocalSIDSet) ReleaseOwner(owner bpf.OwnerTag) error {
	l.mu.Lock()
	current := l.live[owner]
	names := make([]string, 0, len(current))
	for name := range current {
		names = append(names, name)
	}
	l.mu.Unlock()
	sort.Strings(names)

	var firstErr error
	for _, name := range names {
		l.mu.Lock()
		got, ok := current[name]
		l.mu.Unlock()
		if !ok {
			continue
		}
		if err := l.remove(owner, got); err != nil {
			// Kept, not forgotten. The address and the name are what a
			// retry needs, and dropping them here would leave a dispatch
			// entry in the map that nothing knows about and nothing can
			// remove.
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		l.mu.Lock()
		delete(current, name)
		l.mu.Unlock()
	}
	l.mu.Lock()
	if len(current) == 0 {
		delete(l.live, owner)
	}
	l.mu.Unlock()
	return firstErr
}

// LiveCount is how many local SIDs an owner holds.
// LiveSIDs is what an owner holds, in the form a declaration has. It is
// what lets the host re-state an owner's own set when its scope narrows.
//
// The address is not part of it: a declaration names a locator and the
// host picks the address, so re-stating the set the plugin already holds
// hands back the same addresses rather than reallocating.
func (l *LocalSIDSet) LiveSIDs(owner bpf.OwnerTag) []LocalSID {
	l.mu.Lock()
	defer l.mu.Unlock()
	current := l.live[owner]
	out := make([]LocalSID, 0, len(current))
	for name, got := range current {
		out = append(out, LocalSID{
			Name:    name,
			Locator: got.Locator,
			Slot:    got.slot,
			AuxRaw:  append([]byte(nil), got.auxRaw...),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (l *LocalSIDSet) LiveCount(owner bpf.OwnerTag) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.live[owner])
}

// install writes the dispatch entry that points a SID at the plugin's
// data-plane slot.
func (l *LocalSIDSet) install(owner bpf.OwnerTag, sid netip.Addr, want LocalSID) error {
	entry := &bpf.SidFunctionEntry{Action: uint8(want.Slot)}
	var aux *bpf.SidAuxEntry
	if len(want.AuxRaw) > 0 {
		aux = bpf.NewSidAuxPluginRaw(want.AuxRaw)
	}
	prefix := sid.String() + "/128"
	if err := l.sids.CreateSidFunction(prefix, entry, aux, owner); err != nil {
		return fmt.Errorf("local sid %q: install %s: %w", want.Name, prefix, err)
	}
	return nil
}

// removeEntry deletes the dispatch entry and keeps the address.
//
// Deleting the entry is what frees the aux index bound to it: the map
// layer allocates one per install and releases it only on delete.
func (l *LocalSIDSet) removeEntry(owner bpf.OwnerTag, got AllocatedSID) error {
	prefix := got.SID.String() + "/128"
	if err := l.sids.DeleteSidFunction(prefix, owner); err != nil {
		return fmt.Errorf("local sid %q: remove %s: %w", got.Name, prefix, err)
	}
	return nil
}

// remove deletes the dispatch entry and returns the address to its pool.
//
// The entry goes first: releasing the address while the data plane still
// dispatches on it would let the next allocation hand the same address to
// someone else while packets are still arriving for this one.
func (l *LocalSIDSet) remove(owner bpf.OwnerTag, got AllocatedSID) error {
	if err := l.removeEntry(owner, got); err != nil {
		return err
	}
	l.alloc.ReleaseSID(got.SID)
	return nil
}

// validateLocalSID rejects a declaration the host cannot serve.
func validateLocalSID(s LocalSID) error {
	if s.Name == "" {
		return errors.New("local sid: declaration has no name")
	}
	if len(s.Name) > maxLocalSIDNameLen {
		return fmt.Errorf("local sid: name is %d bytes, limit %d", len(s.Name), maxLocalSIDNameLen)
	}
	if len(s.Locator) > maxLocalSIDNameLen {
		return fmt.Errorf("local sid %q: locator name is %d bytes, limit %d",
			s.Name, len(s.Locator), maxLocalSIDNameLen)
	}
	if s.Locator == "" {
		return fmt.Errorf("local sid %q: no locator", s.Name)
	}
	// The slot has to be one a plugin may occupy: pointing a SID at a
	// built-in behavior would let a plugin borrow vinbero's forwarding
	// under its own address.
	if err := bpf.ValidatePluginSlot("endpoint", s.Slot); err != nil {
		return fmt.Errorf("local sid %q: %w", s.Name, err)
	}
	if len(s.AuxRaw) > bpf.SidAuxPluginRawMax {
		return fmt.Errorf("local sid %q: aux payload is %d bytes, limit %d",
			s.Name, len(s.AuxRaw), bpf.SidAuxPluginRawMax)
	}
	return nil
}

// maxLocalSIDNameLen bounds the name a plugin gives a SID.
//
// The name is the plugin's own key for the allocation, kept for as long as
// it holds the SID. Nothing downstream reads it, so its only cost is the
// memory it occupies -- which is exactly why it needs a limit: without one
// a plugin can spend the host's memory on names for SIDs it never uses.
const maxLocalSIDNameLen = 256

// DecodeLocalSID converts a plugin's declaration into the internal form.
func DecodeLocalSID(in *v1.PluginLocalSid) (LocalSID, error) {
	if in == nil {
		return LocalSID{}, errors.New("local sid: nil declaration")
	}
	out := LocalSID{
		Name:    in.GetName(),
		Locator: in.GetLocator(),
		Slot:    in.GetSlot(),
		AuxRaw:  append([]byte(nil), in.GetAuxRaw()...),
	}
	return out, validateLocalSID(out)
}
