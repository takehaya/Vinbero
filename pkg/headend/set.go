// Package headend reconciles owner-scoped forwarding entries for host controllers.
package headend

import (
	"errors"
	"fmt"
	"sort"

	"github.com/takehaya/vinbero/pkg/ownership"

	"github.com/takehaya/vinbero/pkg/bpf"
)

// MapOps is the headend surface a desired-set apply needs. It is
// the writes an owner is allowed plus the reads needed to work out what
// that owner already holds. *bpf.MapOperations satisfies it; narrowing it
// keeps this testable without a live BPF collection, and keeps the 101
// methods of MapOperations away from anything plugin-facing. Native backends
// also enumerate headend owners; older backends without those methods can only
// discover reservations that still have a main-map entry.
type MapOps interface {
	ListHeadendV4() (map[string]*bpf.HeadendEntry, error)
	ListHeadendV6() (map[string]*bpf.HeadendEntry, error)
	GetHeadendV4Owner(triggerPrefix string) (bpf.OwnerTag, bool, error)
	GetHeadendV6Owner(triggerPrefix string) (bpf.OwnerTag, bool, error)
	CreateHeadendV4(triggerPrefix string, entry *bpf.HeadendEntry, owner bpf.OwnerTag) error
	CreateHeadendV6(triggerPrefix string, entry *bpf.HeadendEntry, owner bpf.OwnerTag) error
	DeleteHeadendV4(triggerPrefix string, requester bpf.OwnerTag) error
	DeleteHeadendV6(triggerPrefix string, requester bpf.OwnerTag) error
}

// Family selects which headend map a desired set applies to.
type Family uint8

const (
	// AFv4 is headend_v4_map, keyed by an IPv4 trigger prefix.
	AFv4 Family = iota
	// AFv6 is headend_v6_map, keyed by an IPv6 trigger prefix.
	AFv6
)

// String renders the family for errors and logs.
func (af Family) String() string {
	if af == AFv6 {
		return "headend_v6"
	}
	return "headend_v4"
}

// leaseKind maps the family onto its lease key space.
func (af Family) leaseKind() ownership.LeaseKind {
	if af == AFv6 {
		return ownership.LeaseHeadendV6
	}
	return ownership.LeaseHeadendV4
}

// Desired is one entry of a declared set: the trigger prefix and
// the encap entry it should map to.
type Desired struct {
	TriggerPrefix string
	Entry         *bpf.HeadendEntry
}

// Result reports what a reconcile did. It is returned even when the
// apply fails partway, so a caller can log how far it got.
type Result struct {
	Created int
	Updated int
	Pruned  int
}

// Total is the number of entries the reconcile touched.
func (r Result) Total() int { return r.Created + r.Updated + r.Pruned }

// ApplySet makes the owner's headend entries in one family match
// desired exactly: entries the owner holds but did not declare are pruned,
// declared entries are created or overwritten.
//
// The owner declares the whole set rather than issuing creates and
// deletes, because the core then holds the only copy of the diff. A plugin
// that dies partway through and restarts simply declares the same set
// again and converges, with no need to remember which half of an ordered
// edit sequence it had already sent.
//
// The apply is not a transaction: BPF maps offer no way to make several
// entry writes atomic, so a failure partway leaves earlier writes in
// place. It is safe to retry because it is idempotent -- a repeated apply
// of the same set re-derives the same diff. Ordering is chosen to fail
// safe: prunes run first so a re-pointed prefix never briefly exists twice,
// and entries are applied in sorted order so a retry repeats the same
// sequence rather than a map-iteration reshuffle.
//
// Leases are taken for the whole declared set before anything is written,
// so a set overlapping another owner's key is rejected before it has
// changed the data plane.
func ApplySet(ops MapOps, leases *ownership.Leases, owner bpf.OwnerTag, af Family, desired []Desired, quota int) (Result, error) {
	return applySets(ops, leases, owner, []familySet{{af: af, desired: desired}}, quota)
}

type familySet struct {
	af          Family
	desired     []Desired
	byPrefix    map[string]*bpf.HeadendEntry
	keys, taken []string
	current     map[string]struct{}
}

// applySets reserves every declared key before pruning either family. A
// single-family caller still counts retained keys in the other family.
func applySets(ops MapOps, leases *ownership.Leases, owner bpf.OwnerTag, sets []familySet, quota int) (Result, error) {
	var res Result
	if owner == "" {
		return res, bpf.ErrEmptyOwner
	}
	if ops == nil {
		return res, errors.New("apply headend set: nil map ops")
	}
	var present [2]bool
	total := 0
	for i := range sets {
		x := &sets[i]
		if x.af != AFv4 && x.af != AFv6 {
			return res, fmt.Errorf("invalid headend family %d", x.af)
		}
		present[x.af] = true
		x.byPrefix = make(map[string]*bpf.HeadendEntry, len(x.desired))
		for _, d := range x.desired {
			key, err := canonicalPrefix(x.af, d.TriggerPrefix)
			if err != nil {
				return res, err
			}
			if d.Entry == nil {
				return res, fmt.Errorf("apply %s set: nil entry for %q", x.af, d.TriggerPrefix)
			}
			if _, dup := x.byPrefix[key]; dup {
				return res, fmt.Errorf("apply %s set: %q declared twice", x.af, key)
			}
			x.byPrefix[key] = d.Entry
			x.keys = append(x.keys, key)
		}
		sort.Strings(x.keys)
		total += len(x.keys)
	}
	if quota >= 0 {
		for _, af := range []Family{AFv4, AFv6} {
			if !present[af] {
				held, err := ownedPrefixes(ops, owner, af)
				if err != nil {
					return res, err
				}
				total += len(held)
			}
		}
		if total > quota {
			return res, &ownership.QuotaError{What: "headend entries", Declared: total, Quota: quota}
		}
	}
	// Persisted owners survive restart, and direct operator writes do not
	// take leases. Check both before reserving or deleting any working key.
	for _, x := range sets {
		for _, prefix := range x.keys {
			if leases != nil {
				if holder, held := leases.HolderOf(x.af.leaseKind(), prefix); held && holder != owner {
					return res, &ownership.LeaseError{Kind: x.af.leaseKind(), Key: prefix, Holder: holder}
				}
			}
			holder, found, err := getOwner(ops, x.af, prefix)
			if err != nil {
				return res, fmt.Errorf("read %s owner of %q: %w", x.af, prefix, err)
			}
			if found && holder != owner {
				return res, ownerConflict(x.af, prefix, holder, owner)
			}
		}
	}
	rollback := func() {
		for _, x := range sets {
			releaseAll(leases, x.af, x.taken, owner)
		}
	}
	for i := range sets {
		if leases != nil {
			var err error
			sets[i].taken, err = leases.AcquireAll(sets[i].af.leaseKind(), sets[i].keys, owner)
			if err != nil {
				rollback()
				return res, err
			}
		}
	}
	for i := range sets {
		var err error
		sets[i].current, err = ownedPrefixes(ops, owner, sets[i].af)
		if err != nil {
			rollback()
			return res, err
		}
	}
	for _, x := range sets {
		var stale []string
		for prefix := range x.current {
			if _, keep := x.byPrefix[prefix]; !keep {
				stale = append(stale, prefix)
			}
		}
		sort.Strings(stale)
		for _, prefix := range stale {
			if err := deleteHeadend(ops, x.af, prefix, owner); err != nil {
				for _, pending := range sets {
					releaseUnwritten(leases, pending.af, pending.keys, pending.current, owner)
				}
				return res, fmt.Errorf("apply %s set: prune %q: %w", x.af, prefix, err)
			}
			if leases != nil {
				leases.Release(x.af.leaseKind(), prefix, owner)
			}
			res.Pruned++
		}
	}
	for i, x := range sets {
		for j, prefix := range x.keys {
			if err := createHeadend(ops, x.af, prefix, x.byPrefix[prefix], owner); err != nil {
				releaseUnwritten(leases, x.af, x.keys[j:], x.current, owner)
				for _, pending := range sets[i+1:] {
					releaseUnwritten(leases, pending.af, pending.keys, pending.current, owner)
				}
				return res, fmt.Errorf("apply %s set: write %q: %w", x.af, prefix, err)
			}
			if _, existed := x.current[prefix]; existed {
				res.Updated++
			} else {
				res.Created++
			}
		}
	}
	return res, nil
}

// PruneOwner removes every headend entry an owner holds in one
// family. It is the flush an unregistering plugin runs, and equivalent to
// applying an empty set except that it does not take leases first.
func PruneOwner(ops MapOps, leases *ownership.Leases, owner bpf.OwnerTag, af Family) (int, error) {
	if owner == "" {
		return 0, bpf.ErrEmptyOwner
	}
	if ops == nil {
		return 0, errors.New("prune headend owner: nil map ops")
	}
	if af != AFv4 && af != AFv6 {
		return 0, fmt.Errorf("invalid headend family %d", af)
	}
	current, err := ownedPrefixes(ops, owner, af)
	if err != nil {
		return 0, err
	}
	prefixes := make([]string, 0, len(current))
	for prefix := range current {
		prefixes = append(prefixes, prefix)
	}
	sort.Strings(prefixes)
	var pruned int
	for _, prefix := range prefixes {
		if err := deleteHeadend(ops, af, prefix, owner); err != nil {
			return pruned, fmt.Errorf("prune %s owner %q: %q: %w", af, owner, prefix, err)
		}
		if leases != nil {
			leases.Release(af.leaseKind(), prefix, owner)
		}
		pruned++
	}
	return pruned, nil
}

// releaseAll frees the leases on keys that were never written, so a lease
// never outlives the entry it was taken for.
func releaseAll(leases *ownership.Leases, af Family, keys []string, owner bpf.OwnerTag) {
	if leases == nil {
		return
	}
	for _, key := range keys {
		leases.Release(af.leaseKind(), key, owner)
	}
}

// releaseUnwritten frees the leases on declared keys the owner has no
// entry for, leaving alone the ones it already holds from an earlier
// apply. A lease dropped for a key whose entry is still installed would
// let another owner take a key it cannot actually write.
func releaseUnwritten(leases *ownership.Leases, af Family, keys []string, current map[string]struct{}, owner bpf.OwnerTag) {
	if leases == nil {
		return
	}
	for _, key := range keys {
		if _, live := current[key]; live {
			continue
		}
		leases.Release(af.leaseKind(), key, owner)
	}
}

// OwnedEntries returns what one owner holds in a family, in the
// form a declaration has.
//
// It is what lets the host re-state an owner's own entries as a desired
// set: narrowing a plugin's scope means applying the subset that is still
// inside it, and the reconcile prunes the rest.
func OwnedEntries(ops MapOps, owner bpf.OwnerTag, af Family) ([]Desired, error) {
	if owner == "" {
		return nil, bpf.ErrEmptyOwner
	}
	if ops == nil {
		return nil, errors.New("owned headend entries: nil map ops")
	}
	if af != AFv4 && af != AFv6 {
		return nil, fmt.Errorf("invalid headend family %d", af)
	}
	var (
		entries map[string]*bpf.HeadendEntry
		err     error
	)
	if af == AFv6 {
		entries, err = ops.ListHeadendV6()
	} else {
		entries, err = ops.ListHeadendV4()
	}
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", af, err)
	}
	owned, err := ownedPrefixes(ops, owner, af)
	if err != nil {
		return nil, err
	}
	prefixes := make([]string, 0, len(owned))
	for prefix := range owned {
		prefixes = append(prefixes, prefix)
	}
	sort.Strings(prefixes)
	out := make([]Desired, 0, len(prefixes))
	for _, prefix := range prefixes {
		entry, ok := entries[prefix]
		if !ok || entry == nil {
			continue
		}
		copied := *entry
		out = append(out, Desired{TriggerPrefix: prefix, Entry: &copied})
	}
	return out, nil
}

// ownedPrefixes returns the trigger prefixes reserved by owner in one family.
// Entries with no recorded owner are left alone: claiming them here would let
// a plugin prune state it never wrote.
func ownedPrefixes(ops MapOps, owner bpf.OwnerTag, af Family) (map[string]struct{}, error) {
	// Native maps enumerate ownership independently of live entries so failed
	// owner deletions remain discoverable after restart. Older backends can
	// only discover ownership while the main entry still exists.
	if inventory, ok := ops.(interface {
		ListHeadendV4Owners() (map[string]bpf.OwnerTag, error)
		ListHeadendV6Owners() (map[string]bpf.OwnerTag, error)
	}); ok {
		var owners map[string]bpf.OwnerTag
		var err error
		if af == AFv6 {
			owners, err = inventory.ListHeadendV6Owners()
		} else {
			owners, err = inventory.ListHeadendV4Owners()
		}
		if err != nil {
			return nil, fmt.Errorf("list %s owners: %w", af, err)
		}
		out := make(map[string]struct{})
		for key, holder := range owners {
			if holder == owner {
				out[key] = struct{}{}
			}
		}
		return out, nil
	}
	var (
		entries map[string]*bpf.HeadendEntry
		err     error
	)
	if af == AFv6 {
		entries, err = ops.ListHeadendV6()
	} else {
		entries, err = ops.ListHeadendV4()
	}
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", af, err)
	}
	out := make(map[string]struct{})
	for prefix := range entries {
		var (
			got bpf.OwnerTag
			ok  bool
		)
		if af == AFv6 {
			got, ok, err = ops.GetHeadendV6Owner(prefix)
		} else {
			got, ok, err = ops.GetHeadendV4Owner(prefix)
		}
		if err != nil {
			return nil, fmt.Errorf("read %s owner of %q: %w", af, prefix, err)
		}
		if ok && got == owner {
			out[prefix] = struct{}{}
		}
	}
	return out, nil
}

// createHeadend writes one entry in the family's map.
func createHeadend(ops MapOps, af Family, prefix string, entry *bpf.HeadendEntry, owner bpf.OwnerTag) error {
	if af == AFv6 {
		return ops.CreateHeadendV6(prefix, entry, owner)
	}
	return ops.CreateHeadendV4(prefix, entry, owner)
}

// deleteHeadend removes one entry from the family's map.
func deleteHeadend(ops MapOps, af Family, prefix string, owner bpf.OwnerTag) error {
	if af == AFv6 {
		return ops.DeleteHeadendV6(prefix, owner)
	}
	return ops.DeleteHeadendV4(prefix, owner)
}
