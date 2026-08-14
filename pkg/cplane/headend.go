package cplane

import (
	"errors"
	"fmt"
	"sort"

	"github.com/takehaya/vinbero/pkg/bpf"
)

// HeadendMapOps is the headend surface a desired-set apply needs. It is
// the writes an owner is allowed plus the reads needed to work out what
// that owner already holds. *bpf.MapOperations satisfies it; narrowing it
// keeps this testable without a live BPF collection, and keeps the 101
// methods of MapOperations away from anything plugin-facing.
type HeadendMapOps interface {
	ListHeadendV4() (map[string]*bpf.HeadendEntry, error)
	ListHeadendV6() (map[string]*bpf.HeadendEntry, error)
	GetHeadendV4Owner(triggerPrefix string) (bpf.OwnerTag, bool, error)
	GetHeadendV6Owner(triggerPrefix string) (bpf.OwnerTag, bool, error)
	CreateHeadendV4(triggerPrefix string, entry *bpf.HeadendEntry, owner bpf.OwnerTag) error
	CreateHeadendV6(triggerPrefix string, entry *bpf.HeadendEntry, owner bpf.OwnerTag) error
	DeleteHeadendV4(triggerPrefix string, requester bpf.OwnerTag) error
	DeleteHeadendV6(triggerPrefix string, requester bpf.OwnerTag) error
}

// AddressFamily selects which headend map a desired set applies to.
type AddressFamily uint8

const (
	// AFv4 is headend_v4_map, keyed by an IPv4 trigger prefix.
	AFv4 AddressFamily = iota
	// AFv6 is headend_v6_map, keyed by an IPv6 trigger prefix.
	AFv6
)

// String renders the family for errors and logs.
func (af AddressFamily) String() string {
	if af == AFv6 {
		return "headend_v6"
	}
	return "headend_v4"
}

// leaseKind maps the family onto its lease key space.
func (af AddressFamily) leaseKind() LeaseKind {
	if af == AFv6 {
		return LeaseHeadendV6
	}
	return LeaseHeadendV4
}

// HeadendDesired is one entry of a declared set: the trigger prefix and
// the encap entry it should map to.
type HeadendDesired struct {
	TriggerPrefix string
	Entry         *bpf.HeadendEntry
}

// ApplyResult reports what a reconcile did. It is returned even when the
// apply fails partway, so a caller can log how far it got.
type ApplyResult struct {
	Created int
	Updated int
	Pruned  int
}

// Total is the number of entries the reconcile touched.
func (r ApplyResult) Total() int { return r.Created + r.Updated + r.Pruned }

// ApplyHeadendSet makes the owner's headend entries in one family match
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
func ApplyHeadendSet(
	ops HeadendMapOps,
	leases *Leases,
	owner bpf.OwnerTag,
	af AddressFamily,
	desired []HeadendDesired,
) (ApplyResult, error) {
	var res ApplyResult
	if owner == "" {
		return res, bpf.ErrEmptyOwner
	}
	if ops == nil {
		return res, errors.New("apply headend set: nil map ops")
	}

	byPrefix := make(map[string]*bpf.HeadendEntry, len(desired))
	keys := make([]string, 0, len(desired))
	for _, d := range desired {
		if d.TriggerPrefix == "" {
			return res, fmt.Errorf("apply %s set: empty trigger prefix", af)
		}
		if d.Entry == nil {
			return res, fmt.Errorf("apply %s set: nil entry for %q", af, d.TriggerPrefix)
		}
		if _, dup := byPrefix[d.TriggerPrefix]; dup {
			return res, fmt.Errorf("apply %s set: %q declared twice", af, d.TriggerPrefix)
		}
		byPrefix[d.TriggerPrefix] = d.Entry
		keys = append(keys, d.TriggerPrefix)
	}

	if leases != nil {
		if err := leases.AcquireAll(af.leaseKind(), keys, owner); err != nil {
			return res, err
		}
	}

	current, err := ownedPrefixes(ops, owner, af)
	if err != nil {
		// Nothing was written, so every lease this call took describes
		// nothing. There is no live set to consult here, which is exactly
		// why this releases all of them: the read that would have told us
		// which keys the owner already holds is the one that failed.
		releaseAll(leases, af, keys, owner)
		return res, err
	}

	// Prune first: a prefix moving out of the set must be gone before any
	// new entry is written, so the data plane never holds a stale entry
	// alongside the one meant to replace it.
	stale := make([]string, 0, len(current))
	for prefix := range current {
		if _, keep := byPrefix[prefix]; !keep {
			stale = append(stale, prefix)
		}
	}
	sort.Strings(stale)
	for _, prefix := range stale {
		if err := deleteHeadend(ops, af, prefix, owner); err != nil {
			// Release only the declared keys this owner has no entry for.
			// A key it already holds from an earlier apply is still live
			// in the map, and dropping its lease would let another owner
			// take a key whose entry this one still owns.
			releaseUnwritten(leases, af, keys, current, owner)
			return res, fmt.Errorf("apply %s set: prune %q: %w", af, prefix, err)
		}
		if leases != nil {
			leases.Release(af.leaseKind(), prefix, owner)
		}
		res.Pruned++
	}

	sort.Strings(keys)
	for i, prefix := range keys {
		if err := createHeadend(ops, af, prefix, byPrefix[prefix], owner); err != nil {
			// Release the leases of the keys that were never written,
			// including this one. They hold no map entry, so a later
			// reconcile would not prune them either -- the lease would
			// outlive the declaration and block another owner from a key
			// this one does not actually hold.
			releaseUnwritten(leases, af, keys[i:], current, owner)
			return res, fmt.Errorf("apply %s set: write %q: %w", af, prefix, err)
		}
		if _, existed := current[prefix]; existed {
			res.Updated++
		} else {
			res.Created++
		}
	}
	return res, nil
}

// PruneHeadendOwner removes every headend entry an owner holds in one
// family. It is the flush an unregistering plugin runs, and equivalent to
// applying an empty set except that it does not take leases first.
func PruneHeadendOwner(ops HeadendMapOps, leases *Leases, owner bpf.OwnerTag, af AddressFamily) (int, error) {
	if owner == "" {
		return 0, bpf.ErrEmptyOwner
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
func releaseAll(leases *Leases, af AddressFamily, keys []string, owner bpf.OwnerTag) {
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
func releaseUnwritten(leases *Leases, af AddressFamily, keys []string, current map[string]struct{}, owner bpf.OwnerTag) {
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

// ownedPrefixes returns the trigger prefixes owner currently holds in one
// family. Entries with no recorded owner predate owner tracking and are
// left alone: they belong to nobody, and claiming them here would let a
// plugin prune state it never wrote.
func ownedPrefixes(ops HeadendMapOps, owner bpf.OwnerTag, af AddressFamily) (map[string]struct{}, error) {
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
func createHeadend(ops HeadendMapOps, af AddressFamily, prefix string, entry *bpf.HeadendEntry, owner bpf.OwnerTag) error {
	if af == AFv6 {
		return ops.CreateHeadendV6(prefix, entry, owner)
	}
	return ops.CreateHeadendV4(prefix, entry, owner)
}

// deleteHeadend removes one entry from the family's map.
func deleteHeadend(ops HeadendMapOps, af AddressFamily, prefix string, owner bpf.OwnerTag) error {
	if af == AFv6 {
		return ops.DeleteHeadendV6(prefix, owner)
	}
	return ops.DeleteHeadendV4(prefix, owner)
}
