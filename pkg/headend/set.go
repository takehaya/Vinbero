// Package headend reconciles owner-scoped forwarding entries for host controllers.
package headend

import (
	"errors"
	"fmt"
	"sort"

	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/ownership"
	"github.com/takehaya/vinbero/pkg/vrf"
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

// VRFMapOps is the part of the headend surface that names a VRF other than
// the global one: entries keyed by {vrf_id, prefix}, and listings of every
// VRF. *bpf.MapOperations satisfies it. A backend without it holds the
// global VRF only, and a declared entry in another VRF is refused with
// ErrGlobalVRFOnly rather than written to the global VRF.
type VRFMapOps interface {
	ListHeadendV4IDs() (map[bpf.HeadendID]*bpf.HeadendEntry, error)
	ListHeadendV6IDs() (map[bpf.HeadendID]*bpf.HeadendEntry, error)
	ListHeadendV4OwnerIDs() (map[bpf.HeadendID]bpf.OwnerTag, error)
	ListHeadendV6OwnerIDs() (map[bpf.HeadendID]bpf.OwnerTag, error)
	GetHeadendV4OwnerIn(vrfID uint32, triggerPrefix string) (bpf.OwnerTag, bool, error)
	GetHeadendV6OwnerIn(vrfID uint32, triggerPrefix string) (bpf.OwnerTag, bool, error)
	CreateHeadendV4In(vrfID uint32, triggerPrefix string, entry *bpf.HeadendEntry, owner bpf.OwnerTag) error
	CreateHeadendV6In(vrfID uint32, triggerPrefix string, entry *bpf.HeadendEntry, owner bpf.OwnerTag) error
	DeleteHeadendV4In(vrfID uint32, triggerPrefix string, requester bpf.OwnerTag) error
	DeleteHeadendV6In(vrfID uint32, triggerPrefix string, requester bpf.OwnerTag) error
}

// ErrGlobalVRFOnly is an entry outside the global VRF for a backend that
// does not implement VRFMapOps.
var ErrGlobalVRFOnly = errors.New("headend backend holds global VRF entries only")

// ID names one headend entry: its VRF and its trigger prefix.
type ID = bpf.HeadendID

// leaseKey is the lease of one entry. A global entry is leased under its
// prefix, so the key space is the same as before entries had a VRF; an
// entry of another VRF under "vrf <id> <prefix>", which no prefix spells.
func leaseKey(id ID) string { return id.String() }

func leaseKeys(ids []ID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = leaseKey(id)
	}
	return out
}

func sortIDs(ids []ID) {
	sort.Slice(ids, func(i, j int) bool {
		if ids[i].VRF != ids[j].VRF {
			return ids[i].VRF < ids[j].VRF
		}
		return ids[i].Prefix < ids[j].Prefix
	})
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

// Desired is one entry of a declared set: the VRF and trigger prefix,
// and the encap entry it should map to. VRF is a vrf_id; the zero value
// is the global VRF.
type Desired struct {
	VRF           uint32
	TriggerPrefix string
	Entry         *bpf.HeadendEntry
}

// ID is the entry the declaration names.
func (d Desired) ID() ID { return ID{VRF: d.VRF, Prefix: d.TriggerPrefix} }

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
	af      Family
	desired []Desired
	byID    map[ID]*bpf.HeadendEntry
	keys    []ID
	taken   []string
	current map[ID]struct{}
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
		x.byID = make(map[ID]*bpf.HeadendEntry, len(x.desired))
		for _, d := range x.desired {
			prefix, err := canonicalPrefix(x.af, d.TriggerPrefix)
			if err != nil {
				return res, err
			}
			if d.Entry == nil {
				return res, fmt.Errorf("apply %s set: nil entry for %q", x.af, d.TriggerPrefix)
			}
			key := ID{VRF: d.VRF, Prefix: prefix}
			if key.VRF != vrf.GlobalVRFID && !holdsVRFs(ops) {
				return res, fmt.Errorf("apply %s set: %s: %w", x.af, key, ErrGlobalVRFOnly)
			}
			if _, dup := x.byID[key]; dup {
				return res, fmt.Errorf("apply %s set: %q declared twice", x.af, key)
			}
			x.byID[key] = d.Entry
			x.keys = append(x.keys, key)
		}
		sortIDs(x.keys)
		total += len(x.keys)
	}
	if quota >= 0 {
		for _, af := range []Family{AFv4, AFv6} {
			if !present[af] {
				held, err := ownedIDs(ops, owner, af)
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
		for _, key := range x.keys {
			if leases != nil {
				if holder, held := leases.HolderOf(x.af.leaseKind(), leaseKey(key)); held && holder != owner {
					return res, &ownership.LeaseError{Kind: x.af.leaseKind(), Key: leaseKey(key), Holder: holder}
				}
			}
			holder, found, err := getOwner(ops, x.af, key)
			if err != nil {
				return res, fmt.Errorf("read %s owner of %q: %w", x.af, key, err)
			}
			if found && holder != owner {
				return res, ownerConflict(x.af, key, holder, owner)
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
			sets[i].taken, err = leases.AcquireAll(sets[i].af.leaseKind(), leaseKeys(sets[i].keys), owner)
			if err != nil {
				rollback()
				return res, err
			}
		}
	}
	for i := range sets {
		var err error
		sets[i].current, err = ownedIDs(ops, owner, sets[i].af)
		if err != nil {
			rollback()
			return res, err
		}
	}
	for _, x := range sets {
		var stale []ID
		for key := range x.current {
			if _, keep := x.byID[key]; !keep {
				stale = append(stale, key)
			}
		}
		sortIDs(stale)
		for _, key := range stale {
			if err := deleteHeadend(ops, x.af, key, owner); err != nil {
				for _, pending := range sets {
					releaseUnwritten(leases, pending.af, pending.keys, pending.current, owner)
				}
				return res, fmt.Errorf("apply %s set: prune %q: %w", x.af, key, err)
			}
			if leases != nil {
				leases.Release(x.af.leaseKind(), leaseKey(key), owner)
			}
			res.Pruned++
		}
		n, err := pruneUnlisted(ops, x.af, owner)
		res.Pruned += n
		if err != nil {
			for _, pending := range sets {
				releaseUnwritten(leases, pending.af, pending.keys, pending.current, owner)
			}
			return res, fmt.Errorf("apply %s set: %w", x.af, err)
		}
	}
	for i, x := range sets {
		for j, key := range x.keys {
			if err := createHeadend(ops, x.af, key, x.byID[key], owner); err != nil {
				releaseUnwritten(leases, x.af, x.keys[j:], x.current, owner)
				for _, pending := range sets[i+1:] {
					releaseUnwritten(leases, pending.af, pending.keys, pending.current, owner)
				}
				return res, fmt.Errorf("apply %s set: write %q: %w", x.af, key, err)
			}
			if _, existed := x.current[key]; existed {
				res.Updated++
			} else {
				res.Created++
			}
		}
	}
	return res, nil
}

// PruneOwner removes every headend entry an owner holds in one
// family, in every VRF. It is the flush an unregistering plugin runs, and
// equivalent to applying an empty set except that it does not take leases
// first.
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
	current, err := ownedIDs(ops, owner, af)
	if err != nil {
		return 0, err
	}
	keys := make([]ID, 0, len(current))
	for key := range current {
		keys = append(keys, key)
	}
	sortIDs(keys)
	var pruned int
	for _, key := range keys {
		if err := deleteHeadend(ops, af, key, owner); err != nil {
			return pruned, fmt.Errorf("prune %s owner %q: %q: %w", af, owner, key, err)
		}
		if leases != nil {
			leases.Release(af.leaseKind(), leaseKey(key), owner)
		}
		pruned++
	}
	n, err := pruneUnlisted(ops, af, owner)
	return pruned + n, err
}

// pruneUnlisted removes what owner holds under keys no inventory can name:
// a malformed key in a native map. An owner pruned or re-applied this way
// leaves nothing behind.
func pruneUnlisted(ops MapOps, af Family, owner bpf.OwnerTag) (int, error) {
	unlisted, ok := ops.(interface {
		PruneUnlistedHeadendV4(bpf.OwnerTag) (int, error)
		PruneUnlistedHeadendV6(bpf.OwnerTag) (int, error)
	})
	if !ok {
		return 0, nil
	}
	if af == AFv6 {
		return unlisted.PruneUnlistedHeadendV6(owner)
	}
	return unlisted.PruneUnlistedHeadendV4(owner)
}

// releaseAll frees the leases on keys that were never written, so a lease
// never outlives the entry it was taken for. keys are lease keys.
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
func releaseUnwritten(leases *ownership.Leases, af Family, keys []ID, current map[ID]struct{}, owner bpf.OwnerTag) {
	if leases == nil {
		return
	}
	for _, key := range keys {
		if _, live := current[key]; live {
			continue
		}
		leases.Release(af.leaseKind(), leaseKey(key), owner)
	}
}

// OwnedEntries returns what one owner holds in a family, every VRF, in
// the form a declaration has.
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
	entries, err := listEntries(ops, af)
	if err != nil {
		return nil, err
	}
	owned, err := ownedIDs(ops, owner, af)
	if err != nil {
		return nil, err
	}
	keys := make([]ID, 0, len(owned))
	for key := range owned {
		keys = append(keys, key)
	}
	sortIDs(keys)
	out := make([]Desired, 0, len(keys))
	for _, key := range keys {
		entry, ok := entries[key]
		if !ok || entry == nil {
			continue
		}
		copied := *entry
		out = append(out, Desired{VRF: key.VRF, TriggerPrefix: key.Prefix, Entry: &copied})
	}
	return out, nil
}

// perVRF returns ops as a VRFMapOps: ops itself when it implements one,
// otherwise an adapter that holds the global VRF only. Every helper below
// reads and writes through it, so none of them branches on the backend.
func perVRF(ops MapOps) VRFMapOps {
	if v, ok := ops.(VRFMapOps); ok {
		return v
	}
	return globalOnly{ops}
}

// holdsVRFs reports whether ops can hold an entry outside the global VRF.
func holdsVRFs(ops MapOps) bool {
	_, legacy := perVRF(ops).(globalOnly)
	return !legacy
}

// globalOnly adapts a backend keyed by prefix alone. It is the global VRF:
// an operation naming another VRF fails with ErrGlobalVRFOnly.
type globalOnly struct{ MapOps }

func (g globalOnly) only(vrfID uint32, prefix string) error {
	if vrfID != vrf.GlobalVRFID {
		return fmt.Errorf("%s: %w", ID{VRF: vrfID, Prefix: prefix}, ErrGlobalVRFOnly)
	}
	return nil
}

func globalIDs[V any](in map[string]V, err error) (map[ID]V, error) {
	if err != nil {
		return nil, err
	}
	out := make(map[ID]V, len(in))
	for prefix, v := range in {
		out[ID{Prefix: prefix}] = v
	}
	return out, nil
}

func (g globalOnly) ListHeadendV4IDs() (map[ID]*bpf.HeadendEntry, error) {
	return globalIDs(g.ListHeadendV4())
}
func (g globalOnly) ListHeadendV6IDs() (map[ID]*bpf.HeadendEntry, error) {
	return globalIDs(g.ListHeadendV6())
}

// ownerIDs lists the owners from the backend's own inventory when it has
// one, which also finds owner records whose entry is gone; otherwise from
// the entries it lists.
func (g globalOnly) ownerIDs(v6 bool) (map[ID]bpf.OwnerTag, error) {
	if inventory, ok := g.MapOps.(interface {
		ListHeadendV4Owners() (map[string]bpf.OwnerTag, error)
		ListHeadendV6Owners() (map[string]bpf.OwnerTag, error)
	}); ok {
		if v6 {
			return globalIDs(inventory.ListHeadendV6Owners())
		}
		return globalIDs(inventory.ListHeadendV4Owners())
	}
	list, get := g.ListHeadendV4, g.GetHeadendV4Owner
	if v6 {
		list, get = g.ListHeadendV6, g.GetHeadendV6Owner
	}
	entries, err := list()
	if err != nil {
		return nil, err
	}
	out := make(map[ID]bpf.OwnerTag)
	for prefix := range entries {
		holder, ok, err := get(prefix)
		if err != nil {
			return nil, fmt.Errorf("read owner of %q: %w", prefix, err)
		}
		if ok {
			out[ID{Prefix: prefix}] = holder
		}
	}
	return out, nil
}

func (g globalOnly) ListHeadendV4OwnerIDs() (map[ID]bpf.OwnerTag, error) { return g.ownerIDs(false) }
func (g globalOnly) ListHeadendV6OwnerIDs() (map[ID]bpf.OwnerTag, error) { return g.ownerIDs(true) }
func (g globalOnly) GetHeadendV4OwnerIn(v uint32, p string) (bpf.OwnerTag, bool, error) {
	if err := g.only(v, p); err != nil {
		return "", false, err
	}
	return g.GetHeadendV4Owner(p)
}
func (g globalOnly) GetHeadendV6OwnerIn(v uint32, p string) (bpf.OwnerTag, bool, error) {
	if err := g.only(v, p); err != nil {
		return "", false, err
	}
	return g.GetHeadendV6Owner(p)
}
func (g globalOnly) CreateHeadendV4In(v uint32, p string, e *bpf.HeadendEntry, o bpf.OwnerTag) error {
	if err := g.only(v, p); err != nil {
		return err
	}
	return g.CreateHeadendV4(p, e, o)
}
func (g globalOnly) CreateHeadendV6In(v uint32, p string, e *bpf.HeadendEntry, o bpf.OwnerTag) error {
	if err := g.only(v, p); err != nil {
		return err
	}
	return g.CreateHeadendV6(p, e, o)
}
func (g globalOnly) DeleteHeadendV4In(v uint32, p string, o bpf.OwnerTag) error {
	if err := g.only(v, p); err != nil {
		return err
	}
	return g.DeleteHeadendV4(p, o)
}
func (g globalOnly) DeleteHeadendV6In(v uint32, p string, o bpf.OwnerTag) error {
	if err := g.only(v, p); err != nil {
		return err
	}
	return g.DeleteHeadendV6(p, o)
}

// listEntries reads one family's entries of every VRF the backend holds.
func listEntries(ops MapOps, af Family) (map[ID]*bpf.HeadendEntry, error) {
	v := perVRF(ops)
	list := v.ListHeadendV4IDs
	if af == AFv6 {
		list = v.ListHeadendV6IDs
	}
	entries, err := list()
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", af, err)
	}
	return entries, nil
}

// ownedIDs returns the entries reserved by owner in one family. Entries
// with no recorded owner are left alone: claiming them here would let a
// plugin prune state it never wrote. Native maps enumerate ownership
// independently of live entries, so failed owner deletions remain
// discoverable after restart.
func ownedIDs(ops MapOps, owner bpf.OwnerTag, af Family) (map[ID]struct{}, error) {
	v := perVRF(ops)
	list := v.ListHeadendV4OwnerIDs
	if af == AFv6 {
		list = v.ListHeadendV6OwnerIDs
	}
	owners, err := list()
	if err != nil {
		return nil, fmt.Errorf("list %s owners: %w", af, err)
	}
	out := make(map[ID]struct{})
	for key, holder := range owners {
		if holder == owner {
			out[key] = struct{}{}
		}
	}
	return out, nil
}

// getOwner reads the owner recorded for one entry.
func getOwner(ops MapOps, af Family, key ID) (bpf.OwnerTag, bool, error) {
	v := perVRF(ops)
	if af == AFv6 {
		return v.GetHeadendV6OwnerIn(key.VRF, key.Prefix)
	}
	return v.GetHeadendV4OwnerIn(key.VRF, key.Prefix)
}

// createHeadend writes one entry in the family's map.
func createHeadend(ops MapOps, af Family, key ID, entry *bpf.HeadendEntry, owner bpf.OwnerTag) error {
	v := perVRF(ops)
	if af == AFv6 {
		return v.CreateHeadendV6In(key.VRF, key.Prefix, entry, owner)
	}
	return v.CreateHeadendV4In(key.VRF, key.Prefix, entry, owner)
}

// deleteHeadend removes one entry from the family's map.
func deleteHeadend(ops MapOps, af Family, key ID, owner bpf.OwnerTag) error {
	v := perVRF(ops)
	if af == AFv6 {
		return v.DeleteHeadendV6In(key.VRF, key.Prefix, owner)
	}
	return v.DeleteHeadendV4In(key.VRF, key.Prefix, owner)
}
