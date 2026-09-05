package headend

import (
	"fmt"
	"net/netip"
	"sync"

	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/ownership"
)

// Writer is the incremental headend surface used by built-in appliers.
// Owner reads support migration from a previous owner format; removal still
// checks the observed owner, so migration cannot delete a concurrent replacement.
type Writer interface {
	CreateHeadendV4(string, *bpf.HeadendEntry, bpf.OwnerTag) error
	CreateHeadendV6(string, *bpf.HeadendEntry, bpf.OwnerTag) error
	DeleteHeadendV4(string, bpf.OwnerTag) error
	DeleteHeadendV6(string, bpf.OwnerTag) error
	GetHeadendV4Owner(string) (bpf.OwnerTag, bool, error)
	GetHeadendV6Owner(string) (bpf.OwnerTag, bool, error)
}

// Reconciler serializes each owner's declarations and incremental writes against
// the same maps and leases. Share one instance across all participating writers.
// It does not select between competing intents: another owner's key is refused.
// Operator RPCs may still write directly to MapOps, whose owner checks remain
// authoritative; this lock is not a transaction with those external writers.
type Reconciler struct {
	mu     sync.Mutex
	owners map[bpf.OwnerTag]*ownerLock
	maps   MapOps
	leases *ownership.Leases
}

type ownerLock struct {
	mu   sync.Mutex
	refs int
}

func NewReconciler(maps MapOps, leases *ownership.Leases) (*Reconciler, error) {
	if maps == nil {
		return nil, fmt.Errorf("headend reconciler: nil map ops")
	}
	if leases == nil {
		leases = ownership.NewLeases()
	}
	return &Reconciler{maps: maps, leases: leases, owners: make(map[bpf.OwnerTag]*ownerLock)}, nil
}

// lockOwner excludes a same-owner incremental update from a full-set diff.
// Different owners reserve contested keys through leases. In particular a BGP
// watch callback must not wait for a plugin's full-map scan on unrelated keys.
// Reference counting removes idle locks, including owners of withdrawn MUP routes.
func (r *Reconciler) lockOwner(owner bpf.OwnerTag) func() {
	r.mu.Lock()
	l := r.owners[owner]
	if l == nil {
		l = &ownerLock{}
		r.owners[owner] = l
	}
	l.refs++
	r.mu.Unlock()
	l.mu.Lock()
	return func() {
		l.mu.Unlock()
		r.mu.Lock()
		l.refs--
		if l.refs == 0 {
			delete(r.owners, owner)
		}
		r.mu.Unlock()
	}
}

// Leases returns the shared table, also used for advertisement ownership and
// per-owner accounting. Headend mutations must go through the reconciler.
func (r *Reconciler) Leases() *ownership.Leases { return r.leases }

func (r *Reconciler) ApplySet(owner bpf.OwnerTag, af Family, desired []Desired, quota int) (Result, error) {
	defer r.lockOwner(owner)()
	return ApplySet(r.maps, r.leases, owner, af, desired, quota)
}

func (r *Reconciler) PruneOwner(owner bpf.OwnerTag, af Family) (int, error) {
	defer r.lockOwner(owner)()
	return PruneOwner(r.maps, r.leases, owner, af)
}

func (r *Reconciler) OwnedEntries(owner bpf.OwnerTag, af Family) ([]Desired, error) {
	defer r.lockOwner(owner)()
	return OwnedEntries(r.maps, owner, af)
}

func (r *Reconciler) CreateHeadendV4(prefix string, entry *bpf.HeadendEntry, owner bpf.OwnerTag) error {
	return r.put(AFv4, prefix, entry, owner)
}

func (r *Reconciler) CreateHeadendV6(prefix string, entry *bpf.HeadendEntry, owner bpf.OwnerTag) error {
	return r.put(AFv6, prefix, entry, owner)
}

// put touches only the named key. A built-in route update must not scan the
// whole map or replace the other prefixes held by that built-in's owner.
func (r *Reconciler) put(af Family, prefix string, entry *bpf.HeadendEntry, owner bpf.OwnerTag) error {
	if owner == "" {
		return bpf.ErrEmptyOwner
	}
	key, err := canonicalPrefix(af, prefix)
	if err != nil {
		return err
	}
	if entry == nil {
		return fmt.Errorf("write %s: nil entry for %q", af, key)
	}
	defer r.lockOwner(owner)()
	currentOwner, found, err := getOwner(r.maps, af, key)
	if err != nil {
		return err
	}
	if found && currentOwner != owner {
		return ownerConflict(af, key, currentOwner, owner)
	}
	taken, err := r.leases.AcquireAll(af.leaseKind(), []string{key}, owner)
	if err != nil {
		return err
	}
	if err := createHeadend(r.maps, af, key, entry, owner); err != nil {
		// A pinned entry adopted by this call still needs its lease if an
		// update fails. A failed creation of a new key needs no reservation.
		if !found {
			releaseAll(r.leases, af, taken, owner)
		}
		return err
	}
	return nil
}

func (r *Reconciler) DeleteHeadendV4(prefix string, owner bpf.OwnerTag) error {
	return r.remove(AFv4, prefix, owner)
}

func (r *Reconciler) DeleteHeadendV6(prefix string, owner bpf.OwnerTag) error {
	return r.remove(AFv6, prefix, owner)
}

func (r *Reconciler) remove(af Family, prefix string, owner bpf.OwnerTag) error {
	if owner == "" {
		return bpf.ErrEmptyOwner
	}
	key, err := canonicalPrefix(af, prefix)
	if err != nil {
		return err
	}
	defer r.lockOwner(owner)()
	currentOwner, found, err := getOwner(r.maps, af, key)
	if err != nil {
		return err
	}
	if found && currentOwner != owner {
		return ownerConflict(af, key, currentOwner, owner)
	}
	// Even an absent key may be reserved by another owner's in-flight
	// creation. Do not delete its main entry before its owner record lands.
	taken, err := r.leases.AcquireAll(af.leaseKind(), []string{key}, owner)
	if err != nil {
		return err
	}
	if err := deleteHeadend(r.maps, af, key, owner); err != nil {
		if !found {
			releaseAll(r.leases, af, taken, owner)
		}
		return err
	}
	r.leases.Release(af.leaseKind(), key, owner)
	return nil
}

func (r *Reconciler) GetHeadendV4Owner(prefix string) (bpf.OwnerTag, bool, error) {
	return getOwner(r.maps, AFv4, prefix)
}

func (r *Reconciler) GetHeadendV6Owner(prefix string) (bpf.OwnerTag, bool, error) {
	return getOwner(r.maps, AFv6, prefix)
}

func getOwner(ops MapOps, af Family, prefix string) (bpf.OwnerTag, bool, error) {
	if af == AFv6 {
		return ops.GetHeadendV6Owner(prefix)
	}
	return ops.GetHeadendV4Owner(prefix)
}

func ownerConflict(af Family, prefix string, holder, caller bpf.OwnerTag) error {
	return fmt.Errorf("%s key %q: %w: existing %q, caller %q", af, prefix, bpf.ErrEntryOwnerMismatch, holder, caller)
}

func canonicalPrefix(af Family, raw string) (string, error) {
	if af != AFv4 && af != AFv6 {
		return "", fmt.Errorf("invalid headend family %d", af)
	}
	prefix, err := netip.ParsePrefix(raw)
	if err != nil {
		return "", fmt.Errorf("%s prefix %q: %w", af, raw, err)
	}
	if prefix.Addr().Is4In6() || prefix.Addr().Is4() != (af == AFv4) {
		return "", fmt.Errorf("%s prefix %q: address family mismatch", af, raw)
	}
	return prefix.Masked().String(), nil
}
