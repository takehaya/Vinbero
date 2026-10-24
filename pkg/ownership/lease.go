// Package ownership tracks exclusive resource leases shared by host controllers.
package ownership

import (
	"fmt"
	"sync"

	"github.com/takehaya/vinbero/pkg/bpf"
)

// LeaseKind names a key space that leases are tracked in. Keys are only
// ever compared within one kind, so a headend prefix and an advertised
// NLRI that happen to render the same string never collide.
type LeaseKind string

const (
	// LeaseHeadendV4 covers headend_v4_map trigger prefixes.
	LeaseHeadendV4 LeaseKind = "headend_v4"
	// LeaseHeadendV6 covers headend_v6_map trigger prefixes.
	LeaseHeadendV6 LeaseKind = "headend_v6"
	// LeaseAdvertise covers advertised routes, keyed by family and NLRI.
	LeaseAdvertise LeaseKind = "advertise"
)

// ErrLeaseHeld is returned when a key is already leased by another owner.
// Callers can map it to a permission-denied style error.
var ErrLeaseHeld = fmt.Errorf("key is leased by another owner")

// LeaseError carries who holds the contested key, so an operator reading
// the message can tell which plugin to look at.
type LeaseError struct {
	Kind   LeaseKind
	Key    string
	Holder bpf.OwnerTag
}

func (e *LeaseError) Error() string {
	return fmt.Sprintf("%s key %q is leased by %q", e.Kind, e.Key, e.Holder)
}

func (e *LeaseError) Unwrap() error { return ErrLeaseHeld }

// Denied marks this as a policy refusal rather than a host failure, so a
// caller can tell a plugin "narrow your set" instead of "something broke".
// The plugin runtime tests for this behaviourally, which keeps it from
// having to import this package.
func (e *LeaseError) Denied() bool { return true }

// Leases records which owner holds each writable key.
//
// It exists because a desired set is reconciled per owner: the core diffs
// an owner's declaration against what that owner already holds, so two
// owners declaring the same key would each see a consistent view of their
// own set while quietly fighting over one map entry. The lease makes that
// collision explicit at declaration time.
//
// For BPF maps this is a front line, not the enforcement: the per-entry
// owner map in pkg/bpf still refuses a cross-owner write, so a key that
// escapes the lease (an entry written before the daemon started, say)
// fails at the map. The lease exists to fail early, with a message naming
// the other holder, and to cover key spaces that have no owner map of
// their own.
type Leases struct {
	mu sync.Mutex
	// held maps kind -> key -> owner.
	held map[LeaseKind]map[string]bpf.OwnerTag
}

// NewLeases builds an empty lease table.
func NewLeases() *Leases {
	return &Leases{held: make(map[LeaseKind]map[string]bpf.OwnerTag)}
}

// Acquire takes the lease on one key. Re-acquiring a key the same owner
// already holds succeeds, so a repeated declaration is idempotent.
func (l *Leases) Acquire(kind LeaseKind, key string, owner bpf.OwnerTag) error {
	if owner == "" {
		return bpf.ErrEmptyOwner
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.acquireLocked(kind, key, owner)
}

// acquireLocked is Acquire without the lock, for use inside AcquireAll.
func (l *Leases) acquireLocked(kind LeaseKind, key string, owner bpf.OwnerTag) error {
	byKey, ok := l.held[kind]
	if !ok {
		byKey = make(map[string]bpf.OwnerTag)
		l.held[kind] = byKey
	}
	if holder, taken := byKey[key]; taken && holder != owner {
		return &LeaseError{Kind: kind, Key: key, Holder: holder}
	}
	byKey[key] = owner
	return nil
}

// AcquireAll takes the leases on every key or none of them. A desired set
// is applied as a unit, so a partial acquisition would leave the owner
// holding keys for a declaration that was rejected.
// The keys it returns are the ones this call took, excluding those the
// owner already held. Only those may be rolled back: releasing a key the
// owner held from an earlier apply would drop the lease on an entry that
// is still in the map, and let another owner take it.
func (l *Leases) AcquireAll(kind LeaseKind, keys []string, owner bpf.OwnerTag) ([]string, error) {
	if owner == "" {
		return nil, bpf.ErrEmptyOwner
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	byKey := l.held[kind]
	for _, key := range keys {
		if holder, taken := byKey[key]; taken && holder != owner {
			return nil, &LeaseError{Kind: kind, Key: key, Holder: holder}
		}
	}
	var taken []string
	for _, key := range keys {
		if holder, held := l.held[kind][key]; held && holder == owner {
			continue
		}
		if err := l.acquireLocked(kind, key, owner); err != nil {
			// Unreachable: the loop above already cleared every key.
			return taken, err
		}
		taken = append(taken, key)
	}
	return taken, nil
}

// Release drops one key if owner holds it. Releasing a key held by someone
// else is a no-op, so a stale release cannot steal a lease.
func (l *Leases) Release(kind LeaseKind, key string, owner bpf.OwnerTag) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if byKey, ok := l.held[kind]; ok {
		if holder, taken := byKey[key]; taken && holder == owner {
			delete(byKey, key)
		}
	}
}

// ReleaseOwner drops every lease held by owner, across all kinds. This is
// what unregistering a plugin runs.
func (l *Leases) ReleaseOwner(owner bpf.OwnerTag) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, byKey := range l.held {
		for key, holder := range byKey {
			if holder == owner {
				delete(byKey, key)
			}
		}
	}
}

// HolderOf reports which owner holds a key.
func (l *Leases) HolderOf(kind LeaseKind, key string) (bpf.OwnerTag, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	holder, ok := l.held[kind][key]
	return holder, ok
}

// CountOf is how many keys owner holds in one kind.
func (l *Leases) CountOf(kind LeaseKind, owner bpf.OwnerTag) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	var n int
	for _, holder := range l.held[kind] {
		if holder == owner {
			n++
		}
	}
	return n
}

// KeysOf returns the keys owner holds in one kind. The order is
// unspecified.
func (l *Leases) KeysOf(kind LeaseKind, owner bpf.OwnerTag) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	for key, holder := range l.held[kind] {
		if holder == owner {
			out = append(out, key)
		}
	}
	return out
}
