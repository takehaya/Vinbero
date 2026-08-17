package cplane

import (
	"errors"
	"testing"

	"github.com/takehaya/vinbero/pkg/bpf"
)

const (
	ownerA = bpf.OwnerTag("plugin:v1:bundle=a")
	ownerB = bpf.OwnerTag("plugin:v1:bundle=b")
)

func TestAcquireAndHolder(t *testing.T) {
	l := NewLeases()
	if err := l.Acquire(LeaseHeadendV4, "10.0.0.0/24", ownerA); err != nil {
		t.Fatalf("acquire: %v", err)
	}
	holder, ok := l.HolderOf(LeaseHeadendV4, "10.0.0.0/24")
	if !ok || holder != ownerA {
		t.Fatalf("HolderOf = (%q, %v), want ownerA", holder, ok)
	}
}

func TestAcquireIsIdempotentForSameOwner(t *testing.T) {
	l := NewLeases()
	if err := l.Acquire(LeaseHeadendV4, "10.0.0.0/24", ownerA); err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if err := l.Acquire(LeaseHeadendV4, "10.0.0.0/24", ownerA); err != nil {
		t.Fatalf("re-acquire by the same owner: %v", err)
	}
}

func TestAcquireFailsClosedAcrossOwners(t *testing.T) {
	l := NewLeases()
	if err := l.Acquire(LeaseHeadendV4, "10.0.0.0/24", ownerA); err != nil {
		t.Fatalf("acquire: %v", err)
	}
	err := l.Acquire(LeaseHeadendV4, "10.0.0.0/24", ownerB)
	if err == nil {
		t.Fatal("a second owner acquiring the same key must fail")
	}
	if !errors.Is(err, ErrLeaseHeld) {
		t.Fatalf("error %v does not unwrap to ErrLeaseHeld", err)
	}
	var le *LeaseError
	if !errors.As(err, &le) || le.Holder != ownerA {
		t.Fatalf("error does not name the holder: %v", err)
	}
	if holder, _ := l.HolderOf(LeaseHeadendV4, "10.0.0.0/24"); holder != ownerA {
		t.Error("a rejected acquire must not move the lease")
	}
}

// Keys live in separate spaces per kind, so a headend prefix and an
// advertised NLRI that render the same string do not collide.
func TestKindsAreSeparateKeySpaces(t *testing.T) {
	l := NewLeases()
	if err := l.Acquire(LeaseHeadendV4, "10.0.0.0/24", ownerA); err != nil {
		t.Fatalf("acquire v4: %v", err)
	}
	if err := l.Acquire(LeaseAdvertise, "10.0.0.0/24", ownerB); err != nil {
		t.Fatalf("the same key in another kind must be free: %v", err)
	}
}

func TestAcquireAllIsAllOrNothing(t *testing.T) {
	l := NewLeases()
	if err := l.Acquire(LeaseHeadendV4, "10.0.2.0/24", ownerB); err != nil {
		t.Fatalf("setup: %v", err)
	}
	keys := []string{"10.0.1.0/24", "10.0.2.0/24"}
	if err := l.AcquireAll(LeaseHeadendV4, keys, ownerA); err == nil {
		t.Fatal("a set containing a contested key must be rejected whole")
	}
	if _, ok := l.HolderOf(LeaseHeadendV4, "10.0.1.0/24"); ok {
		t.Error("the free key was taken despite the set being rejected")
	}
}

func TestAcquireAllSucceedsAndIsRepeatable(t *testing.T) {
	l := NewLeases()
	keys := []string{"10.0.1.0/24", "10.0.2.0/24"}
	if err := l.AcquireAll(LeaseHeadendV4, keys, ownerA); err != nil {
		t.Fatalf("acquire all: %v", err)
	}
	if err := l.AcquireAll(LeaseHeadendV4, keys, ownerA); err != nil {
		t.Fatalf("re-declaring the same set: %v", err)
	}
	got := l.KeysOf(LeaseHeadendV4, ownerA)
	if len(got) != 2 {
		t.Fatalf("KeysOf returned %d keys, want 2", len(got))
	}
}

func TestReleaseOnlyByHolder(t *testing.T) {
	l := NewLeases()
	if err := l.Acquire(LeaseHeadendV4, "10.0.0.0/24", ownerA); err != nil {
		t.Fatalf("acquire: %v", err)
	}
	l.Release(LeaseHeadendV4, "10.0.0.0/24", ownerB) // not the holder
	if holder, _ := l.HolderOf(LeaseHeadendV4, "10.0.0.0/24"); holder != ownerA {
		t.Fatal("a non-holder released someone else's lease")
	}
	l.Release(LeaseHeadendV4, "10.0.0.0/24", ownerA)
	if _, ok := l.HolderOf(LeaseHeadendV4, "10.0.0.0/24"); ok {
		t.Fatal("the holder's release did not free the key")
	}
}

func TestReleaseOwnerClearsEveryKind(t *testing.T) {
	l := NewLeases()
	if err := l.Acquire(LeaseHeadendV4, "10.0.0.0/24", ownerA); err != nil {
		t.Fatalf("acquire v4: %v", err)
	}
	if err := l.Acquire(LeaseHeadendV6, "2001:db8::/32", ownerA); err != nil {
		t.Fatalf("acquire v6: %v", err)
	}
	if err := l.Acquire(LeaseAdvertise, "vpnv4|10.0.0.0/24", ownerB); err != nil {
		t.Fatalf("acquire advertise: %v", err)
	}

	l.ReleaseOwner(ownerA)

	if _, ok := l.HolderOf(LeaseHeadendV4, "10.0.0.0/24"); ok {
		t.Error("v4 lease survived ReleaseOwner")
	}
	if _, ok := l.HolderOf(LeaseHeadendV6, "2001:db8::/32"); ok {
		t.Error("v6 lease survived ReleaseOwner")
	}
	if holder, ok := l.HolderOf(LeaseAdvertise, "vpnv4|10.0.0.0/24"); !ok || holder != ownerB {
		t.Error("ReleaseOwner dropped another owner's lease")
	}
}

func TestEmptyOwnerRejected(t *testing.T) {
	l := NewLeases()
	if err := l.Acquire(LeaseHeadendV4, "10.0.0.0/24", ""); !errors.Is(err, bpf.ErrEmptyOwner) {
		t.Fatalf("Acquire with an empty owner = %v, want ErrEmptyOwner", err)
	}
	if err := l.AcquireAll(LeaseHeadendV4, []string{"10.0.0.0/24"}, ""); !errors.Is(err, bpf.ErrEmptyOwner) {
		t.Fatalf("AcquireAll with an empty owner = %v, want ErrEmptyOwner", err)
	}
}
