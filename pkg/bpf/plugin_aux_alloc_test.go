package bpf

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// TestIndexAllocatorOwnerRoundTrip covers the happy path: owner tag is
// recorded at Alloc and respected at Free.
func TestIndexAllocatorOwnerRoundTrip(t *testing.T) {
	a := newIndexAllocator(16)

	idx, err := a.AllocOwner("test-owner")
	if err != nil {
		t.Fatalf("AllocOwner: %v", err)
	}
	if idx == 0 {
		t.Fatal("AllocOwner returned sentinel 0")
	}
	if got := a.OwnerOf(idx); got != "test-owner" {
		t.Errorf("OwnerOf: got %q, want %q", got, "test-owner")
	}
	if err := a.FreeOwner(idx, "test-owner"); err != nil {
		t.Fatalf("FreeOwner: %v", err)
	}
	if got := a.OwnerOf(idx); got != "" {
		t.Errorf("OwnerOf after free: got %q, want \"\"", got)
	}
}

// TestIndexAllocatorOwnerMismatch ensures cross-owner Free is rejected and
// leaves the allocator state untouched.
func TestIndexAllocatorOwnerMismatch(t *testing.T) {
	a := newIndexAllocator(16)

	idx, err := a.AllocOwner("owner-a")
	if err != nil {
		t.Fatalf("AllocOwner: %v", err)
	}
	err = a.FreeOwner(idx, "owner-b")
	if err == nil {
		t.Fatal("expected ErrOwnerMismatch, got nil")
	}
	if !errors.Is(err, ErrOwnerMismatch) {
		t.Errorf("got %v, want ErrOwnerMismatch", err)
	}
	// Index must still belong to owner-a after the failed free.
	if got := a.OwnerOf(idx); got != "owner-a" {
		t.Errorf("OwnerOf after failed free: got %q, want owner-a", got)
	}
	// And owner-a can still free it cleanly.
	if err := a.FreeOwner(idx, "owner-a"); err != nil {
		t.Errorf("owner-a FreeOwner after mismatch: %v", err)
	}
}

// TestIndexAllocatorFreeUnallocated guards against "free something that was
// never allocated" becoming a silent no-op.
func TestIndexAllocatorFreeUnallocated(t *testing.T) {
	a := newIndexAllocator(16)
	err := a.FreeOwner(42, "anyone")
	if !errors.Is(err, ErrOwnerMismatch) {
		t.Errorf("expected ErrOwnerMismatch, got %v", err)
	}
}

// TestIndexAllocatorExhaustion verifies the pool bound kicks in.
func TestIndexAllocatorExhaustion(t *testing.T) {
	a := newIndexAllocator(4) // max=4 → indices 1..3 usable (0 is sentinel)
	got := []uint32{}
	for range 3 {
		idx, err := a.AllocOwner("t")
		if err != nil {
			t.Fatalf("unexpected alloc failure: %v", err)
		}
		got = append(got, idx)
	}
	if _, err := a.AllocOwner("t"); err == nil {
		t.Fatal("expected exhaustion error, got nil")
	}
	// Freeing one should make room again.
	if err := a.FreeOwner(got[0], "t"); err != nil {
		t.Fatalf("free: %v", err)
	}
	if _, err := a.AllocOwner("t"); err != nil {
		t.Errorf("alloc after free: %v", err)
	}
}

// TestIndexAllocatorRecoverWithOwners covers the recovery path used on
// startup: restore owners from a live-index map, rebuild the free list.
func TestIndexAllocatorRecoverWithOwners(t *testing.T) {
	a := newIndexAllocator(16)

	// Simulate an older state: indices 1, 3, 5 in use with different owners.
	a.RecoverWithOwners(map[uint32]string{
		1: AuxOwnerBuiltin,
		3: AuxOwnerPluginTag("endpoint", 32),
		5: AuxOwnerBuiltin,
	})

	if got := a.OwnerOf(1); got != AuxOwnerBuiltin {
		t.Errorf("idx 1 owner: got %q", got)
	}
	if got := a.OwnerOf(3); got != "plugin:endpoint:32" {
		t.Errorf("idx 3 owner: got %q", got)
	}

	// Next allocation should come from the gap (2 or 4, LIFO order).
	next, err := a.AllocOwner("next")
	if err != nil {
		t.Fatalf("alloc: %v", err)
	}
	if next != 2 && next != 4 {
		t.Errorf("expected recovered gap 2 or 4, got %d", next)
	}
}

// TestIndexAllocatorRejectsEmptyOwner keeps AllocOwner("") from accidentally
// creating indices with a default-zero tag that would match every caller.
func TestIndexAllocatorRejectsEmptyOwner(t *testing.T) {
	a := newIndexAllocator(4)
	if _, err := a.AllocOwner(""); err == nil {
		t.Error("AllocOwner(\"\") should fail")
	}
}

// TestIndexAllocatorWithOwnerLockedSerializesFree verifies that FreeOwner
// blocks while a concurrent WithOwnerLocked is still inside its callback.
// This is the property that closes the TOCTOU window for callers that need
// "owner check + map op" to be atomic against PluginAuxFree.
func TestIndexAllocatorWithOwnerLockedSerializesFree(t *testing.T) {
	a := newIndexAllocator(16)
	idx, err := a.AllocOwner("owner-a")
	if err != nil {
		t.Fatalf("AllocOwner: %v", err)
	}

	const slowFnDuration = 50 * time.Millisecond
	started := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = a.WithOwnerLocked(idx, "owner-a", func() error {
			close(started)
			time.Sleep(slowFnDuration)
			return nil
		})
	}()

	// Make sure goroutine A actually entered the critical section before we
	// start measuring; otherwise B could finish before A even runs.
	<-started

	freeStart := time.Now()
	if err := a.FreeOwner(idx, "owner-a"); err != nil {
		t.Fatalf("FreeOwner: %v", err)
	}
	elapsed := time.Since(freeStart)

	// Use a generous lower bound (40ms) to absorb scheduler jitter while
	// still proving Free was blocked behind WithOwnerLocked.
	if elapsed < 40*time.Millisecond {
		t.Errorf("FreeOwner returned in %v; expected >=40ms (serialization broken)",
			elapsed)
	}

	wg.Wait()
}

// TestIndexAllocatorConcurrentAllocFree stresses Alloc/Free under the race
// detector to catch any unsynchronized access to freeList / owners /
// nextNew. After the storm settles every index must be free again.
func TestIndexAllocatorConcurrentAllocFree(t *testing.T) {
	const goroutines = 100
	const iterations = 1000
	const maxIndex = 256
	a := newIndexAllocator(maxIndex)

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for range iterations {
				idx, err := a.AllocOwner("stress")
				if err != nil {
					// Pool exhaustion is acceptable here (concurrent peak
					// load can hit the cap); just retry next iteration.
					continue
				}
				if err := a.FreeOwner(idx, "stress"); err != nil {
					t.Errorf("FreeOwner: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()

	for i := uint32(1); i < maxIndex; i++ {
		if got := a.OwnerOf(i); got != "" {
			t.Errorf("idx %d owner after stress: %q, want empty", i, got)
		}
	}
}
