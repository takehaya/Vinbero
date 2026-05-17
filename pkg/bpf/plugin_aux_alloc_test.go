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
	if got := a.OwnerOf(3); got != "plugin:v1:endpoint:32" {
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

// TestParseAuxOwnerTag covers every persisted format we promise to
// understand: the legacy unversioned "plugin:endpoint:32" / "builtin" of
// the version-stamped "plugin:v1:endpoint:32" / "builtin:v1", and
// well-formed errors for malformed inputs. The migration contract:
// ParseAuxOwnerTag must accept the legacy unversioned pins so old pin
// directories remain readable.
func TestParseAuxOwnerTag(t *testing.T) {
	cases := []struct {
		name        string
		in          string
		wantKind    string
		wantMapType string
		wantSlot    uint32
		wantErr     bool
	}{
		{"plugin_versioned", "plugin:v1:endpoint:32", AuxOwnerKindPlugin, "endpoint", 32, false},
		{"plugin_legacy", "plugin:endpoint:32", AuxOwnerKindPlugin, "endpoint", 32, false},
		{"plugin_versioned_headend", "plugin:v1:headend_v4:16", AuxOwnerKindPlugin, "headend_v4", 16, false},
		{"builtin_versioned", "builtin:v1", AuxOwnerKindBuiltin, "", 0, false},
		{"builtin_legacy", "builtin", AuxOwnerKindBuiltin, "", 0, false},
		{"empty", "", "", "", 0, true},
		{"unknown_scheme", "weird:thing", "", "", 0, true},
		{"plugin_too_few_segments", "plugin:foo", "", "", 0, true},
		{"plugin_bad_slot", "plugin:v1:endpoint:notanumber", "", "", 0, true},
		{"builtin_extra_segments", "builtin:v1:extra", "", "", 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			kind, mt, slot, err := ParseAuxOwnerTag(c.in)
			if c.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil (kind=%q mt=%q slot=%d)", kind, mt, slot)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if kind != c.wantKind {
				t.Errorf("kind: got %q want %q", kind, c.wantKind)
			}
			if mt != c.wantMapType {
				t.Errorf("mapType: got %q want %q", mt, c.wantMapType)
			}
			if slot != c.wantSlot {
				t.Errorf("slot: got %d want %d", slot, c.wantSlot)
			}
		})
	}
}

// TestAuxOwnerPluginTag_VersionStamped pins the wire format. CI catches
// accidental rewrites that would corrupt running clusters' pins.
func TestAuxOwnerPluginTag_VersionStamped(t *testing.T) {
	if got := AuxOwnerPluginTag("endpoint", 32); got != "plugin:v1:endpoint:32" {
		t.Errorf("plugin tag: got %q want plugin:v1:endpoint:32", got)
	}
	if got := AuxOwnerBuiltinTag; got != "builtin:v1" {
		t.Errorf("builtin tag: got %q want builtin:v1", got)
	}
}

// TestFreeAllByOwner_Allocator covers the allocator-only path used when
// pinning is disabled. The MapOperations wrapper that adds sid_aux_map
// zero-writes is exercised by TestDeleteSidFunctionPreservesPluginAux
// under the BPF integration suite.
func TestFreeAllByOwner_Allocator(t *testing.T) {
	a := newIndexAllocator(64)

	// Mix two plugin owners and one builtin so we can verify only the
	// matching tag is freed.
	pluginA := AuxOwnerPluginTag("endpoint", 32)
	pluginB := AuxOwnerPluginTag("endpoint", 33)
	for range 3 {
		if _, err := a.AllocOwner(pluginA); err != nil {
			t.Fatalf("alloc A: %v", err)
		}
	}
	if _, err := a.AllocOwner(pluginB); err != nil {
		t.Fatalf("alloc B: %v", err)
	}
	if _, err := a.AllocOwner(AuxOwnerBuiltin); err != nil {
		t.Fatalf("alloc builtin: %v", err)
	}

	// Purge only pluginA.
	if got := a.FreeAllByOwner(pluginA); got != 3 {
		t.Errorf("FreeAllByOwner: got %d, want 3", got)
	}
	if got := a.countByOwner(pluginA); got != 0 {
		t.Errorf("post-purge pluginA count: %d, want 0", got)
	}
	if got := a.countByOwner(pluginB); got != 1 {
		t.Errorf("pluginB must survive: %d, want 1", got)
	}
	if got := a.countByOwner(AuxOwnerBuiltin); got != 1 {
		t.Errorf("builtin must survive: %d, want 1", got)
	}

	// Purging an empty owner returns 0, not an error.
	if got := a.FreeAllByOwner("plugin:v1:endpoint:99"); got != 0 {
		t.Errorf("empty purge: got %d, want 0", got)
	}
}

// TestListAuxByOwner verifies the filter semantics used by PluginAuxList
// without needing a BPF map. Unfiltered returns everything; filtered by
// map_type returns only matching plugin tags; filtered by map_type + slot
// (match_slot=true) further restricts to one slot.
func TestListAuxByOwner(t *testing.T) {
	a := newIndexAllocator(64)
	endpoint32 := AuxOwnerPluginTag("endpoint", 32)
	endpoint33 := AuxOwnerPluginTag("endpoint", 33)
	headend := AuxOwnerPluginTag("headend_v4", 16)

	for _, owner := range []string{endpoint32, endpoint33, headend, AuxOwnerBuiltin} {
		if _, err := a.AllocOwner(owner); err != nil {
			t.Fatalf("alloc %s: %v", owner, err)
		}
	}

	all := a.listByOwner("", 0, false)
	if len(all) != 4 {
		t.Errorf("unfiltered: got %d entries, want 4", len(all))
	}
	// All persisted owners should round-trip cleanly.
	for _, e := range all {
		if _, _, _, err := ParseAuxOwnerTag(e.Owner); err != nil {
			t.Errorf("persisted owner %q does not parse: %v", e.Owner, err)
		}
	}

	endpointOnly := a.listByOwner("endpoint", 0, false)
	if len(endpointOnly) != 2 {
		t.Errorf("endpoint-only: got %d entries, want 2", len(endpointOnly))
	}

	endpoint32Only := a.listByOwner("endpoint", 32, true)
	if len(endpoint32Only) != 1 {
		t.Errorf("endpoint:32: got %d entries, want 1", len(endpoint32Only))
	}
	if endpoint32Only[0].Owner != endpoint32 {
		t.Errorf("endpoint:32 owner: got %q want %q", endpoint32Only[0].Owner, endpoint32)
	}
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
