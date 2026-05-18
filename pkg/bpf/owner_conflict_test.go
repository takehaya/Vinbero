package bpf

import (
	"errors"
	"testing"
)

// TestEntryOwnerConflictMatrix covers the contract that Create / Delete /
// Flush on a main map respect the OwnerTag recorded in the paired owner
// map. The scenarios mirror the cross-owner cases the BGP integration
// must navigate when both a Connect RPC and a BGP UPDATE try to mutate
// the same prefix.
func TestEntryOwnerConflictMatrix(t *testing.T) {
	h := newXDPTestHelper(t)

	const prefix = "fc00:dead::/128"
	bgpOwner := OwnerBGPVPN(65000, "65000:100")

	t.Run("same-owner-overwrite-allowed", func(t *testing.T) {
		entry := &SidFunctionEntry{Action: uint8(1)}
		if err := h.mapOps.CreateSidFunction(prefix, entry, nil, OwnerRPC); err != nil {
			t.Fatalf("first create: %v", err)
		}
		t.Cleanup(func() { _ = h.mapOps.ForceDeleteSidFunction(prefix) })

		entry2 := &SidFunctionEntry{Action: uint8(2)}
		if err := h.mapOps.CreateSidFunction(prefix, entry2, nil, OwnerRPC); err != nil {
			t.Errorf("re-create with same owner rejected: %v", err)
		}
	})

	t.Run("cross-owner-create-rejected", func(t *testing.T) {
		// Different prefix so the subtest is hermetic.
		const p = "fc00:beef::/128"
		entry := &SidFunctionEntry{Action: uint8(1)}
		if err := h.mapOps.CreateSidFunction(p, entry, nil, OwnerRPC); err != nil {
			t.Fatalf("seed: %v", err)
		}
		t.Cleanup(func() { _ = h.mapOps.ForceDeleteSidFunction(p) })

		err := h.mapOps.CreateSidFunction(p, entry, nil, bgpOwner)
		if !errors.Is(err, ErrEntryOwnerMismatch) {
			t.Errorf("cross-owner create: got %v, want ErrEntryOwnerMismatch", err)
		}
	})

	t.Run("cross-owner-delete-rejected", func(t *testing.T) {
		const p = "fc00:cafe::/128"
		entry := &SidFunctionEntry{Action: uint8(1)}
		if err := h.mapOps.CreateSidFunction(p, entry, nil, OwnerRPC); err != nil {
			t.Fatalf("seed: %v", err)
		}
		t.Cleanup(func() { _ = h.mapOps.ForceDeleteSidFunction(p) })

		err := h.mapOps.DeleteSidFunction(p, bgpOwner)
		if !errors.Is(err, ErrEntryOwnerMismatch) {
			t.Errorf("cross-owner delete: got %v, want ErrEntryOwnerMismatch", err)
		}
		// Entry must survive the rejected delete.
		if _, err := h.mapOps.GetSidFunction(p); err != nil {
			t.Errorf("entry vanished after rejected delete: %v", err)
		}
	})

	t.Run("force-override-delete-allowed", func(t *testing.T) {
		const p = "fc00:f00d::/128"
		entry := &SidFunctionEntry{Action: uint8(1)}
		if err := h.mapOps.CreateSidFunction(p, entry, nil, OwnerRPC); err != nil {
			t.Fatalf("seed: %v", err)
		}
		// force=true must allow a delete from a foreign caller.
		if err := h.mapOps.ForceDeleteSidFunction(p); err != nil {
			t.Errorf("force delete rejected: %v", err)
		}
		if _, err := h.mapOps.GetSidFunction(p); err == nil {
			t.Errorf("force delete left entry behind")
		}
	})

	t.Run("flush-owner-scoped", func(t *testing.T) {
		// Seed two RPC entries and two BGP entries, then flush only RPC scope.
		// BGP entries must survive.
		rpcPrefixes := []string{"fc00:1::/128", "fc00:2::/128"}
		bgpPrefixes := []string{"fc00:3::/128", "fc00:4::/128"}
		for _, p := range rpcPrefixes {
			if err := h.mapOps.CreateSidFunction(p, &SidFunctionEntry{Action: uint8(1)}, nil, OwnerRPC); err != nil {
				t.Fatalf("seed RPC %q: %v", p, err)
			}
		}
		for _, p := range bgpPrefixes {
			if err := h.mapOps.CreateSidFunction(p, &SidFunctionEntry{Action: uint8(1)}, nil, bgpOwner); err != nil {
				t.Fatalf("seed BGP %q: %v", p, err)
			}
		}
		t.Cleanup(func() {
			for _, p := range append(rpcPrefixes, bgpPrefixes...) {
				_ = h.mapOps.ForceDeleteSidFunction(p)
			}
		})

		n, err := h.mapOps.FlushSidFunctions(OwnerRPC)
		if err != nil {
			t.Fatalf("flush RPC scope: %v", err)
		}
		if n != uint32(len(rpcPrefixes)) {
			t.Errorf("flush deleted %d entries, want %d", n, len(rpcPrefixes))
		}
		for _, p := range rpcPrefixes {
			if _, err := h.mapOps.GetSidFunction(p); err == nil {
				t.Errorf("RPC entry %q survived owner-scoped flush", p)
			}
		}
		for _, p := range bgpPrefixes {
			if _, err := h.mapOps.GetSidFunction(p); err != nil {
				t.Errorf("BGP entry %q vanished from owner-scoped flush: %v", p, err)
			}
		}
	})

	t.Run("flush-force-all-owners", func(t *testing.T) {
		// Empty scope flushes everything regardless of owner.
		bgpPrefixes := []string{"fc00:5::/128", "fc00:6::/128"}
		for _, p := range bgpPrefixes {
			if err := h.mapOps.CreateSidFunction(p, &SidFunctionEntry{Action: uint8(1)}, nil, bgpOwner); err != nil {
				t.Fatalf("seed BGP %q: %v", p, err)
			}
		}
		n, err := h.mapOps.ForceFlushSidFunctions()
		if err != nil {
			t.Fatalf("flush all: %v", err)
		}
		if n < uint32(len(bgpPrefixes)) {
			t.Errorf("flush deleted %d entries, want >= %d", n, len(bgpPrefixes))
		}
	})

	t.Run("delete-removes-owner-record", func(t *testing.T) {
		const p = "fc00:7::/128"
		entry := &SidFunctionEntry{Action: uint8(1)}
		if err := h.mapOps.CreateSidFunction(p, entry, nil, OwnerRPC); err != nil {
			t.Fatalf("seed: %v", err)
		}
		if err := h.mapOps.DeleteSidFunction(p, OwnerRPC); err != nil {
			t.Fatalf("delete: %v", err)
		}
		// The owner record is now gone, so a brand-new owner can claim the slot.
		if err := h.mapOps.CreateSidFunction(p, entry, nil, bgpOwner); err != nil {
			t.Errorf("re-create after delete (different owner) rejected: %v", err)
		}
		t.Cleanup(func() { _ = h.mapOps.ForceDeleteSidFunction(p) })
	})
}

// TestHeadendV4OwnerConflictMatrix mirrors TestEntryOwnerConflictMatrix
// for headend_v4_map. The conflict semantics must hold uniformly across
// all three main maps; covering v4 explicitly catches regressions in
// the headendV4Owners wiring (key type, putMainAndOwner specialization).
func TestHeadendV4OwnerConflictMatrix(t *testing.T) {
	h := newXDPTestHelper(t)
	bgpOwner := OwnerBGPVPN(65000, "65000:200")

	t.Run("same-owner-overwrite-allowed", func(t *testing.T) {
		const p = "10.10.0.0/24"
		entry := &HeadendEntry{}
		if err := h.mapOps.CreateHeadendV4(p, entry, OwnerRPC); err != nil {
			t.Fatalf("first create: %v", err)
		}
		t.Cleanup(func() { _ = h.mapOps.ForceDeleteHeadendV4(p) })
		if err := h.mapOps.CreateHeadendV4(p, entry, OwnerRPC); err != nil {
			t.Errorf("re-create with same owner rejected: %v", err)
		}
	})

	t.Run("cross-owner-delete-rejected", func(t *testing.T) {
		const p = "10.20.0.0/24"
		if err := h.mapOps.CreateHeadendV4(p, &HeadendEntry{}, OwnerRPC); err != nil {
			t.Fatalf("seed: %v", err)
		}
		t.Cleanup(func() { _ = h.mapOps.ForceDeleteHeadendV4(p) })
		err := h.mapOps.DeleteHeadendV4(p, bgpOwner)
		if !errors.Is(err, ErrEntryOwnerMismatch) {
			t.Errorf("cross-owner delete: got %v, want ErrEntryOwnerMismatch", err)
		}
	})

	t.Run("force-delete-allowed", func(t *testing.T) {
		const p = "10.30.0.0/24"
		if err := h.mapOps.CreateHeadendV4(p, &HeadendEntry{}, OwnerRPC); err != nil {
			t.Fatalf("seed: %v", err)
		}
		if err := h.mapOps.ForceDeleteHeadendV4(p); err != nil {
			t.Errorf("force delete rejected: %v", err)
		}
	})

	t.Run("flush-owner-scoped", func(t *testing.T) {
		rpcPrefixes := []string{"10.40.0.0/24", "10.41.0.0/24"}
		bgpPrefixes := []string{"10.42.0.0/24", "10.43.0.0/24"}
		for _, p := range rpcPrefixes {
			if err := h.mapOps.CreateHeadendV4(p, &HeadendEntry{}, OwnerRPC); err != nil {
				t.Fatalf("seed RPC %q: %v", p, err)
			}
		}
		for _, p := range bgpPrefixes {
			if err := h.mapOps.CreateHeadendV4(p, &HeadendEntry{}, bgpOwner); err != nil {
				t.Fatalf("seed BGP %q: %v", p, err)
			}
		}
		t.Cleanup(func() {
			for _, p := range append(rpcPrefixes, bgpPrefixes...) {
				_ = h.mapOps.ForceDeleteHeadendV4(p)
			}
		})

		n, err := h.mapOps.FlushHeadendV4(OwnerRPC)
		if err != nil {
			t.Fatalf("flush RPC scope: %v", err)
		}
		if n != uint32(len(rpcPrefixes)) {
			t.Errorf("flush deleted %d, want %d", n, len(rpcPrefixes))
		}
		for _, p := range bgpPrefixes {
			if _, err := h.mapOps.GetHeadendV4(p); err != nil {
				t.Errorf("BGP entry %q vanished from owner-scoped flush", p)
			}
		}
	})
}

// TestHeadendV6OwnerConflictMatrix mirrors TestHeadendV4OwnerConflictMatrix
// for headend_v6_map. v4 and v6 share entryOwnerMap code so the smoke
// suite is intentionally smaller.
func TestHeadendV6OwnerConflictMatrix(t *testing.T) {
	h := newXDPTestHelper(t)
	bgpOwner := OwnerBGPVPN(65000, "65000:300")

	t.Run("same-owner-overwrite-allowed", func(t *testing.T) {
		const p = "2001:db8:a::/48"
		entry := &HeadendEntry{}
		if err := h.mapOps.CreateHeadendV6(p, entry, OwnerRPC); err != nil {
			t.Fatalf("first create: %v", err)
		}
		t.Cleanup(func() { _ = h.mapOps.ForceDeleteHeadendV6(p) })
		if err := h.mapOps.CreateHeadendV6(p, entry, OwnerRPC); err != nil {
			t.Errorf("re-create with same owner rejected: %v", err)
		}
	})

	t.Run("cross-owner-delete-rejected", func(t *testing.T) {
		const p = "2001:db8:b::/48"
		if err := h.mapOps.CreateHeadendV6(p, &HeadendEntry{}, OwnerRPC); err != nil {
			t.Fatalf("seed: %v", err)
		}
		t.Cleanup(func() { _ = h.mapOps.ForceDeleteHeadendV6(p) })
		err := h.mapOps.DeleteHeadendV6(p, bgpOwner)
		if !errors.Is(err, ErrEntryOwnerMismatch) {
			t.Errorf("cross-owner delete: got %v, want ErrEntryOwnerMismatch", err)
		}
	})

	t.Run("force-delete-allowed", func(t *testing.T) {
		const p = "2001:db8:c::/48"
		if err := h.mapOps.CreateHeadendV6(p, &HeadendEntry{}, OwnerRPC); err != nil {
			t.Fatalf("seed: %v", err)
		}
		if err := h.mapOps.ForceDeleteHeadendV6(p); err != nil {
			t.Errorf("force delete rejected: %v", err)
		}
	})

	t.Run("flush-owner-scoped", func(t *testing.T) {
		rpcPrefixes := []string{"2001:db8:10::/48", "2001:db8:11::/48"}
		bgpPrefixes := []string{"2001:db8:12::/48", "2001:db8:13::/48"}
		for _, p := range rpcPrefixes {
			if err := h.mapOps.CreateHeadendV6(p, &HeadendEntry{}, OwnerRPC); err != nil {
				t.Fatalf("seed RPC %q: %v", p, err)
			}
		}
		for _, p := range bgpPrefixes {
			if err := h.mapOps.CreateHeadendV6(p, &HeadendEntry{}, bgpOwner); err != nil {
				t.Fatalf("seed BGP %q: %v", p, err)
			}
		}
		t.Cleanup(func() {
			for _, p := range append(rpcPrefixes, bgpPrefixes...) {
				_ = h.mapOps.ForceDeleteHeadendV6(p)
			}
		})
		n, err := h.mapOps.FlushHeadendV6(OwnerRPC)
		if err != nil {
			t.Fatalf("flush RPC scope: %v", err)
		}
		if n != uint32(len(rpcPrefixes)) {
			t.Errorf("flush deleted %d, want %d", n, len(rpcPrefixes))
		}
		for _, p := range bgpPrefixes {
			if _, err := h.mapOps.GetHeadendV6(p); err != nil {
				t.Errorf("BGP entry %q vanished from owner-scoped flush", p)
			}
		}
	})
}

// TestCreateRejectsEmptyOwner pins the contract that empty OwnerTag is
// rejected on the Create path -- otherwise it would silently collide
// with the "no recorded owner" sentinel during conflict checks.
func TestCreateRejectsEmptyOwner(t *testing.T) {
	h := newXDPTestHelper(t)

	if err := h.mapOps.CreateSidFunction("fc00:e::/128", &SidFunctionEntry{Action: 1}, nil, ""); !errors.Is(err, ErrEmptyOwner) {
		t.Errorf("CreateSidFunction with empty owner: got %v, want ErrEmptyOwner", err)
	}
	if err := h.mapOps.CreateHeadendV4("172.16.0.0/24", &HeadendEntry{}, ""); !errors.Is(err, ErrEmptyOwner) {
		t.Errorf("CreateHeadendV4 with empty owner: got %v, want ErrEmptyOwner", err)
	}
	if err := h.mapOps.CreateHeadendV6("2001:db8:f::/48", &HeadendEntry{}, ""); !errors.Is(err, ErrEmptyOwner) {
		t.Errorf("CreateHeadendV6 with empty owner: got %v, want ErrEmptyOwner", err)
	}
}

// TestDeleteAbsentEntryIsIdempotent pins that deleting an entry that was
// never created is a no-op, not an error. The BGP applier relies on this
// for safe double-withdraw handling: a withdraw for a route that was
// never installed (e.g. filtered out, or replayed) must not surface as
// a failure.
func TestDeleteAbsentEntryIsIdempotent(t *testing.T) {
	h := newXDPTestHelper(t)

	if err := h.mapOps.DeleteSidFunction("fc00:abef::/128", OwnerRPC); err != nil {
		t.Errorf("DeleteSidFunction of an absent prefix: %v", err)
	}
	if err := h.mapOps.DeleteHeadendV4("203.0.113.0/24", OwnerRPC); err != nil {
		t.Errorf("DeleteHeadendV4 of an absent prefix: %v", err)
	}
	if err := h.mapOps.DeleteHeadendV6("2001:db8:abef::/48", OwnerRPC); err != nil {
		t.Errorf("DeleteHeadendV6 of an absent prefix: %v", err)
	}
}
