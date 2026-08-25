package bpf

import (
	"net"
	"sync"
	"testing"
)

// auxTestOps loads a collection and returns MapOperations for the aux
// lifecycle tests. Loading needs privileges, like the rest of pkg/bpf: the
// suite is run with `go test -exec "sudo -E"`, and a load failure is a real
// failure rather than a reason to skip.
func auxTestOps(t *testing.T) *MapOperations {
	t.Helper()
	objs, err := ReadCollection(nil, nil)
	if err != nil {
		t.Fatalf("Failed to load BPF objects: %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })
	return NewMapOperations(objs)
}

func nexthopBytes(t *testing.T, addr string) [16]byte {
	t.Helper()
	var out [16]byte
	ip := net.ParseIP(addr).To16()
	if ip == nil {
		t.Fatalf("bad address %q", addr)
	}
	copy(out[:], ip)
	return out
}

func auxIndexOf(t *testing.T, m *MapOperations, prefix string) uint16 {
	t.Helper()
	entry, err := m.GetSidFunction(prefix)
	if err != nil {
		t.Fatalf("GetSidFunction(%s): %v", prefix, err)
	}
	return entry.AuxIndex
}

// CreateSidFunction is an upsert. Re-creating an entry that carries a
// builtin aux allocates a fresh index, so the superseded one has to go back
// to the pool -- otherwise every re-create burns a slot and the aux map
// eventually refuses new SIDs.
func TestCreateSidFunction_UpsertFreesTheSupersededAux(t *testing.T) {
	m := auxTestOps(t)
	const prefix = "fd00:1:a11:1::1/128"
	nh := nexthopBytes(t, "fe80::1")

	entry := &SidFunctionEntry{Action: actionEndX}
	if err := m.CreateSidFunction(prefix, entry, NewSidAuxNexthop(nh), OwnerRPC); err != nil {
		t.Fatalf("first create: %v", err)
	}
	t.Cleanup(func() { _ = m.DeleteSidFunction(prefix, OwnerRPC) })
	first := auxIndexOf(t, m, prefix)
	before := m.auxAlloc.countByOwner(AuxOwnerBuiltin)

	entry2 := &SidFunctionEntry{Action: actionEndX}
	if err := m.CreateSidFunction(prefix, entry2, NewSidAuxNexthop(nexthopBytes(t, "fe80::2")), OwnerRPC); err != nil {
		t.Fatalf("re-create: %v", err)
	}
	second := auxIndexOf(t, m, prefix)

	if got := m.auxAlloc.countByOwner(AuxOwnerBuiltin); got != before {
		t.Errorf("builtin aux slots in use = %d, want %d (the re-create leaked one)", got, before)
	}
	if first != second && m.auxAlloc.OwnerOf(uint32(first)) != "" {
		t.Errorf("aux index %d is still owned after being superseded", first)
	}
}

// Deleting a prefix that has no entry of its own must not touch the broader
// entry covering it. sid_function_map is an LPM trie, so the pre-delete
// lookup answers with that covering entry; acting on it would free the aux
// of a SID that is still installed.
func TestDeleteSidFunction_MissingPrefixKeepsTheCoveringAux(t *testing.T) {
	m := auxTestOps(t)
	const covering = "fd00:1:a11:c0de::/64"
	nh := nexthopBytes(t, "fe80::1")

	entry := &SidFunctionEntry{Action: actionEndX}
	if err := m.CreateSidFunction(covering, entry, NewSidAuxNexthop(nh), OwnerRPC); err != nil {
		t.Fatalf("create covering entry: %v", err)
	}
	t.Cleanup(func() { _ = m.DeleteSidFunction(covering, OwnerRPC) })
	idx := auxIndexOf(t, m, covering)

	// Nothing is installed at this /128; it only falls under the /64.
	if err := m.DeleteSidFunction("fd00:1:a11:c0de::5/128", OwnerRPC); err != nil {
		t.Fatalf("delete of an absent prefix: %v", err)
	}

	if owner := m.auxAlloc.OwnerOf(uint32(idx)); owner != AuxOwnerBuiltin {
		t.Errorf("aux index %d owner = %q, want %q (freed by an unrelated delete)", idx, owner, AuxOwnerBuiltin)
	}
	aux, err := m.GetSidAux(uint32(idx))
	if err != nil {
		t.Fatalf("GetSidAux: %v", err)
	}
	if aux.Nexthop.Nexthop != nh {
		t.Errorf("aux nexthop = %v, want %v (zeroed by an unrelated delete)", aux.Nexthop.Nexthop, nh)
	}
}

// Entries pinned before owner tracking existed carry no owner record, so
// ownership cannot stand in for "this prefix already has an entry". Such an
// entry must still hand its aux back when it is upserted.
func TestCreateSidFunction_UpsertFreesTheAuxOfAnUnownedEntry(t *testing.T) {
	m := auxTestOps(t)
	const prefix = "fd00:1:a11:2::1/128"

	// Build the legacy shape by hand: a main-map entry with a builtin aux
	// and no owner record.
	key, err := buildLpmKeyV6(prefix)
	if err != nil {
		t.Fatalf("buildLpmKeyV6: %v", err)
	}
	legacyAux, err := m.auxAlloc.AllocOwner(AuxOwnerBuiltin)
	if err != nil {
		t.Fatalf("AllocOwner: %v", err)
	}
	if err := m.objs.SidAuxMap.Put(legacyAux, NewSidAuxNexthop(nexthopBytes(t, "fe80::9"))); err != nil {
		t.Fatalf("put aux: %v", err)
	}
	legacy := &SidFunctionEntry{Action: actionEndX, AuxIndex: uint16(legacyAux)}
	if err := m.objs.SidFunctionMap.Put(key, legacy); err != nil {
		t.Fatalf("put legacy entry: %v", err)
	}
	t.Cleanup(func() { _ = m.ForceDeleteSidFunction(prefix) })

	entry := &SidFunctionEntry{Action: actionEndX}
	if err := m.CreateSidFunction(prefix, entry, NewSidAuxNexthop(nexthopBytes(t, "fe80::1")), OwnerRPC); err != nil {
		t.Fatalf("upsert over the legacy entry: %v", err)
	}

	if owner := m.auxAlloc.OwnerOf(legacyAux); owner != "" {
		t.Errorf("legacy aux index %d owner = %q, want it freed", legacyAux, owner)
	}
}

// Drives concurrent upserts and checks the aux bookkeeping still adds up:
// one live index per prefix, each owned by the entry pointing at it. The
// ABA window the lifecycle lock closes is too narrow to hit on demand, so
// this is a load-shaped invariant check rather than proof of the lock --
// it catches gross double-free or double-alloc, not the specific
// interleaving.
func TestSidFunctionAuxLifecycle_ConcurrentUpserts(t *testing.T) {
	m := auxTestOps(t)
	prefixes := []string{
		"fd00:1:a11:3::1/128",
		"fd00:1:a11:3::2/128",
		"fd00:1:a11:3::3/128",
	}
	t.Cleanup(func() {
		for _, p := range prefixes {
			_ = m.DeleteSidFunction(p, OwnerRPC)
		}
	})

	before := m.auxAlloc.countByOwner(AuxOwnerBuiltin)
	var wg sync.WaitGroup
	for _, p := range prefixes {
		wg.Add(1)
		go func(prefix string) {
			defer wg.Done()
			for i := range 20 {
				entry := &SidFunctionEntry{Action: actionEndX}
				nh := nexthopBytes(t, "fe80::1")
				nh[15] = byte(i + 1)
				if err := m.CreateSidFunction(prefix, entry, NewSidAuxNexthop(nh), OwnerRPC); err != nil {
					t.Errorf("create %s: %v", prefix, err)
					return
				}
			}
		}(p)
	}
	wg.Wait()

	// One live aux per prefix, whatever order the updates landed in.
	if got, want := m.auxAlloc.countByOwner(AuxOwnerBuiltin), before+len(prefixes); got != want {
		t.Errorf("builtin aux slots in use = %d, want %d", got, want)
	}
	for _, p := range prefixes {
		idx := auxIndexOf(t, m, p)
		if owner := m.auxAlloc.OwnerOf(uint32(idx)); owner != AuxOwnerBuiltin {
			t.Errorf("%s points at aux %d whose owner is %q", p, idx, owner)
		}
	}
}
