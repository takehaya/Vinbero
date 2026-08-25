package bpf

import (
	"net"
	"testing"
)

// auxTestOps loads a collection and returns MapOperations for the aux
// lifecycle tests. Requires sudo, like the rest of pkg/bpf.
func auxTestOps(t *testing.T) *MapOperations {
	t.Helper()
	objs, err := ReadCollection(nil, nil)
	if err != nil {
		t.Skipf("BPF collection load failed (needs sudo): %v", err)
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
