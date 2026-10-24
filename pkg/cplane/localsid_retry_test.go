package cplane

import (
	"errors"
	"testing"

	"github.com/takehaya/vinbero/pkg/bpf"
)

type partialSIDDelete struct {
	*fakeSIDOps
	failAfterDelete bool
}

func (m *partialSIDDelete) DeleteSidFunction(prefix string, owner bpf.OwnerTag) error {
	if err := m.fakeSIDOps.DeleteSidFunction(prefix, owner); err != nil {
		return err
	}
	if m.failAfterDelete {
		// Mirror maps.go: main entry and aux are gone before the owner
		// map deletion is attempted and can return an error.
		m.owners[prefix] = owner
		return errors.New("injected owner-map delete failure after freeing aux")
	}
	return nil
}

func TestLocalSIDDeleteRetryDoesNotRevokeReusedGrant(t *testing.T) {
	alloc := &fakeAllocator{}
	maps := &partialSIDDelete{fakeSIDOps: newFakeSIDOps()}
	grants := newFakeGrantOps()
	maps.grants = grants
	set := NewLocalSIDSet(alloc, maps, grants, func(string) (uint32, error) { return 42, nil })
	out, _, err := set.Apply(ownerA, []LocalSID{{Name: "self", Locator: "main", Slot: 33, DecapVRF: "blue"}}, unlimited)
	if err != nil {
		t.Fatal(err)
	}
	oldIndex := out[0].auxIndex
	maps.failAfterDelete = true
	if _, _, err := set.Apply(ownerA, nil, unlimited); err == nil {
		t.Fatal("expected deletion failure")
	}
	if maps.count() != 0 {
		t.Fatal("dispatch should already be removed")
	}
	// The map-layer allocator freed oldIndex, so another SID can now use it.
	grants.grants[oldIndex] = 9999
	maps.failAfterDelete = false
	if _, _, err := set.Apply(ownerA, nil, unlimited); err != nil {
		t.Fatal(err)
	}
	if grants.grants[oldIndex] != 9999 {
		t.Fatalf("retry revoked another SID's grant at reused aux index %d", oldIndex)
	}
}

// A failed withdrawal may revoke the VRF grant without deleting the dispatch.
// Re-declaring the old desired set must restore forwarding, not report a no-op.
func TestLocalSIDRedeclareAfterFailedDeleteRestoresGrant(t *testing.T) {
	alloc := &fakeAllocator{}
	maps := newFakeSIDOps()
	grants := newFakeGrantOps()
	maps.grants = grants
	set := NewLocalSIDSet(alloc, maps, grants, func(string) (uint32, error) { return 42, nil })
	want := []LocalSID{{Name: "self", Locator: "main", Slot: 33, DecapVRF: "blue"}}
	out, _, err := set.Apply(ownerA, want, unlimited)
	if err != nil {
		t.Fatal(err)
	}
	sid := out[0].SID
	maps.delFailOn = sid.String() + "/128"
	if _, _, err := set.Apply(ownerA, nil, unlimited); err == nil {
		t.Fatal("expected deletion failure")
	}
	if set.OwnsSID(ownerA, sid) {
		t.Fatal("partially removed SID must not authorize advertisement")
	}
	if grants.count() != 0 {
		t.Fatal("expected revoked grant before failed dispatch deletion")
	}
	maps.delFailOn = ""
	if _, _, err := set.Apply(ownerA, want, unlimited); err != nil {
		t.Fatal(err)
	}
	if !set.OwnsSID(ownerA, sid) {
		t.Fatal("expected the host to permit re-advertisement")
	}
	if grants.count() != 1 {
		t.Fatalf("re-declaration succeeded and authorizes advertisement, but grant count = %d; dispatch remains with no usable decap grant", grants.count())
	}
}
