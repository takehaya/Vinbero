package vrf

import (
	"errors"
	"testing"
	"time"
)

// LookupID resolves without creating: "" and "global" are vrf 0, a known
// name its id, and an unknown name is an error that leaves no VRF behind.
func TestManager_LookupIDDoesNotCreate(t *testing.T) {
	m := NewManager()
	a, err := m.Ensure("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", GlobalVRFName} {
		if id, err := m.LookupID(name); err != nil || id != GlobalVRFID {
			t.Errorf("LookupID(%q) = %d %v, want 0", name, id, err)
		}
	}
	if id, err := m.LookupID("tenant-a"); err != nil || id != a.ID {
		t.Errorf("LookupID(tenant-a) = %d %v, want %d", id, err, a.ID)
	}
	if _, err := m.LookupID("tenant-b"); !errors.Is(err, ErrUnknownVRF) {
		t.Errorf("LookupID(tenant-b) = %v, want ErrUnknownVRF", err)
	}
	if _, ok := m.Get("tenant-b"); ok {
		t.Error("LookupID created the VRF it was asked about")
	}
	if name, ok := m.NameOf(a.ID); !ok || name != "tenant-a" {
		t.Errorf("NameOf(%d) = %q %v", a.ID, name, ok)
	}
	if name, ok := m.NameOf(GlobalVRFID); !ok || name != GlobalVRFName {
		t.Errorf("NameOf(0) = %q %v", name, ok)
	}
	m.Delete("tenant-a")
	if _, ok := m.NameOf(a.ID); ok {
		t.Error("NameOf names a deleted VRF")
	}
}

// LockIDs waits for every HoldIDs to end, and holds share.
func TestManager_LockIDsWaitsForHolds(t *testing.T) {
	m := NewManager()
	r1 := m.HoldIDs()
	r2 := m.HoldIDs() // holds share
	locked := make(chan func())
	go func() { locked <- m.LockIDs() }()
	select {
	case <-locked:
		t.Fatal("LockIDs went ahead of a hold")
	case <-time.After(50 * time.Millisecond):
	}
	r1()
	r2()
	select {
	case unlock := <-locked:
		unlock()
	case <-time.After(time.Second):
		t.Fatal("LockIDs did not proceed once the holds ended")
	}
}
