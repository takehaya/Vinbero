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
		if !IsGlobalName(name) {
			t.Errorf("IsGlobalName(%q) = false", name)
		}
		if id, err := m.LookupID(name); err != nil || id != GlobalVRFID {
			t.Errorf("LookupID(%q) = %d %v, want 0", name, id, err)
		}
	}
	if IsGlobalName("tenant-a") {
		t.Error("IsGlobalName(tenant-a) = true")
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

// StartDelete waits for every hold, runs its check while none can start,
// and from then on LookupID refuses the VRF until Delete or abort.
func TestManager_StartDeleteOrdersAgainstHolds(t *testing.T) {
	m := NewManager()
	a, _ := m.Ensure("tenant-a")
	r1 := m.HoldIDs()
	r2 := m.HoldIDs() // holds share
	started := make(chan func())
	checked := make(chan uint32, 1)
	go func() {
		abort, err := m.StartDelete("tenant-a", func(id uint32) error { checked <- id; return nil })
		if err != nil {
			t.Error(err)
		}
		started <- abort
	}()
	select {
	case <-started:
		t.Fatal("StartDelete went ahead of a hold")
	case <-time.After(50 * time.Millisecond):
	}
	r1()
	r2()
	var abort func()
	select {
	case abort = <-started:
	case <-time.After(time.Second):
		t.Fatal("StartDelete did not proceed once the holds ended")
	}
	if id := <-checked; id != a.ID {
		t.Errorf("checked id %d, want %d", id, a.ID)
	}
	if _, err := m.LookupID("tenant-a"); !errors.Is(err, ErrUnknownVRF) {
		t.Errorf("LookupID during the deletion = %v, want ErrUnknownVRF", err)
	}
	// A hold does not wait for the rest of the deletion.
	m.HoldIDs()()
	abort()
	if id, err := m.LookupID("tenant-a"); err != nil || id != a.ID {
		t.Errorf("LookupID after abort = %d %v", id, err)
	}

	// A failed check leaves the VRF resolvable.
	if _, err := m.StartDelete("tenant-a", func(uint32) error { return errors.New("in use") }); err == nil {
		t.Error("a failed check started the deletion")
	}
	if _, err := m.LookupID("tenant-a"); err != nil {
		t.Errorf("LookupID after a failed check = %v", err)
	}
	if _, err := m.StartDelete("tenant-a", func(uint32) error { return nil }); err != nil {
		t.Fatal(err)
	}
	m.Delete("tenant-a")
	b, _ := m.Ensure("tenant-a")
	if b.ID == a.ID {
		t.Error("the id was given out again")
	}
	if _, err := m.LookupID("tenant-a"); err != nil {
		t.Errorf("a recreated VRF is still marked deleting: %v", err)
	}
}

// ReserveIDsThrough raises the watermark above an id still in use, so a
// lost state file cannot hand it out again; it never lowers it.
func TestManager_ReserveIDsThrough(t *testing.T) {
	m := NewManager()
	if err := m.ReserveIDsThrough(7); err != nil {
		t.Fatal(err)
	}
	a, _ := m.Ensure("a")
	if a.ID != 8 {
		t.Errorf("first id after reserving 7 = %d, want 8", a.ID)
	}
	if err := m.ReserveIDsThrough(3); err != nil {
		t.Fatal(err)
	}
	b, _ := m.Ensure("b")
	if b.ID != 9 {
		t.Errorf("next id = %d, want 9 (the watermark is not lowered)", b.ID)
	}
	if err := m.ReserveIDsThrough(MaxNextID); err == nil {
		t.Error("reserving the last watermark succeeded")
	}
}
