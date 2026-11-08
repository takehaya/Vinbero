package netresource

import (
	"os"
	"slices"
	"strings"
	"testing"

	"go.uber.org/zap"
)

// Devices round-trip through the state file; an add of a recorded name
// updates its mode, and a remove of unknown names writes nothing.
func TestDevices_Persist(t *testing.T) {
	m := newTestManager(t)
	if err := m.AddDevice("veth1", "driver"); err != nil {
		t.Fatalf("AddDevice: %v", err)
	}
	if err := m.AddDevice("veth2", "generic"); err != nil {
		t.Fatalf("AddDevice: %v", err)
	}
	if err := m.AddDevice("veth1", "generic"); err != nil {
		t.Fatalf("AddDevice (update): %v", err)
	}
	m2, err := NewResourceManager(m.statePath, zap.NewNop())
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	want := []ManagedDevice{{Name: "veth1", Mode: "generic"}, {Name: "veth2", Mode: "generic"}}
	if got := m2.ListDevices(); !slices.Equal(got, want) {
		t.Errorf("reloaded devices = %v, want %v", got, want)
	}

	before, err := os.ReadFile(m.statePath)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	// Make any write visible: a rewrite would replace the stat'ed inode.
	st, err := os.Stat(m.statePath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if err := m2.RemoveDevices("nope"); err != nil {
		t.Errorf("RemoveDevices of an unknown name: %v", err)
	}
	after, err := os.ReadFile(m.statePath)
	if err != nil {
		t.Fatalf("re-read state: %v", err)
	}
	st2, err := os.Stat(m.statePath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if string(before) != string(after) || !os.SameFile(st, st2) {
		t.Error("a no-op RemoveDevices rewrote the state file")
	}
	if err := m2.RemoveDevices("veth1", "veth2"); err != nil {
		t.Fatalf("RemoveDevices: %v", err)
	}
	if got := m2.ListDevices(); len(got) != 0 {
		t.Errorf("devices after remove = %v", got)
	}
}

// A state file written before devices existed still loads, and one without
// devices does not grow the key.
func TestDevices_OldStateFile(t *testing.T) {
	m := newTestManager(t)
	if err := os.WriteFile(m.statePath, []byte(`{"vrfs": [], "bridges": []}`), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	m2, err := NewResourceManager(m.statePath, zap.NewNop())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(m2.ListDevices()) != 0 {
		t.Errorf("devices = %v", m2.ListDevices())
	}
	if err := m2.persist(); err != nil {
		t.Fatalf("persist: %v", err)
	}
	data, err := os.ReadFile(m.statePath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.Contains(string(data), "devices") {
		t.Errorf("empty devices were written: %s", data)
	}
}
