package vrfbgp

import (
	"errors"
	"testing"
)

func TestManager_BindListUnbind(t *testing.T) {
	m := NewManager()
	if !m.Empty() {
		t.Fatal("a fresh Manager must report Empty()")
	}
	b := Binding{
		VRFName:        "vrf-a",
		ImportRTs:      []string{"65000:100"},
		ExportRTs:      []string{"65000:100"},
		DefaultLocator: "LOC1",
	}
	if err := m.Bind(b); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if m.Empty() {
		t.Error("Empty() = true after Bind")
	}
	if list := m.List(); len(list) != 1 || list[0].VRFName != "vrf-a" {
		t.Errorf("List = %v, want one vrf-a", list)
	}
	if err := m.Unbind("vrf-a"); err != nil {
		t.Fatalf("Unbind: %v", err)
	}
	if !m.Empty() {
		t.Error("Empty() = false after Unbind")
	}
}

func TestManager_BindEmptyNameRejected(t *testing.T) {
	if err := NewManager().Bind(Binding{VRFName: ""}); !errors.Is(err, ErrEmptyVRFName) {
		t.Errorf("Bind with empty name: got %v, want ErrEmptyVRFName", err)
	}
}

func TestManager_UnbindUnknownRejected(t *testing.T) {
	if err := NewManager().Unbind("nope"); !errors.Is(err, ErrBindingNotFound) {
		t.Errorf("Unbind unknown: got %v, want ErrBindingNotFound", err)
	}
}

// TestManager_BindReplaces pins that re-binding a VRF name overwrites the
// previous policy rather than accumulating a second entry.
func TestManager_BindReplaces(t *testing.T) {
	m := NewManager()
	if err := m.Bind(Binding{VRFName: "vrf-a", ImportRTs: []string{"65000:1"}}); err != nil {
		t.Fatalf("first Bind: %v", err)
	}
	if err := m.Bind(Binding{VRFName: "vrf-a", ImportRTs: []string{"65000:2"}}); err != nil {
		t.Fatalf("re-Bind: %v", err)
	}
	if list := m.List(); len(list) != 1 {
		t.Errorf("re-Bind must replace, got %d bindings", len(list))
	}
	if _, ok := m.MatchImport([]string{"65000:2"}); !ok {
		t.Error("MatchImport should see the replacement import RT")
	}
	if _, ok := m.MatchImport([]string{"65000:1"}); ok {
		t.Error("MatchImport should not see the stale import RT after replace")
	}
}

func TestManager_GetByBDID(t *testing.T) {
	m := NewManager()
	if err := m.Bind(Binding{VRFName: "evi100", RD: "65000:100", BDID: 100}); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if err := m.Bind(Binding{VRFName: "l3vrf", RD: "65000:1"}); err != nil { // BDID 0
		t.Fatalf("Bind: %v", err)
	}
	b, ok := m.GetByBDID(100)
	if !ok || b.VRFName != "evi100" {
		t.Errorf("GetByBDID(100) = %+v, %v; want the evi100 binding", b, ok)
	}
	if _, ok := m.GetByBDID(200); ok {
		t.Error("GetByBDID(200) should miss when no binding has that bd_id")
	}
	if _, ok := m.GetByBDID(0); ok {
		t.Error("GetByBDID(0) must never match an L3VPN-only binding")
	}
	// Two bindings claiming the same bd_id is ambiguous: GetByBDID must refuse
	// rather than return a map-order-dependent result.
	if err := m.Bind(Binding{VRFName: "evi100-dup", RD: "65000:101", BDID: 100}); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if _, ok := m.GetByBDID(100); ok {
		t.Error("GetByBDID(100) must be ambiguous (ok=false) when two bindings share the bd_id")
	}
}

func TestManager_MatchImport(t *testing.T) {
	m := NewManager()
	if err := m.Bind(Binding{VRFName: "vrf-a", ImportRTs: []string{"65000:100", "65000:101"}}); err != nil {
		t.Fatalf("Bind vrf-a: %v", err)
	}
	if err := m.Bind(Binding{VRFName: "vrf-b", ImportRTs: []string{"65000:200"}}); err != nil {
		t.Fatalf("Bind vrf-b: %v", err)
	}

	if vrf, ok := m.MatchImport([]string{"65000:101"}); !ok || vrf != "vrf-a" {
		t.Errorf("MatchImport 65000:101 = (%q,%v), want (vrf-a,true)", vrf, ok)
	}
	if vrf, ok := m.MatchImport([]string{"65000:200"}); !ok || vrf != "vrf-b" {
		t.Errorf("MatchImport 65000:200 = (%q,%v), want (vrf-b,true)", vrf, ok)
	}
	if _, ok := m.MatchImport([]string{"65000:999"}); ok {
		t.Error("MatchImport of an unregistered RT should miss")
	}
	// A route carrying several RTs matches if any one is imported.
	if _, ok := m.MatchImport([]string{"65000:999", "65000:200"}); !ok {
		t.Error("MatchImport should match when any RT is imported")
	}
}
