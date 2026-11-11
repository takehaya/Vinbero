package netresource

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"go.uber.org/zap"
)

func sampleBindings() []ManagedVrfBinding {
	return []ManagedVrfBinding{
		{
			VRFName: "tenant-a", RD: "65000:1", DefaultLocator: "LOC1", Redistribute: []string{"static"}, MaxPrefixes: 10,
			ImportRTs: []string{"65000:1"}, ExportRTs: []string{"65000:1"},
			Families: map[string]ManagedFamilyPolicy{
				"vpnv4": {RouteTargets: []ManagedRouteTarget{{RT: "65000:1", Direction: "both"}}},
				"evpn":  {RouteTargets: []ManagedRouteTarget{}},
			},
			MupGTP4SourcePrefix: "2001:db8::/64",
		},
		{VRFName: "tenant-b", Families: map[string]ManagedFamilyPolicy{}},
		{VRFName: "tenant-c", RD: "65000:3"},
	}
}

// Saved bindings come back from the file as they were written, null and
// empty families kept apart.
func TestRuntimeVrfBindings_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	m, err := NewResourceManager(path, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	want := sampleBindings()
	if err := m.SaveRuntimeVrfBindings(want); err != nil {
		t.Fatal(err)
	}
	m2, err := NewResourceManager(path, zap.NewNop())
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := m2.RuntimeVrfBindings(); !reflect.DeepEqual(got, want) {
		t.Errorf("after reload = %+v\nwant %+v", got, want)
	}
	// Saving none removes the field, so the file looks like one without
	// runtime bindings.
	if err := m2.SaveRuntimeVrfBindings(nil); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "runtime_vrf_bindings") {
		t.Errorf("an empty record is still written: %s", data)
	}
}

// A file without the field reads as no saved bindings, and keeps its other
// records when bindings are saved into it.
func TestRuntimeVrfBindings_OlderFileWithoutTheField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	old := `{"vrfs":[],"bridges":[{"name":"br1","bd_id":10,"members":null,"ifindex":6}],` +
		`"vrf_objects":{"next_vrf_id":2,"entries":[{"name":"tenant-a","vrf_id":1}]}}`
	if err := os.WriteFile(path, []byte(old), 0644); err != nil {
		t.Fatal(err)
	}
	m, err := NewResourceManager(path, zap.NewNop())
	if err != nil {
		t.Fatalf("older state refused: %v", err)
	}
	if got := m.RuntimeVrfBindings(); len(got) != 0 {
		t.Fatalf("bindings of an older file = %+v", got)
	}
	if err := m.SaveRuntimeVrfBindings(sampleBindings()[:1]); err != nil {
		t.Fatal(err)
	}
	m2, err := NewResourceManager(path, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if len(m2.ListBridges()) != 1 || m2.VrfObjects() == nil || len(m2.RuntimeVrfBindings()) != 1 {
		t.Errorf("records lost: bridges=%v objects=%v bindings=%v", m2.ListBridges(), m2.VrfObjects(), m2.RuntimeVrfBindings())
	}
	for _, empty := range []string{`{"runtime_vrf_bindings":null}`, `{"runtime_vrf_bindings":[]}`} {
		if err := os.WriteFile(path, []byte(empty), 0644); err != nil {
			t.Fatal(err)
		}
		m3, err := NewResourceManager(path, zap.NewNop())
		if err != nil {
			t.Errorf("%s: %v", empty, err)
		} else if got := m3.RuntimeVrfBindings(); len(got) != 0 {
			t.Errorf("%s: %+v", empty, got)
		}
	}
}

// A binding record with a field this version does not know is refused: it
// may restrict what the binding imports.
func TestRuntimeVrfBindings_UnknownFieldIsRefused(t *testing.T) {
	for _, data := range []string{
		`{"runtime_vrf_bindings":[{"vrf_name":"a","families":null,"import_policy":"strict"}]}`,
		`{"runtime_vrf_bindings":[{"vrf_name":"a","families":{"vpnv4":{"route_targets":[{"rt":"65000:1","direction":"both","weight":1}]}}}]}`,
	} {
		path := filepath.Join(t.TempDir(), "state.json")
		if err := os.WriteFile(path, []byte(data), 0644); err != nil {
			t.Fatal(err)
		}
		_, err := NewResourceManager(path, zap.NewNop())
		if err == nil || !strings.Contains(err.Error(), "unknown field") {
			t.Errorf("%s: err = %v, want an unknown-field refusal", data, err)
		}
	}
}

// A failed write puts the previous record back, so a later write by anyone
// does not put the refused bindings on disk; a record equal to the saved one
// is not written again.
func TestSaveRuntimeVrfBindings_FailureKeepsThePreviousRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	m, err := NewResourceManager(path, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	first := sampleBindings()[:1]
	if err := m.SaveRuntimeVrfBindings(first); err != nil {
		t.Fatal(err)
	}
	// Make the rename fail, also as root.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0755); err != nil {
		t.Fatal(err)
	}
	if err := m.SaveRuntimeVrfBindings(sampleBindings()); err == nil {
		t.Fatal("a write onto a directory succeeded")
	}
	if got := m.RuntimeVrfBindings(); !reflect.DeepEqual(got, first) {
		t.Errorf("record after a failed write = %+v, want the previous one", got)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	// Another record's write now carries the previous bindings, not the
	// refused ones.
	if err := m.Save(); err != nil {
		t.Fatal(err)
	}
	m2, err := NewResourceManager(path, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if got := m2.RuntimeVrfBindings(); !reflect.DeepEqual(got, first) {
		t.Errorf("file after the next write = %+v, want %+v", got, first)
	}
	// Unchanged: no write (the file is gone and stays gone).
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := m.SaveRuntimeVrfBindings(first); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("an unchanged record was written again (stat: %v)", err)
	}
}
