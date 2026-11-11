package netresource

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"go.uber.org/zap"
)

func sampleCircuits() []ManagedL2Circuit {
	return []ManagedL2Circuit{
		{Interface: "veth1", Ifindex: 9, MAC: "02:00:00:00:00:01", VLAN: 0, Mode: "SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2", BdID: 100},
		{Interface: "veth0", Ifindex: 7, MAC: "02:00:00:00:00:02", VLAN: 5, Mode: "SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2",
			SrcAddr: "fc00:1::1", Segments: []string{"fc00:2::1"}, ESI: "00:01:02:03:04:05:06:07:08:09", Deleting: true},
	}
}

// Saved circuits come back from the file in key order; none removes the
// field.
func TestL2Circuits_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	m, err := NewResourceManager(path, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SaveL2Circuits(sampleCircuits()); err != nil {
		t.Fatal(err)
	}
	m2, err := NewResourceManager(path, zap.NewNop())
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	want := sampleCircuits()
	want[0], want[1] = want[1], want[0]
	if got := m2.L2Circuits(); !reflect.DeepEqual(got, want) {
		t.Errorf("after reload = %+v\nwant %+v", got, want)
	}
	if err := m2.SaveL2Circuits(nil); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "runtime_l2_circuits") {
		t.Errorf("an empty record is still written: %s", data)
	}
}

// A file without the field reads as none saved; a record with a field this
// version does not know is refused.
func TestL2Circuits_OldAndNewerFiles(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "old.json")
	if err := os.WriteFile(old, []byte(`{"vrfs": [], "bridges": []}`), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := NewResourceManager(old, zap.NewNop())
	if err != nil || len(m.L2Circuits()) != 0 {
		t.Fatalf("old file: %v, %+v", err, m)
	}
	newer := filepath.Join(dir, "newer.json")
	body := `{"vrfs": [], "bridges": [], "runtime_l2_circuits": [{"interface": "a", "ifindex": 1, "vlan": 0, "mode": "x", "qos": 5}]}`
	if err := os.WriteFile(newer, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewResourceManager(newer, zap.NewNop()); err == nil || !strings.Contains(err.Error(), "qos") {
		t.Errorf("unknown field = %v, want a refusal naming it", err)
	}
}

// A failed save puts the previous record back; a failed drop keeps the new
// one for the next write.
func TestL2Circuits_SaveAndDropFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "state.json")
	m, err := NewResourceManager(path, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SaveL2Circuits(sampleCircuits()[:1]); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		t.Skip("root writes into a read-only directory")
	}
	if err := os.Chmod(filepath.Join(dir, "sub"), 0o500); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(filepath.Join(dir, "sub"), 0o755) }()
	if err := m.SaveL2Circuits(sampleCircuits()); err == nil {
		t.Fatal("save into a read-only directory succeeded")
	}
	if got := m.L2Circuits(); len(got) != 1 || got[0].Interface != "veth1" {
		t.Errorf("after a failed save: %+v", got)
	}
	if err := m.DropL2Circuits(nil); err == nil {
		t.Fatal("drop into a read-only directory succeeded")
	}
	if got := m.L2Circuits(); len(got) != 0 {
		t.Errorf("after a failed drop: %+v", got)
	}
	// The file still has the dropped circuit: a save equal to memory writes
	// it all the same.
	if err := os.Chmod(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := m.SaveL2Circuits(nil); err != nil {
		t.Fatal(err)
	}
	m2, err := NewResourceManager(path, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if got := m2.L2Circuits(); len(got) != 0 {
		t.Errorf("the file kept %+v after a save equal to memory", got)
	}
}
