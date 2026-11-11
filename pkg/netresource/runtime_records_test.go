package netresource

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"go.uber.org/zap"
)

func sampleLocators() []ManagedLocator {
	return []ManagedLocator{
		{Name: "LOC2", Prefix: "fd00:2::/48", BlockLen: 32, NodeLen: 16, FunctionLen: 16, ArgumentLen: 64, Behavior: "classic", FunctionAutoStart: 1, FunctionAutoEnd: 100},
		{Name: "LOC1", Prefix: "fc00:0:1::/48", BlockLen: 32, NodeLen: 16, FunctionLen: 16, Behavior: "usid"},
	}
}

func sampleSegments() []ManagedEthernetSegment {
	return []ManagedEthernetSegment{
		{ESI: "01:00:00:00:00:00:00:00:00:02", RedundancyMode: "ESI_REDUNDANCY_MODE_SINGLE_ACTIVE"},
		{ESI: "01:00:00:00:00:00:00:00:00:01", LocalAttached: true, RedundancyMode: "ESI_REDUNDANCY_MODE_ALL_ACTIVE",
			LocalPeSrcAddr: "fc00:1::1", DfPeSrcAddr: "fc00:2::2", RD: "65000:1"},
	}
}

func reload(t *testing.T, path string) *ResourceManager {
	t.Helper()
	m, err := NewResourceManager(path, zap.NewNop())
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	return m
}

// The locators, segments and policy come back from the file as they were
// saved: locators in registration order, segments in ESI order. Saving none
// removes each field.
func TestRuntimeRecords_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	m := reload(t, path)
	if err := m.SaveRuntimeLocators(sampleLocators()); err != nil {
		t.Fatal(err)
	}
	if err := m.SaveEthernetSegments(sampleSegments()); err != nil {
		t.Fatal(err)
	}
	if err := m.SaveRuntimeVrfPolicy(ManagedVrfPolicy{DefaultDeny: true, DenyAction: "pass"}); err != nil {
		t.Fatal(err)
	}
	m2 := reload(t, path)
	if got := m2.RuntimeLocators(); !reflect.DeepEqual(got, sampleLocators()) {
		t.Errorf("locators = %+v", got)
	}
	segs := sampleSegments()
	if got := m2.EthernetSegments(); !reflect.DeepEqual(got, []ManagedEthernetSegment{segs[1], segs[0]}) {
		t.Errorf("segments = %+v", got)
	}
	if got := m2.RuntimeVrfPolicy(); got == nil || *got != (ManagedVrfPolicy{DefaultDeny: true, DenyAction: "pass"}) {
		t.Errorf("policy = %+v", got)
	}

	if err := m2.SaveRuntimeLocators(nil); err != nil {
		t.Fatal(err)
	}
	if err := m2.SaveEthernetSegments(nil); err != nil {
		t.Fatal(err)
	}
	if err := m2.DropRuntimeVrfPolicy(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"runtime_locators", "runtime_ethernet_segments", "runtime_vrf_policy"} {
		if strings.Contains(string(data), f) {
			t.Errorf("%s is still written: %s", f, data)
		}
	}
}

// A file written before these records reads as none saved.
func TestRuntimeRecords_OlderFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	old := `{"vrfs":[],"bridges":[],"runtime_vrf_bindings":[{"vrf_name":"a","families":null}]}`
	if err := os.WriteFile(path, []byte(old), 0644); err != nil {
		t.Fatal(err)
	}
	m := reload(t, path)
	if len(m.RuntimeLocators()) != 0 || len(m.EthernetSegments()) != 0 || m.RuntimeVrfPolicy() != nil {
		t.Errorf("older file: locators %+v segments %+v policy %+v", m.RuntimeLocators(), m.EthernetSegments(), m.RuntimeVrfPolicy())
	}
	if len(m.RuntimeVrfBindings()) != 1 {
		t.Errorf("bindings lost: %+v", m.RuntimeVrfBindings())
	}
}

// A record with a field this version does not know is refused.
func TestRuntimeRecords_UnknownFieldIsRefused(t *testing.T) {
	for _, data := range []string{
		`{"runtime_locators":[{"name":"L","prefix":"fd00::/48","block_len":32,"node_len":16,"function_len":16,"argument_len":64,"behavior":"classic","function_auto_start":0,"function_auto_end":0,"flavor":"psp"}]}`,
		`{"runtime_ethernet_segments":[{"esi":"01:00:00:00:00:00:00:00:00:01","redundancy_mode":"ESI_REDUNDANCY_MODE_ALL_ACTIVE","df_election":"preference"}]}`,
		`{"runtime_vrf_policy":{"default_deny":true,"deny_action":"drop","log":true}}`,
	} {
		path := filepath.Join(t.TempDir(), "state.json")
		if err := os.WriteFile(path, []byte(data), 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := NewResourceManager(path, zap.NewNop()); err == nil || !strings.Contains(err.Error(), "unknown field") {
			t.Errorf("%s: err = %v, want an unknown-field refusal", data, err)
		}
	}
}

// A failed write puts the previous record back, so a later write of another
// record does not put the refused one on disk; after it, saving the same
// record as before writes it, since the file may lack it.
func TestRuntimeRecords_FailedWriteKeepsThePreviousRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	m := reload(t, path)
	first := sampleLocators()[:1]
	if err := m.SaveRuntimeLocators(first); err != nil {
		t.Fatal(err)
	}
	policy := ManagedVrfPolicy{DenyAction: "drop"}
	if err := m.SaveRuntimeVrfPolicy(policy); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0755); err != nil {
		t.Fatal(err)
	}
	if err := m.SaveRuntimeLocators(sampleLocators()); err == nil {
		t.Fatal("a write onto a directory succeeded")
	}
	if err := m.SaveRuntimeVrfPolicy(ManagedVrfPolicy{DefaultDeny: true, DenyAction: "drop"}); err == nil {
		t.Fatal("a write onto a directory succeeded")
	}
	if got := m.RuntimeLocators(); !reflect.DeepEqual(got, first) {
		t.Errorf("locators after a failed write = %+v", got)
	}
	if got := m.RuntimeVrfPolicy(); got == nil || *got != policy {
		t.Errorf("policy after a failed write = %+v", got)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	// The record in memory is unchanged, but the file is not known to
	// have it: written.
	if err := m.SaveRuntimeLocators(first); err != nil {
		t.Fatal(err)
	}
	m2 := reload(t, path)
	if got := m2.RuntimeLocators(); !reflect.DeepEqual(got, first) {
		t.Errorf("file after the retry = %+v, want %+v", got, first)
	}
	if got := m2.RuntimeVrfPolicy(); got == nil || *got != policy {
		t.Errorf("policy in the file after the retry = %+v", got)
	}
	// Unchanged now that the file has it: no write.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := m.SaveRuntimeLocators(first); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("an unchanged record was written again (stat: %v)", err)
	}
}

// A drop at boot keeps its result in memory when the write fails, so the
// next write of any record removes the dropped ones from disk.
func TestRuntimeRecords_FailedDropIsWrittenLater(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	m := reload(t, path)
	if err := m.SaveRuntimeLocators(sampleLocators()); err != nil {
		t.Fatal(err)
	}
	if err := m.SaveRuntimeVrfPolicy(ManagedVrfPolicy{DenyAction: "drop"}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0755); err != nil {
		t.Fatal(err)
	}
	if err := m.DropRuntimeLocators(sampleLocators()[1:]); err == nil {
		t.Fatal("a write onto a directory succeeded")
	}
	if err := m.DropRuntimeVrfPolicy(); err == nil {
		t.Fatal("a write onto a directory succeeded")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := m.Save(); err != nil {
		t.Fatal(err)
	}
	m2 := reload(t, path)
	if got := m2.RuntimeLocators(); !reflect.DeepEqual(got, sampleLocators()[1:]) || m2.RuntimeVrfPolicy() != nil {
		t.Errorf("after the next write: locators %+v policy %+v", got, m2.RuntimeVrfPolicy())
	}
}
