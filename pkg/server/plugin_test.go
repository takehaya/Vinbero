package server

import (
	"testing"
	"time"

	"github.com/cilium/ebpf/btf"
)

// TestSnapshotEntriesFilterAndSort verifies that SnapshotEntries returns a
// sorted, filtered view of the registry. The filter handles the PluginList
// --type argument, and the sort stabilizes CLI / test output.
func TestSnapshotEntriesFilterAndSort(t *testing.T) {
	s := &PluginServer{registry: map[pluginSlotKey]*pluginEntry{}}

	now := time.Now()
	s.registry[pluginSlotKey{MapType: "endpoint", Slot: 33}] = &pluginEntry{
		program:       "p33",
		ownedMapNames: []string{"p33_map"},
		sharedRONames: []string{"sid_aux_map"},
		sharedRWNames: []string{"stats_map"},
		registeredAt:  now,
	}
	s.registry[pluginSlotKey{MapType: "endpoint", Slot: 32}] = &pluginEntry{
		program:      "p32",
		auxType:      &btf.Struct{Name: "p32_aux"},
		registeredAt: now,
	}
	s.registry[pluginSlotKey{MapType: "headend_v4", Slot: 16}] = &pluginEntry{
		program:      "hv4",
		registeredAt: now,
	}

	all := s.SnapshotEntries("")
	if len(all) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(all))
	}
	// endpoint/32, endpoint/33, headend_v4/16 in that order
	if all[0].MapType != "endpoint" || all[0].Slot != 32 {
		t.Errorf("entry 0: got %s/%d, want endpoint/32", all[0].MapType, all[0].Slot)
	}
	if all[1].MapType != "endpoint" || all[1].Slot != 33 {
		t.Errorf("entry 1: got %s/%d, want endpoint/33", all[1].MapType, all[1].Slot)
	}
	if all[2].MapType != "headend_v4" || all[2].Slot != 16 {
		t.Errorf("entry 2: got %s/%d, want headend_v4/16", all[2].MapType, all[2].Slot)
	}

	// Filter: only endpoint
	ep := s.SnapshotEntries("endpoint")
	if len(ep) != 2 {
		t.Fatalf("expected 2 endpoint entries, got %d", len(ep))
	}
	for _, e := range ep {
		if e.MapType != "endpoint" {
			t.Errorf("filter leaked %s entry", e.MapType)
		}
	}

	// Aux type: p32 has one, others do not
	if !ep[0].HasAuxType || ep[0].AuxTypeName != "p32_aux" {
		t.Errorf("p32 aux missing: has=%v name=%q", ep[0].HasAuxType, ep[0].AuxTypeName)
	}
	if ep[1].HasAuxType {
		t.Errorf("p33 should not report an aux type")
	}

	// Owned / shared lists are copied, not aliased
	ep[1].OwnedMapNames[0] = "mutated"
	ep2 := s.SnapshotEntries("endpoint")
	if ep2[1].OwnedMapNames[0] == "mutated" {
		t.Error("SnapshotEntries returned aliased slice; expected deep copy")
	}
}
