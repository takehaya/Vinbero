package bpf

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/takehaya/vinbero/pkg/config"
)

// TestSharedMapNamesStatic verifies the BPF-free helpers used by the CLI
// validator: SharedReadOnlyMapNames / SharedReadWriteMapNames must be
// disjoint and the set-form helper must agree with the slice form. This
// test runs without sudo so CI sandboxes that can't load BPF still catch
// classification regressions.
func TestSharedMapNamesStatic(t *testing.T) {
	ro := SharedReadOnlyMapNames()
	rw := SharedReadWriteMapNames()
	if len(ro) == 0 {
		t.Fatal("SharedReadOnlyMapNames is empty")
	}
	if len(rw) == 0 {
		t.Fatal("SharedReadWriteMapNames is empty")
	}
	roSet := make(map[string]struct{}, len(ro))
	for _, n := range ro {
		if _, dup := roSet[n]; dup {
			t.Errorf("SharedReadOnlyMapNames duplicate %q", n)
		}
		roSet[n] = struct{}{}
	}
	for _, n := range rw {
		if _, clash := roSet[n]; clash {
			t.Errorf("map %q listed in both RO and RW slices", n)
		}
	}
	gotSet := SharedReadOnlyMapNamesSet()
	if len(gotSet) != len(roSet) {
		t.Errorf("SharedReadOnlyMapNamesSet size %d != %d", len(gotSet), len(roSet))
	}
	for n := range roSet {
		if _, ok := gotSet[n]; !ok {
			t.Errorf("SharedReadOnlyMapNamesSet missing %q", n)
		}
	}
}

// TestSharedMapPartitioning verifies that every map returned by the
// plugin-visible getters is classified into exactly one of RO / RW. Both the
// validator (plugin_validate_btf.go) and PluginRegister rely on this
// invariant to audit plugin-ELF map usage.
//
// Also verifies that the static helpers SharedReadOnlyMapNames /
// SharedReadWriteMapNames (used by the CLI validator, which has no live
// MapOperations) carry the same key set. Drift would mean the asm-level
// RO-write enforcer rejects in one path but lets the same plugin through
// in another.
func TestSharedMapPartitioning(t *testing.T) {
	h := newXDPTestHelper(t)

	ro := h.mapOps.GetSharedReadOnlyMaps()
	rw := h.mapOps.GetSharedReadWriteMaps()

	for name := range ro {
		if _, dup := rw[name]; dup {
			t.Errorf("map %q appears in both RO and RW sets", name)
		}
	}
	if len(ro) == 0 {
		t.Error("GetSharedReadOnlyMaps returned an empty set")
	}
	if len(rw) == 0 {
		t.Error("GetSharedReadWriteMaps returned an empty set")
	}

	// Static helper agrees with the live getter, in both directions. The
	// helper is what `vbctl plugin validate` consumes, so any divergence
	// would create a CLI-vs-server validation gap.
	staticRO := make(map[string]struct{})
	for _, n := range SharedReadOnlyMapNames() {
		if _, dup := staticRO[n]; dup {
			t.Errorf("SharedReadOnlyMapNames duplicate entry %q", n)
		}
		staticRO[n] = struct{}{}
	}
	if len(staticRO) != len(ro) {
		t.Errorf("RO size mismatch: static=%d, live=%d", len(staticRO), len(ro))
	}
	for name := range ro {
		if _, ok := staticRO[name]; !ok {
			t.Errorf("live RO map %q missing from SharedReadOnlyMapNames", name)
		}
	}
	for name := range staticRO {
		if _, ok := ro[name]; !ok {
			t.Errorf("static RO map %q missing from GetSharedReadOnlyMaps", name)
		}
	}

	staticRW := make(map[string]struct{})
	for _, n := range SharedReadWriteMapNames() {
		if _, dup := staticRW[n]; dup {
			t.Errorf("SharedReadWriteMapNames duplicate entry %q", n)
		}
		staticRW[n] = struct{}{}
	}
	if len(staticRW) != len(rw) {
		t.Errorf("RW size mismatch: static=%d, live=%d", len(staticRW), len(rw))
	}
	for name := range rw {
		if _, ok := staticRW[name]; !ok {
			t.Errorf("live RW map %q missing from SharedReadWriteMapNames", name)
		}
	}
	for name := range staticRW {
		if _, ok := rw[name]; !ok {
			t.Errorf("static RW map %q missing from GetSharedReadWriteMaps", name)
		}
	}

	// Set-form helper covers the same keys as the slice form.
	roSet := SharedReadOnlyMapNamesSet()
	if len(roSet) != len(staticRO) {
		t.Errorf("SharedReadOnlyMapNamesSet size %d != slice %d", len(roSet), len(staticRO))
	}
	for name := range staticRO {
		if _, ok := roSet[name]; !ok {
			t.Errorf("SharedReadOnlyMapNamesSet missing %q", name)
		}
	}

	// sanity check: the validator's expected value types should all refer to
	// maps that exist in one of the two sets (otherwise validation targets a
	// map plugins can no longer reference).
	for name := range expectedMapValueTypes {
		if _, ok := ro[name]; ok {
			continue
		}
		if _, ok := rw[name]; ok {
			continue
		}
		t.Errorf("expectedMapValueTypes references %q but neither RO nor RW contains it", name)
	}
}

// TestSidAuxRoundTrip verifies that aux entry constructors and readers
// produce consistent data for each union variant.
func TestSidAuxRoundTrip(t *testing.T) {
	t.Run("Nexthop", func(t *testing.T) {
		nh, _ := ParseIPv6("fc00::1")
		aux := NewSidAuxNexthop(nh)
		if aux.Nexthop.Nexthop != nh {
			t.Errorf("nexthop mismatch: got %v, want %v", aux.Nexthop.Nexthop, nh)
		}
	})

	t.Run("L2", func(t *testing.T) {
		aux := NewSidAuxL2(100, 42)
		bdID, bridgeIf := SidAuxL2Data(aux)
		if bdID != 100 {
			t.Errorf("bd_id: got %d, want 100", bdID)
		}
		if bridgeIf != 42 {
			t.Errorf("bridge_ifindex: got %d, want 42", bridgeIf)
		}
	})

	t.Run("Gtp4e", func(t *testing.T) {
		srcAddr := [IPv4AddrLen]uint8{10, 0, 0, 1}
		aux := NewSidAuxGtp4e(7, srcAddr)
		gotOffset, gotSrc := SidAuxGtp4eData(aux)
		if gotOffset != 7 {
			t.Errorf("args_offset: got %d, want 7", gotOffset)
		}
		if gotSrc != srcAddr {
			t.Errorf("gtp_v4_src_addr: got %v, want %v", gotSrc, srcAddr)
		}
	})

	t.Run("Gtp6e", func(t *testing.T) {
		srcAddr, _ := ParseIPv6("2001:db8::1")
		dstAddr, _ := ParseIPv6("2001:db8::2")
		aux := NewSidAuxGtp6e(5, srcAddr, dstAddr)
		gotOffset, gotSrc, gotDst := SidAuxGtp6eData(aux)
		if gotOffset != 5 {
			t.Errorf("args_offset: got %d, want 5", gotOffset)
		}
		if gotSrc != srcAddr {
			t.Errorf("src_addr: got %v, want %v", gotSrc, srcAddr)
		}
		if gotDst != dstAddr {
			t.Errorf("dst_addr: got %v, want %v", gotDst, dstAddr)
		}
	})

	t.Run("B6Policy", func(t *testing.T) {
		srcAddr, _ := ParseIPv6("fc00::1")
		segments, numSeg, _ := ParseSegments([]string{"fc00::200", "fc00::300"})
		policy := &HeadendEntry{
			Mode:        1,
			NumSegments: numSeg,
			SrcAddr:     srcAddr,
			Segments:    segments,
		}
		aux := NewSidAuxB6Policy(policy)
		got := SidAuxB6PolicyData(aux)
		if got.Mode != 1 {
			t.Errorf("mode: got %d, want 1", got.Mode)
		}
		if got.NumSegments != numSeg {
			t.Errorf("num_segments: got %d, want %d", got.NumSegments, numSeg)
		}
		if got.SrcAddr != srcAddr {
			t.Errorf("src_addr mismatch")
		}
		if got.Segments[0] != segments[0] || got.Segments[1] != segments[1] {
			t.Errorf("segments mismatch")
		}
	})
}

// TestRecoverAuxIndices verifies that the index allocator correctly recovers
// used indices from existing sid_function_map entries.
func TestRecoverAuxIndices(t *testing.T) {
	h := newXDPTestHelper(t)

	// Create entries with aux (indices 1, 2 — index 0 is the no-aux sentinel)
	nh, _ := ParseIPv6("fc00::1")
	e1 := &SidFunctionEntry{Action: actionEndX}
	if err := h.mapOps.CreateSidFunction("fc00:1::1/128", e1, NewSidAuxNexthop(nh), OwnerRPC); err != nil {
		t.Fatalf("create 1: %v", err)
	}
	e2 := &SidFunctionEntry{Action: actionEndX}
	if err := h.mapOps.CreateSidFunction("fc00:2::1/128", e2, NewSidAuxNexthop(nh), OwnerRPC); err != nil {
		t.Fatalf("create 2: %v", err)
	}
	// Create entry without aux (no index used)
	e3 := &SidFunctionEntry{Action: actionEnd}
	if err := h.mapOps.CreateSidFunction("fc00:3::1/128", e3, nil, OwnerRPC); err != nil {
		t.Fatalf("create 3: %v", err)
	}

	// Delete entry 1 to create a gap (index 1 freed)
	if err := h.mapOps.DeleteSidFunction("fc00:1::1/128", OwnerRPC); err != nil {
		t.Fatalf("delete: %v", err)
	}

	// Simulate restart: create fresh MapOperations and recover
	freshMapOps := NewMapOperations(h.objs)
	if err := freshMapOps.RecoverAuxIndices(); err != nil {
		t.Fatalf("recover: %v", err)
	}

	// Allocate new index — should get 1 (freed gap), not 3
	e4 := &SidFunctionEntry{Action: actionEndX}
	if err := freshMapOps.CreateSidFunction("fc00:4::1/128", e4, NewSidAuxNexthop(nh), OwnerRPC); err != nil {
		t.Fatalf("create after recover: %v", err)
	}

	got, err := freshMapOps.GetSidFunction("fc00:4::1/128")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.AuxIndex != 1 {
		t.Errorf("expected recovered gap index 1, got %d", got.AuxIndex)
	}
}

// TestFlushSidFunctions verifies that FlushSidFunctions wipes every SID
// entry, frees the matching aux indices back into the allocator, and
// leaves the map ready to accept fresh entries from index 1 again.
func TestFlushSidFunctions(t *testing.T) {
	h := newXDPTestHelper(t)

	nh, _ := ParseIPv6("fc00::1")
	// 3 entries that each consume an aux_index, plus 1 without aux.
	mustCreate := func(prefix string, action uint8, aux *SidAuxEntry) {
		t.Helper()
		entry := &SidFunctionEntry{Action: action}
		if err := h.mapOps.CreateSidFunction(prefix, entry, aux, OwnerRPC); err != nil {
			t.Fatalf("create %s: %v", prefix, err)
		}
	}
	mustCreate("fc00:1::1/128", actionEndX, NewSidAuxNexthop(nh))
	mustCreate("fc00:1::2/128", actionEndX, NewSidAuxNexthop(nh))
	mustCreate("fc00:1::3/128", actionEndX, NewSidAuxNexthop(nh))
	mustCreate("fc00:1::a/128", actionEnd, nil)

	before, err := h.mapOps.ListSidFunctions()
	if err != nil {
		t.Fatalf("list before: %v", err)
	}
	if len(before) != 4 {
		t.Fatalf("pre-flush count: got %d, want 4", len(before))
	}

	count, err := h.mapOps.FlushSidFunctions(OwnerRPC)
	if err != nil {
		t.Fatalf("flush: %v", err)
	}
	if count != 4 {
		t.Errorf("flush count: got %d, want 4", count)
	}

	after, err := h.mapOps.ListSidFunctions()
	if err != nil {
		t.Fatalf("list after: %v", err)
	}
	if len(after) != 0 {
		t.Errorf("post-flush count: got %d, want 0", len(after))
	}

	// Allocator should have reclaimed the freed indices; the next
	// allocation must pop one of them (1..3) rather than allocate a
	// fresh index 4.
	entry := &SidFunctionEntry{Action: actionEndX}
	if err := h.mapOps.CreateSidFunction("fc00:2::1/128", entry, NewSidAuxNexthop(nh), OwnerRPC); err != nil {
		t.Fatalf("post-flush create: %v", err)
	}
	if entry.AuxIndex < 1 || entry.AuxIndex > 3 {
		t.Errorf("expected reused aux_index in 1..3 after flush, got %d", entry.AuxIndex)
	}
}

// TestBpfLoad_PinMapsRoundTrip verifies that settings.pin_maps.enabled
// makes control-state maps survive a Collection close/reopen cycle.
// The check is end-to-end via ReadCollection: create an entry, close
// the objects, reload from the same pin path, confirm the entry is
// still there.
//
// Requires /sys/fs/bpf to be bpffs-mounted. The test skips itself
// gracefully when that is not the case (e.g. sandbox without bpffs),
// and always cleans up the pin directory it allocated.
func TestBpfLoad_PinMapsRoundTrip(t *testing.T) {
	const bpffsRoot = "/sys/fs/bpf"
	var stat syscall.Statfs_t
	if err := syscall.Statfs(bpffsRoot, &stat); err != nil {
		t.Skipf("bpffs not accessible at %s: %v", bpffsRoot, err)
	}
	const bpfFsMagic = 0xcafe4a11
	if stat.Type != bpfFsMagic {
		t.Skipf("%s is not bpffs (fstype=0x%x)", bpffsRoot, stat.Type)
	}

	pinPath := filepath.Join(bpffsRoot, fmt.Sprintf("vinbero-test-%d", os.Getpid()))
	_ = os.RemoveAll(pinPath)
	t.Cleanup(func() { _ = os.RemoveAll(pinPath) })

	cfg := &config.Config{
		Setting: config.SettingConfig{
			PinMaps: config.PinMapsConfig{
				Enabled: true,
				Path:    pinPath,
			},
		},
	}

	// Phase 1: load fresh, create a SID entry, close.
	{
		objs, err := ReadCollection(nil, cfg)
		if err != nil {
			t.Fatalf("initial ReadCollection: %v", err)
		}
		mapOps := NewMapOperations(objs)
		nh, _ := ParseIPv6("fc00::1")
		entry := &SidFunctionEntry{Action: actionEndX}
		if err := mapOps.CreateSidFunction("fc00:1::1/128", entry, NewSidAuxNexthop(nh), OwnerRPC); err != nil {
			t.Fatalf("create: %v", err)
		}
		if err := objs.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
	}

	// The pin files should still be present on bpffs.
	for _, name := range pinnedControlMaps {
		if _, err := os.Stat(filepath.Join(pinPath, name)); err != nil {
			t.Fatalf("expected pin %q to persist after close: %v", name, err)
		}
	}

	// Phase 2: reload from the same pin path and verify the SID entry
	// is still there.
	{
		objs, err := ReadCollection(nil, cfg)
		if err != nil {
			t.Fatalf("reload ReadCollection: %v", err)
		}
		t.Cleanup(func() { _ = objs.Close() })
		mapOps := NewMapOperations(objs)
		got, err := mapOps.GetSidFunction("fc00:1::1/128")
		if err != nil {
			t.Fatalf("get after reload: %v", err)
		}
		if got.Action != actionEndX {
			t.Errorf("action after reload: got %d, want %d", got.Action, actionEndX)
		}
		if got.AuxIndex == 0 {
			t.Errorf("aux_index should be preserved across reload, got 0")
		}
	}
}

// TestStatsReadReset verifies ReadStats and ResetStats round-trip.
func TestStatsReadReset(t *testing.T) {
	h := newXDPTestHelper(t)

	// Read stats (should be all zeros since enable_stats=false by default)
	stats, err := h.mapOps.ReadStats()
	if err != nil {
		t.Fatalf("ReadStats: %v", err)
	}
	if len(stats) != StatsMax {
		t.Fatalf("expected %d counters, got %d", StatsMax, len(stats))
	}
	for _, s := range stats {
		if s.Name == "" {
			t.Error("counter name is empty")
		}
	}

	// Reset should succeed even with all-zero counters
	if err := h.mapOps.ResetStats(); err != nil {
		t.Fatalf("ResetStats: %v", err)
	}

	// Read again — should still be zeros
	stats2, err := h.mapOps.ReadStats()
	if err != nil {
		t.Fatalf("ReadStats after reset: %v", err)
	}
	for _, s := range stats2 {
		if s.Packets != 0 || s.Bytes != 0 {
			t.Errorf("counter %s not zero after reset: packets=%d, bytes=%d", s.Name, s.Packets, s.Bytes)
		}
	}
}

// TestSlotStatsReadReset verifies per-slot counters round-trip for all
// three PROG_ARRAYs (endpoint / headend_v4 / headend_v6).
func TestSlotStatsReadReset(t *testing.T) {
	h := newXDPTestHelper(t)

	cases := []struct {
		mapType string
		max     int
	}{
		{MapTypeEndpoint, SlotStatsEndpointMax},
		{MapTypeHeadendV4, SlotStatsHeadendMax},
		{MapTypeHeadendV6, SlotStatsHeadendMax},
	}
	for _, tc := range cases {
		t.Run(tc.mapType, func(t *testing.T) {
			entries, err := h.mapOps.ReadSlotStats(tc.mapType)
			if err != nil {
				t.Fatalf("ReadSlotStats(%s): %v", tc.mapType, err)
			}
			if len(entries) != tc.max {
				t.Fatalf("expected %d entries, got %d", tc.max, len(entries))
			}
			for _, e := range entries {
				if e.MapType != tc.mapType {
					t.Errorf("map_type=%s, want %s", e.MapType, tc.mapType)
				}
				if e.Packets != 0 || e.Bytes != 0 {
					t.Errorf("slot %d not zero on fresh read: p=%d b=%d",
						e.Slot, e.Packets, e.Bytes)
				}
			}

			if err := h.mapOps.ResetSlotStats(tc.mapType); err != nil {
				t.Fatalf("ResetSlotStats(%s): %v", tc.mapType, err)
			}

			entries2, err := h.mapOps.ReadSlotStats(tc.mapType)
			if err != nil {
				t.Fatalf("ReadSlotStats after reset: %v", err)
			}
			for _, e := range entries2 {
				if e.Packets != 0 || e.Bytes != 0 {
					t.Errorf("slot %d not zero after reset: p=%d b=%d",
						e.Slot, e.Packets, e.Bytes)
				}
			}
		})
	}
}

// TestFdbAging verifies that AgeFdbEntries deletes stale dynamic entries
// and preserves static entries.
func TestFdbAging(t *testing.T) {
	h := newXDPTestHelper(t)

	bdID := uint16(100)

	// Create a dynamic entry (is_static=0, last_seen=1 → extremely old)
	dynamicMAC := net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	dynamicEntry := &FdbEntry{
		Oif:      1,
		LastSeen: 1, // very old timestamp (nanoseconds)
	}
	if err := h.mapOps.CreateFdb(bdID, dynamicMAC, dynamicEntry); err != nil {
		t.Fatalf("create dynamic: %v", err)
	}

	// Create a static entry (is_static=1, last_seen=0)
	staticMAC := net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x02}
	staticEntry := &FdbEntry{
		Oif:      2,
		IsStatic: 1,
		LastSeen: 0,
	}
	if err := h.mapOps.CreateFdb(bdID, staticMAC, staticEntry); err != nil {
		t.Fatalf("create static: %v", err)
	}

	// Create a fresh dynamic entry (last_seen = now, won't be aged)
	freshMAC := net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x03}
	freshEntry := &FdbEntry{
		Oif:      3,
		LastSeen: currentKtimeNs(),
	}
	if err := h.mapOps.CreateFdb(bdID, freshMAC, freshEntry); err != nil {
		t.Fatalf("create fresh: %v", err)
	}

	// Age with 1s timeout — should delete the old entry (last_seen=1ns is ancient)
	// Use short timeout because CI VMs may have small CLOCK_MONOTONIC after boot.
	aged, err := h.mapOps.AgeFdbEntries(1e9) // 1 second in ns
	if err != nil {
		t.Fatalf("AgeFdbEntries: %v", err)
	}
	if len(aged) != 1 {
		t.Errorf("expected 1 deleted, got %d", len(aged))
	} else if aged[0].BDID != bdID || aged[0].MAC.String() != dynamicMAC.String() {
		t.Errorf("aged entry = bd %d mac %s, want bd %d mac %s",
			aged[0].BDID, aged[0].MAC, bdID, dynamicMAC)
	}

	// Verify: old dynamic entry gone
	if _, err := h.mapOps.GetFdb(bdID, dynamicMAC); err == nil {
		t.Error("old dynamic entry should have been aged out")
	}

	// Verify: static entry preserved
	if _, err := h.mapOps.GetFdb(bdID, staticMAC); err != nil {
		t.Error("static entry should not have been aged out")
	}

	// Verify: fresh dynamic entry preserved
	if _, err := h.mapOps.GetFdb(bdID, freshMAC); err != nil {
		t.Error("fresh dynamic entry should not have been aged out")
	}
}

// TestFdbMacLearningTimestamp verifies that BPF MAC learning sets last_seen.
func TestFdbMacLearningTimestamp(t *testing.T) {
	h := newXDPTestHelper(t)

	srcAddr, _ := ParseIPv6("fc00::1")
	segments, numSegments, _ := ParseSegments([]string{"fc00::200"})
	bdID := uint16(100)

	h.createHeadendL2Entry(0, 100, srcAddr, segments, numSegments, bdID)
	h.createHeadendL2Entry(1, 100, srcAddr, segments, numSegments, bdID)

	// Build VLAN 100 tagged packet
	pkt, err := buildVlanTaggedIPv4Packet(100,
		net.ParseIP("10.0.0.1").To4(), net.ParseIP("192.0.2.100").To4())
	if err != nil {
		t.Fatalf("build packet: %v", err)
	}

	// Run XDP — triggers MAC learning
	h.run(pkt)

	// Check FDB entry has non-zero last_seen
	srcMAC := net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	fdbEntry, err := h.mapOps.GetFdb(bdID, srcMAC)
	if err != nil {
		t.Fatalf("src MAC not learned: %v", err)
	}
	if fdbEntry.LastSeen == 0 {
		t.Error("BPF-learned FDB entry should have non-zero last_seen timestamp")
	}
	if fdbEntry.IsStatic != 0 {
		t.Error("BPF-learned FDB entry should not be static")
	}
	t.Logf("SUCCESS: learned MAC=%s oif=%d last_seen=%d", srcMAC, fdbEntry.Oif, fdbEntry.LastSeen)
}

// TestDeleteSidFunctionPreservesPluginAux pins the contract that DeleteSidFunction
// only releases builtin-owned aux indices; plugin-owned aux must survive a SID
// unbind so the plugin's PluginAuxFree RPC stays in charge of that lifecycle.
// Regressions here would let SID delete corrupt unrelated plugin state.
func TestDeleteSidFunctionPreservesPluginAux(t *testing.T) {
	h := newXDPTestHelper(t)

	owner := AuxOwnerPluginTag(MapTypeEndpoint, EndpointPluginBase)
	idx, err := h.mapOps.AllocPluginAux(owner)
	if err != nil {
		t.Fatalf("AllocPluginAux: %v", err)
	}
	if idx == 0 {
		t.Fatal("AllocPluginAux returned sentinel 0")
	}

	const prefix = "fc00:1::1/128"
	entry := &SidFunctionEntry{
		Action:   uint8(EndpointPluginBase),
		AuxIndex: uint16(idx),
	}
	if err := h.mapOps.CreateSidFunctionWithAuxIndex(prefix, entry, owner, OwnerRPC); err != nil {
		t.Fatalf("CreateSidFunctionWithAuxIndex: %v", err)
	}

	if err := h.mapOps.DeleteSidFunction(prefix, OwnerRPC); err != nil {
		t.Fatalf("DeleteSidFunction: %v", err)
	}

	// Plugin owner tag must still be intact — DeleteSidFunction only unbinds
	// the SID, never the plugin aux slot.
	if got := h.mapOps.auxAlloc.OwnerOf(idx); got != owner {
		t.Errorf("aux owner after SID delete: got %q, want %q", got, owner)
	}
	if _, err := h.mapOps.GetPluginAux(idx, owner); err != nil {
		t.Errorf("GetPluginAux after SID delete: %v", err)
	}
	if err := h.mapOps.FreePluginAux(idx, owner); err != nil {
		t.Errorf("FreePluginAux: %v", err)
	}
	if got := h.mapOps.auxAlloc.OwnerOf(idx); got != "" {
		t.Errorf("aux owner after FreePluginAux: got %q, want \"\"", got)
	}
}
