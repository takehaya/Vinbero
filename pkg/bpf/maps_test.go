package bpf

import (
	"net"
	"testing"
)

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

	// Create entries with aux (indices 0, 1)
	nh, _ := ParseIPv6("fc00::1")
	e1 := &SidFunctionEntry{Action: actionEndX}
	if err := h.mapOps.CreateSidFunction("fc00:1::1/128", e1, NewSidAuxNexthop(nh)); err != nil {
		t.Fatalf("create 1: %v", err)
	}
	e2 := &SidFunctionEntry{Action: actionEndX}
	if err := h.mapOps.CreateSidFunction("fc00:2::1/128", e2, NewSidAuxNexthop(nh)); err != nil {
		t.Fatalf("create 2: %v", err)
	}
	// Create entry without aux (no index used)
	e3 := &SidFunctionEntry{Action: actionEnd}
	if err := h.mapOps.CreateSidFunction("fc00:3::1/128", e3, nil); err != nil {
		t.Fatalf("create 3: %v", err)
	}

	// Delete entry 1 to create a gap (index 0 freed)
	if err := h.mapOps.DeleteSidFunction("fc00:1::1/128"); err != nil {
		t.Fatalf("delete: %v", err)
	}

	// Simulate restart: create fresh MapOperations and recover
	freshMapOps := NewMapOperations(h.objs)
	if err := freshMapOps.RecoverAuxIndices(); err != nil {
		t.Fatalf("recover: %v", err)
	}

	// Allocate new index — should get 0 (freed gap), not 2
	e4 := &SidFunctionEntry{Action: actionEndX}
	if err := freshMapOps.CreateSidFunction("fc00:4::1/128", e4, NewSidAuxNexthop(nh)); err != nil {
		t.Fatalf("create after recover: %v", err)
	}

	got, err := freshMapOps.GetSidFunction("fc00:4::1/128")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.AuxIndex != 0 {
		t.Errorf("expected recovered gap index 0, got %d", got.AuxIndex)
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
	deleted, err := h.mapOps.AgeFdbEntries(1e9) // 1 second in ns
	if err != nil {
		t.Fatalf("AgeFdbEntries: %v", err)
	}
	if deleted != 1 {
		t.Errorf("expected 1 deleted, got %d", deleted)
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
