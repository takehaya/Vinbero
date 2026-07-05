package bpf

import (
	"fmt"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	vinberov1 "github.com/takehaya/vinbero/api/vinbero/v1"
)

// buildUDPIPv4Packet constructs an IPv4/UDP packet with the given ports so
// ECMP tests can vary the 5-tuple per flow.
func buildUDPIPv4Packet(srcIP, dstIP net.IP, srcPort, dstPort uint16) ([]byte, error) {
	eth := newTestEthernet(layers.EthernetTypeIPv4)
	ip4 := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		Protocol: layers.IPProtocolUDP, SrcIP: srcIP, DstIP: dstIP,
	}
	udp := &layers.UDP{SrcPort: layers.UDPPort(srcPort), DstPort: layers.UDPPort(dstPort)}
	if err := udp.SetNetworkLayerForChecksum(ip4); err != nil {
		return nil, err
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip4, udp, gopacket.Payload(newTestPayload(32))); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// buildUDPIPv6Packet is the IPv6 counterpart of buildUDPIPv4Packet.
func buildUDPIPv6Packet(srcIP, dstIP net.IP, srcPort, dstPort uint16) ([]byte, error) {
	eth := newTestEthernet(layers.EthernetTypeIPv6)
	ip6 := &layers.IPv6{
		Version: 6, SrcIP: srcIP, DstIP: dstIP,
		NextHeader: layers.IPProtocolUDP, HopLimit: 64,
	}
	udp := &layers.UDP{SrcPort: layers.UDPPort(srcPort), DstPort: layers.UDPPort(dstPort)}
	if err := udp.SetNetworkLayerForChecksum(ip6); err != nil {
		return nil, err
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip6, udp, gopacket.Payload(newTestPayload(32))); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// outerIPv6DA extracts the outer IPv6 destination address of an encapsulated
// output packet (Ethernet at 0, IPv6 at 14).
func outerIPv6DA(t *testing.T, pkt []byte) [16]byte {
	t.Helper()
	var da [16]byte
	if len(pkt) < 14+40 {
		t.Fatalf("packet too short for outer IPv6: %d bytes", len(pkt))
	}
	copy(da[:], pkt[14+24:14+40])
	return da
}

// outerFlowLabel extracts the outer IPv6 flow label.
func outerFlowLabel(t *testing.T, pkt []byte) uint32 {
	t.Helper()
	if len(pkt) < 14+4 {
		t.Fatalf("packet too short for outer IPv6: %d bytes", len(pkt))
	}
	return uint32(pkt[14+1]&0x0F)<<16 | uint32(pkt[14+2])<<8 | uint32(pkt[14+3])
}

// ecmpTestGroup installs a headend entry on prefix that references an ECMP
// group whose paths encap to the given SIDs (one segment each, equal or
// custom weights). The parent entry carries fallback segments pointing at
// fallbackSID when non-zero.
type ecmpTestFixture struct {
	h       *xdpTestHelper
	srcAddr [16]byte
	sids    [][16]byte
}

func newEcmpFixture(t *testing.T, weights []uint16) *ecmpTestFixture {
	t.Helper()
	h := newXDPTestHelper(t)
	srcAddr, _ := ParseIPv6("fc00::1")

	sids := make([][16]byte, len(weights))
	paths := make([]*HeadendEntry, len(weights))
	for i := range weights {
		sid, _ := ParseIPv6(fmt.Sprintf("fd00:e0%d::1", i))
		sids[i] = sid
		var segs [MaxSegments][IPv6AddrLen]uint8
		segs[0] = sid
		paths[i] = &HeadendEntry{
			Mode:        uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS),
			NumSegments: 1,
			SrcAddr:     srcAddr,
			Segments:    segs,
		}
	}
	const groupID = 42
	if err := h.mapOps.PutEcmpGroup(groupID, paths, weights, OwnerRPC); err != nil {
		t.Fatalf("PutEcmpGroup: %v", err)
	}

	// Parent trigger entry: pure group reference (no fallback segments).
	parent := &HeadendEntry{
		Mode:    uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS),
		SrcAddr: srcAddr,
		GroupId: groupID,
	}
	if err := h.mapOps.CreateHeadendV4("192.0.2.0/24", parent, OwnerRPC); err != nil {
		t.Fatalf("CreateHeadendV4: %v", err)
	}
	return &ecmpTestFixture{h: h, srcAddr: srcAddr, sids: sids}
}

// classify runs the packet and returns which path SID the outer DA matches,
// or -1 for none.
func (f *ecmpTestFixture) classify(t *testing.T, pkt []byte) int {
	t.Helper()
	ret, out := f.h.run(pkt)
	if ret != XDP_PASS {
		t.Fatalf("expected XDP_PASS, got %d", ret)
	}
	da := outerIPv6DA(t, out)
	for i, sid := range f.sids {
		if da == sid {
			return i
		}
	}
	return -1
}

// spread pushes nFlows UDP flows (varying source port) through the fixture
// and returns the per-path hit counts.
func (f *ecmpTestFixture) spread(t *testing.T, nFlows int) []int {
	t.Helper()
	src := net.ParseIP("10.0.0.1").To4()
	dst := net.ParseIP("192.0.2.100").To4()
	counts := make([]int, len(f.sids))
	for i := range nFlows {
		pkt, err := buildUDPIPv4Packet(src, dst, uint16(20000+i), 443)
		if err != nil {
			t.Fatalf("build packet: %v", err)
		}
		sel := f.classify(t, pkt)
		if sel < 0 {
			t.Fatalf("flow %d: outer DA matches no path SID", i)
		}
		counts[sel]++
	}
	return counts
}

// TestXDPProgECMPGroup exercises the headend ECMP group data plane: weighted
// hash-modulo path selection, per-flow stability, liveness-driven fast
// reroute, fail-open on an all-dead bitmap, and the parent-entry fallback on
// group misses.
func TestXDPProgECMPGroup(t *testing.T) {
	t.Run("spreads flows across equal-weight paths", func(t *testing.T) {
		f := newEcmpFixture(t, []uint16{1, 1})
		counts := f.spread(t, 128)
		t.Logf("distribution: %v", counts)
		for i, c := range counts {
			// jhash over 128 distinct 5-tuples: each of two equal paths must
			// take a substantial share. 25% is far below the binomial mean
			// (50%) but far above what a broken constant hash would yield.
			if c < 32 {
				t.Errorf("path %d took %d/128 flows, want >= 32", i, c)
			}
		}
	})

	t.Run("same flow always picks the same path", func(t *testing.T) {
		f := newEcmpFixture(t, []uint16{1, 1})
		src := net.ParseIP("10.0.0.1").To4()
		dst := net.ParseIP("192.0.2.100").To4()
		pkt, err := buildUDPIPv4Packet(src, dst, 33333, 443)
		if err != nil {
			t.Fatalf("build packet: %v", err)
		}
		first := f.classify(t, pkt)
		for range 16 {
			if got := f.classify(t, pkt); got != first {
				t.Fatalf("flow flapped: first %d, now %d", first, got)
			}
		}
	})

	t.Run("weights skew the distribution", func(t *testing.T) {
		f := newEcmpFixture(t, []uint16{7, 1})
		counts := f.spread(t, 128)
		t.Logf("distribution: %v", counts)
		if counts[0] <= counts[1] {
			t.Errorf("weight 7 path took %d flows, weight 1 path %d; want a clear majority on path 0",
				counts[0], counts[1])
		}
		if counts[1] == 0 {
			t.Errorf("weight 1 path took no flows; UCMP must not starve low-weight paths")
		}
	})

	t.Run("liveness flip reroutes and restores", func(t *testing.T) {
		f := newEcmpFixture(t, []uint16{1, 1})
		const groupID = 42

		// Kill path 0: everything must land on path 1.
		if err := f.h.mapOps.SetEcmpLive(groupID, 0b10); err != nil {
			t.Fatalf("SetEcmpLive: %v", err)
		}
		counts := f.spread(t, 64)
		if counts[0] != 0 || counts[1] != 64 {
			t.Fatalf("with path 0 dead, distribution = %v, want [0 64]", counts)
		}

		// Recover: both paths carry traffic again.
		if err := f.h.mapOps.SetEcmpLive(groupID, 0b11); err != nil {
			t.Fatalf("SetEcmpLive: %v", err)
		}
		counts = f.spread(t, 128)
		if counts[0] < 32 || counts[1] < 32 {
			t.Fatalf("after recovery, distribution = %v, want both paths >= 32", counts)
		}

		// Removing the bitmap restores the fail-open default.
		if err := f.h.mapOps.DeleteEcmpLive(groupID); err != nil {
			t.Fatalf("DeleteEcmpLive: %v", err)
		}
		counts = f.spread(t, 128)
		if counts[0] < 32 || counts[1] < 32 {
			t.Fatalf("with no bitmap, distribution = %v, want both paths >= 32", counts)
		}
	})

	t.Run("all-dead bitmap fails open", func(t *testing.T) {
		f := newEcmpFixture(t, []uint16{1, 1})
		if err := f.h.mapOps.SetEcmpLive(42, 0); err != nil {
			t.Fatalf("SetEcmpLive: %v", err)
		}
		counts := f.spread(t, 128)
		// BGP still holds both paths; an all-dead prober verdict must spread
		// over the full set rather than drop.
		if counts[0] < 32 || counts[1] < 32 {
			t.Fatalf("all-dead distribution = %v, want both paths >= 32", counts)
		}
	})

	t.Run("group miss falls back to parent segments", func(t *testing.T) {
		h := newXDPTestHelper(t)
		srcAddr, _ := ParseIPv6("fc00::1")
		fallbackSID, _ := ParseIPv6("fd00:ff::1")
		var segs [MaxSegments][IPv6AddrLen]uint8
		segs[0] = fallbackSID
		parent := &HeadendEntry{
			Mode:        uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS),
			NumSegments: 1,
			SrcAddr:     srcAddr,
			Segments:    segs,
			GroupId:     999, // never installed
		}
		if err := h.mapOps.CreateHeadendV4("192.0.2.0/24", parent, OwnerRPC); err != nil {
			t.Fatalf("CreateHeadendV4: %v", err)
		}
		pkt, err := buildUDPIPv4Packet(net.ParseIP("10.0.0.1").To4(), net.ParseIP("192.0.2.100").To4(), 1234, 80)
		if err != nil {
			t.Fatalf("build packet: %v", err)
		}
		ret, out := h.run(pkt)
		if ret != XDP_PASS {
			t.Fatalf("expected XDP_PASS, got %d", ret)
		}
		if da := outerIPv6DA(t, out); da != fallbackSID {
			t.Fatalf("outer DA = %x, want fallback SID", da)
		}
	})

	t.Run("pure group ref with dead group drops", func(t *testing.T) {
		h := newXDPTestHelper(t)
		srcAddr, _ := ParseIPv6("fc00::1")
		parent := &HeadendEntry{
			Mode:    uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS),
			SrcAddr: srcAddr,
			GroupId: 999, // never installed, and no fallback segments
		}
		if err := h.mapOps.CreateHeadendV4("192.0.2.0/24", parent, OwnerRPC); err != nil {
			t.Fatalf("CreateHeadendV4: %v", err)
		}
		pkt, err := buildUDPIPv4Packet(net.ParseIP("10.0.0.1").To4(), net.ParseIP("192.0.2.100").To4(), 1234, 80)
		if err != nil {
			t.Fatalf("build packet: %v", err)
		}
		ret, _ := h.run(pkt)
		if ret != XDP_DROP {
			t.Fatalf("expected XDP_DROP, got %d", ret)
		}
	})

	t.Run("ipv6 flows spread too", func(t *testing.T) {
		h := newXDPTestHelper(t)
		srcAddr, _ := ParseIPv6("fc00::1")
		sidA, _ := ParseIPv6("fd00:e00::1")
		sidB, _ := ParseIPv6("fd00:e01::1")
		paths := make([]*HeadendEntry, 2)
		for i, sid := range [][16]byte{sidA, sidB} {
			var segs [MaxSegments][IPv6AddrLen]uint8
			segs[0] = sid
			paths[i] = &HeadendEntry{
				Mode:        uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS),
				NumSegments: 1,
				SrcAddr:     srcAddr,
				Segments:    segs,
			}
		}
		if err := h.mapOps.PutEcmpGroup(43, paths, []uint16{1, 1}, OwnerRPC); err != nil {
			t.Fatalf("PutEcmpGroup: %v", err)
		}
		parent := &HeadendEntry{
			Mode:    uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS),
			SrcAddr: srcAddr,
			GroupId: 43,
		}
		if err := h.mapOps.CreateHeadendV6("2001:db8:100::/64", parent, OwnerRPC); err != nil {
			t.Fatalf("CreateHeadendV6: %v", err)
		}

		src := net.ParseIP("2001:db8:1::1")
		dst := net.ParseIP("2001:db8:100::100")
		counts := map[[16]byte]int{}
		for i := range 128 {
			pkt, err := buildUDPIPv6Packet(src, dst, uint16(20000+i), 443)
			if err != nil {
				t.Fatalf("build packet: %v", err)
			}
			ret, out := h.run(pkt)
			if ret != XDP_PASS {
				t.Fatalf("expected XDP_PASS, got %d", ret)
			}
			counts[outerIPv6DA(t, out)]++
		}
		t.Logf("distribution: A=%d B=%d", counts[sidA], counts[sidB])
		if counts[sidA] < 32 || counts[sidB] < 32 {
			t.Fatalf("v6 distribution A=%d B=%d, want both >= 32", counts[sidA], counts[sidB])
		}
	})
}

// TestXDPProgECMPFlowLabel verifies the RFC 6437 outer flow-label entropy:
// every hashed headend encap (grouped or not) writes a non-zero label that
// is stable per flow and varies across flows.
func TestXDPProgECMPFlowLabel(t *testing.T) {
	h := newXDPTestHelper(t)
	srcAddr, _ := ParseIPv6("fc00::1")
	sid, _ := ParseIPv6("fd00:5fc::1")
	var segs [MaxSegments][IPv6AddrLen]uint8
	segs[0] = sid
	entry := &HeadendEntry{
		Mode:        uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS),
		NumSegments: 1,
		SrcAddr:     srcAddr,
		Segments:    segs,
	}
	if err := h.mapOps.CreateHeadendV4("192.0.2.0/24", entry, OwnerRPC); err != nil {
		t.Fatalf("CreateHeadendV4: %v", err)
	}

	src := net.ParseIP("10.0.0.1").To4()
	dst := net.ParseIP("192.0.2.100").To4()
	label := func(srcPort uint16) uint32 {
		pkt, err := buildUDPIPv4Packet(src, dst, srcPort, 443)
		if err != nil {
			t.Fatalf("build packet: %v", err)
		}
		ret, out := h.run(pkt)
		if ret != XDP_PASS {
			t.Fatalf("expected XDP_PASS, got %d", ret)
		}
		return outerFlowLabel(t, out)
	}

	l1 := label(10001)
	if l1 == 0 {
		t.Fatal("hashed flow produced flow label 0; entropy is missing")
	}
	if l2 := label(10001); l2 != l1 {
		t.Fatalf("same flow produced different labels: %#x vs %#x", l1, l2)
	}
	// Across 32 distinct flows at least two labels must differ (equal labels
	// for all would mean the hash ignores the L4 ports).
	distinct := map[uint32]struct{}{}
	for i := range 32 {
		distinct[label(uint16(11000+i))] = struct{}{}
	}
	if len(distinct) < 2 {
		t.Fatalf("32 flows produced %d distinct labels, want >= 2", len(distinct))
	}
}

// TestEcmpGroupCRUD covers the userspace API surface: validation, round
// trips, single-path replace, owner enforcement, and teardown.
func TestEcmpGroupCRUD(t *testing.T) {
	h := newXDPTestHelper(t)
	srcAddr, _ := ParseIPv6("fc00::1")
	newPath := func(sidStr string) *HeadendEntry {
		sid, _ := ParseIPv6(sidStr)
		var segs [MaxSegments][IPv6AddrLen]uint8
		segs[0] = sid
		return &HeadendEntry{
			Mode:        uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS),
			NumSegments: 1,
			SrcAddr:     srcAddr,
			Segments:    segs,
		}
	}

	t.Run("validation", func(t *testing.T) {
		p := newPath("fd00::1")
		if err := h.mapOps.PutEcmpGroup(0, []*HeadendEntry{p}, []uint16{1}, OwnerRPC); err == nil {
			t.Error("group id 0 must be rejected (sentinel)")
		}
		if err := h.mapOps.PutEcmpGroup(1, nil, nil, OwnerRPC); err == nil {
			t.Error("empty path list must be rejected")
		}
		if err := h.mapOps.PutEcmpGroup(1, []*HeadendEntry{p}, []uint16{0}, OwnerRPC); err == nil {
			t.Error("zero weight must be rejected")
		}
		if err := h.mapOps.PutEcmpGroup(1, []*HeadendEntry{p}, []uint16{1, 2}, OwnerRPC); err == nil {
			t.Error("weights/paths length mismatch must be rejected")
		}
		many := make([]*HeadendEntry, EcmpMaxPaths+1)
		w := make([]uint16, EcmpMaxPaths+1)
		for i := range many {
			many[i], w[i] = p, 1
		}
		if err := h.mapOps.PutEcmpGroup(1, many, w, OwnerRPC); err == nil {
			t.Errorf("more than %d paths must be rejected", EcmpMaxPaths)
		}
	})

	t.Run("round trip, shrink, and delete", func(t *testing.T) {
		const id = 7
		paths := []*HeadendEntry{newPath("fd00:a::1"), newPath("fd00:b::1"), newPath("fd00:c::1")}
		if err := h.mapOps.PutEcmpGroup(id, paths, []uint16{2, 1, 1}, OwnerRPC); err != nil {
			t.Fatalf("PutEcmpGroup: %v", err)
		}
		info, got, err := h.mapOps.GetEcmpGroup(id)
		if err != nil {
			t.Fatalf("GetEcmpGroup: %v", err)
		}
		if info == nil || info.NumPaths != 3 || info.Weight[0] != 2 || info.Weight[1] != 1 {
			t.Fatalf("group info = %+v, want 3 paths weights [2 1 1]", info)
		}
		if len(got) != 3 || got[0] == nil || got[0].Segments[0] != paths[0].Segments[0] {
			t.Fatalf("paths round trip mismatch")
		}
		// Paths are forced terminal.
		if got[0].GroupId != EcmpGroupNone {
			t.Errorf("stored path GroupId = %d, want 0", got[0].GroupId)
		}

		// Shrink to 1: stale tail slots must disappear.
		if err := h.mapOps.PutEcmpGroup(id, paths[:1], []uint16{1}, OwnerRPC); err != nil {
			t.Fatalf("PutEcmpGroup shrink: %v", err)
		}
		info, got, err = h.mapOps.GetEcmpGroup(id)
		if err != nil || info == nil || info.NumPaths != 1 || len(got) != 1 {
			t.Fatalf("after shrink: info=%+v paths=%d err=%v", info, len(got), err)
		}
		var stale HeadendEntry
		if err := h.objs.EcmpPathMap.Lookup(EcmpPathKey{GroupId: id, PathIndex: 1}, &stale); err == nil {
			t.Error("stale path slot 1 survived the shrink")
		}

		if err := h.mapOps.SetEcmpLive(id, 0b1); err != nil {
			t.Fatalf("SetEcmpLive: %v", err)
		}
		if err := h.mapOps.DeleteEcmpGroup(id, OwnerRPC); err != nil {
			t.Fatalf("DeleteEcmpGroup: %v", err)
		}
		info, _, err = h.mapOps.GetEcmpGroup(id)
		if err != nil || info != nil {
			t.Fatalf("after delete: info=%+v err=%v, want nil/nil", info, err)
		}
		if _, ok, _ := h.mapOps.GetEcmpLive(id); ok {
			t.Error("liveness bitmap survived group delete")
		}
	})

	t.Run("SetEcmpPath replaces in place", func(t *testing.T) {
		const id = 8
		if err := h.mapOps.PutEcmpGroup(id, []*HeadendEntry{newPath("fd00:a::1"), newPath("fd00:b::1")}, []uint16{1, 1}, OwnerRPC); err != nil {
			t.Fatalf("PutEcmpGroup: %v", err)
		}
		repl := newPath("fd00:bb::1")
		if err := h.mapOps.SetEcmpPath(id, 1, repl, OwnerRPC); err != nil {
			t.Fatalf("SetEcmpPath: %v", err)
		}
		_, got, err := h.mapOps.GetEcmpGroup(id)
		if err != nil || len(got) != 2 || got[1] == nil {
			t.Fatalf("GetEcmpGroup after replace: %v", err)
		}
		if got[1].Segments[0] != repl.Segments[0] {
			t.Error("path 1 was not replaced")
		}
		// Out-of-coverage index must be rejected.
		if err := h.mapOps.SetEcmpPath(id, 5, repl, OwnerRPC); err == nil {
			t.Error("index beyond num_paths must be rejected")
		}
	})

	t.Run("owner enforcement", func(t *testing.T) {
		const id = 9
		if err := h.mapOps.PutEcmpGroup(id, []*HeadendEntry{newPath("fd00:a::1")}, []uint16{1}, OwnerRPC); err != nil {
			t.Fatalf("PutEcmpGroup: %v", err)
		}
		other := OwnerTag("bgp:v1:asn=65000:ecmp")
		if err := h.mapOps.PutEcmpGroup(id, []*HeadendEntry{newPath("fd00:b::1")}, []uint16{1}, other); err == nil {
			t.Error("cross-owner overwrite must be rejected")
		}
		if err := h.mapOps.DeleteEcmpGroup(id, other); err == nil {
			t.Error("cross-owner delete must be rejected")
		}
		if err := h.mapOps.ForceDeleteEcmpGroup(id); err != nil {
			t.Errorf("ForceDeleteEcmpGroup: %v", err)
		}
	})
}
