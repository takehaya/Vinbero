package bpf

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	vinberov1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/packet"
)

// newTestEthernet creates a standard Ethernet header for testing
func newTestEthernet() *layers.Ethernet {
	return &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv6,
	}
}

// newTestICMPv6Echo creates standard ICMPv6 Echo Request headers for testing
func newTestICMPv6Echo() (*layers.ICMPv6, *layers.ICMPv6Echo) {
	icmp := &layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0),
	}
	icmpEcho := &layers.ICMPv6Echo{
		Identifier: 1234,
		SeqNumber:  1,
	}
	return icmp, icmpEcho
}

// newTestPayload creates a test payload of the specified size
func newTestPayload(size int) []byte {
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i)
	}
	return payload
}

// buildSRv6Packet constructs an SRv6 packet with the given parameters
func buildSRv6Packet(srcIP, dstIP net.IP, segments []net.IP, segmentsLeft uint8) ([]byte, error) {
	eth := newTestEthernet()

	ip6 := &layers.IPv6{
		Version:    6,
		SrcIP:      srcIP,
		DstIP:      dstIP,
		NextHeader: layers.IPProtocol(43), // IPPROTO_ROUTING
		HopLimit:   64,
	}

	// Convert segments to netip.Addr
	segAddrs := make([]netip.Addr, len(segments))
	for i, seg := range segments {
		addr, ok := netip.AddrFromSlice(seg.To16())
		if !ok {
			return nil, nil
		}
		segAddrs[i] = addr
	}

	// Build SRv6 Layer
	numSegments := len(segments)
	srv6 := &packet.Srv6Layer{
		NextHeader:   58, // ICMPv6
		HdrExtLen:    uint8(numSegments * 2),
		RoutingType:  4, // Segment Routing
		SegmentsLeft: segmentsLeft,
		LastEntry:    uint8(numSegments - 1),
		Flags:        0,
		Tag:          0,
		Segments:     segAddrs,
	}

	icmp, icmpEcho := newTestICMPv6Echo()
	payload := newTestPayload(64)

	// Serialize the packet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	_ = icmp.SetNetworkLayerForChecksum(ip6)
	if err := gopacket.SerializeLayers(buf, opts,
		eth, ip6, srv6, icmp, icmpEcho, gopacket.Payload(payload)); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// buildSimpleIPv6Packet constructs a simple IPv6 packet without SRH
func buildSimpleIPv6Packet(srcIP, dstIP net.IP) ([]byte, error) {
	eth := newTestEthernet()

	ip6 := &layers.IPv6{
		Version:    6,
		SrcIP:      srcIP,
		DstIP:      dstIP,
		NextHeader: layers.IPProtocolICMPv6,
		HopLimit:   64,
	}

	icmp, icmpEcho := newTestICMPv6Echo()
	payload := newTestPayload(64)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	_ = icmp.SetNetworkLayerForChecksum(ip6)
	if err := gopacket.SerializeLayers(buf, opts, eth, ip6, icmp, icmpEcho, gopacket.Payload(payload)); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// buildSimpleIPv4Packet constructs a simple IPv4 packet
func buildSimpleIPv4Packet(srcIP, dstIP net.IP) ([]byte, error) {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip4 := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolICMPv4,
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}

	icmp := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		Id:       1234,
		Seq:      1,
	}

	payload := newTestPayload(64)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buf, opts, eth, ip4, icmp, gopacket.Payload(payload)); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// ========== H.Encaps Verification Helper Functions ==========

// Packet offsets for encapsulated packets
const (
	ethHeaderLen  = 14
	ipv6HeaderLen = 40
	srhBaseLen    = 8 // SRH header without segments
	ipv6AddrLen   = 16
	ipv4HeaderLen = 20
)

// verifyEthernetIPv6 verifies that the Ethernet header indicates IPv6
func verifyEthernetIPv6(t *testing.T, pkt []byte) bool {
	t.Helper()
	if len(pkt) < ethHeaderLen {
		t.Errorf("Packet too short for Ethernet header: %d bytes", len(pkt))
		return false
	}
	etherType := binary.BigEndian.Uint16(pkt[12:14])
	if etherType != 0x86DD {
		t.Errorf("Expected EtherType 0x86DD (IPv6), got 0x%04X", etherType)
		return false
	}
	return true
}

// verifyOuterIPv6Header verifies the outer IPv6 header of an encapsulated packet
func verifyOuterIPv6Header(t *testing.T, pkt []byte, expectedSrc, expectedDst [16]byte) bool {
	t.Helper()
	offset := ethHeaderLen
	if len(pkt) < offset+ipv6HeaderLen {
		t.Errorf("Packet too short for IPv6 header: %d bytes", len(pkt))
		return false
	}

	// Version (should be 6)
	version := (pkt[offset] >> 4) & 0x0F
	if version != 6 {
		t.Errorf("Expected IPv6 version 6, got %d", version)
		return false
	}

	// Next Header (should be 43 for Routing)
	nextHeader := pkt[offset+6]
	if nextHeader != 43 {
		t.Errorf("Expected Next Header 43 (Routing), got %d", nextHeader)
		return false
	}

	// Source Address (offset 8-23)
	var actualSrc [16]byte
	copy(actualSrc[:], pkt[offset+8:offset+24])
	if !bytes.Equal(actualSrc[:], expectedSrc[:]) {
		t.Errorf("Source address mismatch: expected %x, got %x", expectedSrc, actualSrc)
		return false
	}

	// Destination Address (offset 24-39)
	var actualDst [16]byte
	copy(actualDst[:], pkt[offset+24:offset+40])
	if !bytes.Equal(actualDst[:], expectedDst[:]) {
		t.Errorf("Destination address mismatch: expected %x, got %x", expectedDst, actualDst)
		return false
	}

	return true
}

// verifySRHStructure verifies the SRH structure of an encapsulated packet
func verifySRHStructure(t *testing.T, pkt []byte, numSegments int, expectedSegments [][16]byte) bool {
	t.Helper()
	srhOffset := ethHeaderLen + ipv6HeaderLen
	srhLen := srhBaseLen + numSegments*ipv6AddrLen

	if len(pkt) < srhOffset+srhLen {
		t.Errorf("Packet too short for SRH: need %d bytes, have %d", srhOffset+srhLen, len(pkt))
		return false
	}

	// Routing Type (should be 4 for Segment Routing)
	routingType := pkt[srhOffset+2]
	if routingType != 4 {
		t.Errorf("Expected Routing Type 4 (SR), got %d", routingType)
		return false
	}

	// Segments Left (should be numSegments - 1)
	segmentsLeft := pkt[srhOffset+3]
	expectedSL := uint8(numSegments - 1)
	if segmentsLeft != expectedSL {
		t.Errorf("Expected Segments Left %d, got %d", expectedSL, segmentsLeft)
		return false
	}

	// First Segment (should be numSegments - 1)
	firstSegment := pkt[srhOffset+4]
	expectedFS := uint8(numSegments - 1)
	if firstSegment != expectedFS {
		t.Errorf("Expected First Segment %d, got %d", expectedFS, firstSegment)
		return false
	}

	// Verify segment list
	for i, expectedSeg := range expectedSegments {
		segOffset := srhOffset + srhBaseLen + i*ipv6AddrLen
		var actualSeg [16]byte
		copy(actualSeg[:], pkt[segOffset:segOffset+ipv6AddrLen])
		if !bytes.Equal(actualSeg[:], expectedSeg[:]) {
			t.Errorf("Segment[%d] mismatch: expected %x, got %x", i, expectedSeg, actualSeg)
			return false
		}
	}

	return true
}

// verifyInnerIPv4Packet verifies the inner IPv4 packet is preserved
func verifyInnerIPv4Packet(t *testing.T, pkt []byte, numSegments int, expectedSrc, expectedDst net.IP) bool {
	t.Helper()
	srhLen := srhBaseLen + numSegments*ipv6AddrLen
	innerOffset := ethHeaderLen + ipv6HeaderLen + srhLen

	if len(pkt) < innerOffset+ipv4HeaderLen {
		t.Errorf("Packet too short for inner IPv4: need %d bytes, have %d", innerOffset+ipv4HeaderLen, len(pkt))
		return false
	}

	// Version (should be 4)
	version := (pkt[innerOffset] >> 4) & 0x0F
	if version != 4 {
		t.Errorf("Expected inner IPv4 version 4, got %d", version)
		return false
	}

	// Source Address (offset 12-15)
	actualSrc := net.IP(pkt[innerOffset+12 : innerOffset+16])
	if !actualSrc.Equal(expectedSrc) {
		t.Errorf("Inner IPv4 source mismatch: expected %s, got %s", expectedSrc, actualSrc)
		return false
	}

	// Destination Address (offset 16-19)
	actualDst := net.IP(pkt[innerOffset+16 : innerOffset+20])
	if !actualDst.Equal(expectedDst) {
		t.Errorf("Inner IPv4 destination mismatch: expected %s, got %s", expectedDst, actualDst)
		return false
	}

	return true
}

// verifyInnerIPv6Packet verifies the inner IPv6 packet is preserved
func verifyInnerIPv6Packet(t *testing.T, pkt []byte, numSegments int, expectedSrc, expectedDst net.IP) bool {
	t.Helper()
	srhLen := srhBaseLen + numSegments*ipv6AddrLen
	innerOffset := ethHeaderLen + ipv6HeaderLen + srhLen

	if len(pkt) < innerOffset+ipv6HeaderLen {
		t.Errorf("Packet too short for inner IPv6: need %d bytes, have %d", innerOffset+ipv6HeaderLen, len(pkt))
		return false
	}

	// Version (should be 6)
	version := (pkt[innerOffset] >> 4) & 0x0F
	if version != 6 {
		t.Errorf("Expected inner IPv6 version 6, got %d", version)
		return false
	}

	// Source Address (offset 8-23)
	actualSrc := net.IP(pkt[innerOffset+8 : innerOffset+24])
	if !actualSrc.Equal(expectedSrc) {
		t.Errorf("Inner IPv6 source mismatch: expected %s, got %s", expectedSrc, actualSrc)
		return false
	}

	// Destination Address (offset 24-39)
	actualDst := net.IP(pkt[innerOffset+24 : innerOffset+40])
	if !actualDst.Equal(expectedDst) {
		t.Errorf("Inner IPv6 destination mismatch: expected %s, got %s", expectedDst, actualDst)
		return false
	}

	return true
}

// convertSegmentsToBytes converts segment addresses to byte arrays for verification
// Segments in SRH are stored in reverse order (last segment first)
func convertSegmentsToBytes(segments [10][16]byte, numSegments int) [][16]byte {
	result := make([][16]byte, numSegments)
	for i := range numSegments {
		result[i] = segments[numSegments-1-i]
	}
	return result
}

// TestXDPProgEnd tests the End operation with SRv6 packets
func TestXDPProgEnd(t *testing.T) {
	// Load BPF program
	objs, err := ReadCollection(nil, nil)
	if err != nil {
		t.Fatalf("Failed to load BPF objects: %v", err)
	}
	defer objs.Close()

	// Configure SID function map
	// Add End action for fd00:1:100::2/128
	mapOps := NewMapOperations(objs)
	triggerPrefix := "fd00:1:100::2/128"
	entry := &SidFunctionEntry{
		Action: 1, // SRV6_LOCAL_ACTION_END
		Flavor: 0, // No flavor
	}
	if err := mapOps.CreateSidFunction(triggerPrefix, entry); err != nil {
		t.Fatalf("Failed to create SID function entry: %v", err)
	}

	tests := []struct {
		name           string
		srcIP          string
		dstIP          string
		segments       []string
		segmentsLeft   uint8
		expectedAction uint32
		checkDA        bool
		expectedDA     string
	}{
		{
			name:           "End operation with SL=1",
			srcIP:          "fd00:1:1::1",
			dstIP:          "fd00:1:100::2",
			segments:       []string{"fd00:1:100::3", "fd00:1:100::2"},
			segmentsLeft:   1,
			expectedAction: XDP_PASS, // FIB lookup will likely fail in test, so XDP_PASS
			checkDA:        true,
			expectedDA:     "fd00:1:100::3", // DA should be updated to segments[0]
		},
		{
			name:           "End operation with SL=0",
			srcIP:          "fd00:1:1::1",
			dstIP:          "fd00:1:100::2",
			segments:       []string{"fd00:1:100::3", "fd00:1:100::2"},
			segmentsLeft:   0,
			expectedAction: XDP_PASS, // SL=0 should pass to upper layer
			checkDA:        false,
		},
		{
			name:           "End operation with SL=2",
			srcIP:          "fd00:1:1::1",
			dstIP:          "fd00:1:100::2",
			segments:       []string{"fd00:1:100::4", "fd00:1:100::3", "fd00:1:100::2"},
			segmentsLeft:   2,
			expectedAction: XDP_PASS,
			checkDA:        true,
			expectedDA:     "fd00:1:100::3", // DA should be updated to segments[1]
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build packet
			srcIP := net.ParseIP(tt.srcIP)
			dstIP := net.ParseIP(tt.dstIP)
			segments := make([]net.IP, len(tt.segments))
			for i, seg := range tt.segments {
				segments[i] = net.ParseIP(seg)
			}

			pkt, err := buildSRv6Packet(srcIP, dstIP, segments, tt.segmentsLeft)
			if err != nil {
				t.Fatalf("Failed to build SRv6 packet: %v", err)
			}

			// Run BPF program with bpf_prog_test_run
			opts := ebpf.RunOptions{
				Data:    pkt,
				DataOut: make([]byte, len(pkt)+256), // Extra space for modifications
				Repeat:  1,
			}

			ret, err := objs.VinberoMain.Run(&opts)
			if err != nil {
				t.Fatalf("Failed to run BPF program: %v", err)
			}

			if ret != tt.expectedAction {
				t.Errorf("Expected action %d, got %d", tt.expectedAction, ret)
			}

			// Check if DA was updated
			if tt.checkDA && tt.segmentsLeft > 0 {
				// Parse the output packet
				// DataOut contains the modified packet, but we need to check actual length
				outPkt := opts.DataOut
				if len(outPkt) < 14+40 {
					t.Fatal("Output packet too short")
				}

				// Extract DA from IPv6 header (bytes 38-53, 14 bytes Ethernet + 24-39 for DA)
				da := net.IP(outPkt[38:54])
				expectedDA := net.ParseIP(tt.expectedDA)

				if !da.Equal(expectedDA) {
					t.Errorf("Expected DA %s, got %s", expectedDA, da)
				}

				// Also check that segments_left was decremented
				// SRH starts at offset 54 (14 Ethernet + 40 IPv6)
				if len(outPkt) > 54+3 {
					newSL := outPkt[54+3] // segments_left is at offset 3 in SRH
					expectedSL := tt.segmentsLeft - 1
					if newSL != expectedSL {
						t.Errorf("Expected segments_left %d, got %d", expectedSL, newSL)
					}
				}
			}
		})
	}
}

// TestXDPProgNonSRv6 tests that non-SRv6 packets are passed through
func TestXDPProgNonSRv6(t *testing.T) {
	// Load BPF program
	objs, err := ReadCollection(nil, nil)
	if err != nil {
		t.Fatalf("Failed to load BPF objects: %v", err)
	}
	defer objs.Close()

	// Build simple IPv6 packet without SRH
	srcIP := net.ParseIP("fd00:1:1::1")
	dstIP := net.ParseIP("fd00:1:2::1")
	pkt, err := buildSimpleIPv6Packet(srcIP, dstIP)
	if err != nil {
		t.Fatalf("Failed to build simple IPv6 packet: %v", err)
	}

	// Run BPF program
	opts := ebpf.RunOptions{
		Data:    pkt,
		DataOut: make([]byte, len(pkt)+256),
		Repeat:  1,
	}

	ret, err := objs.VinberoMain.Run(&opts)
	if err != nil {
		t.Fatalf("Failed to run BPF program: %v", err)
	}

	if ret != XDP_PASS {
		t.Errorf("Expected XDP_PASS for non-SRv6 packet, got %d", ret)
	}
}

// TestXDPProgNoSIDEntry tests that packets without matching SID entry are passed
func TestXDPProgNoSIDEntry(t *testing.T) {
	// Load BPF program (without adding any SID entries)
	objs, err := ReadCollection(nil, nil)
	if err != nil {
		t.Fatalf("Failed to load BPF objects: %v", err)
	}
	defer objs.Close()

	// Build SRv6 packet with DA that doesn't match any SID entry
	srcIP := net.ParseIP("fd00:1:1::1")
	dstIP := net.ParseIP("fd00:9:9::9") // No SID entry for this
	segments := []net.IP{
		net.ParseIP("fd00:1:100::3"),
		net.ParseIP("fd00:9:9::9"),
	}

	pkt, err := buildSRv6Packet(srcIP, dstIP, segments, 1)
	if err != nil {
		t.Fatalf("Failed to build SRv6 packet: %v", err)
	}

	// Run BPF program
	opts := ebpf.RunOptions{
		Data:    pkt,
		DataOut: make([]byte, len(pkt)+256),
		Repeat:  1,
	}

	ret, err := objs.VinberoMain.Run(&opts)
	if err != nil {
		t.Fatalf("Failed to run BPF program: %v", err)
	}

	if ret != XDP_PASS {
		t.Errorf("Expected XDP_PASS for packet without SID entry, got %d", ret)
	}
}

// TestHeadendV4MapOperations tests CRUD operations on HeadendV4 map
func TestHeadendV4MapOperations(t *testing.T) {
	// Load BPF program
	objs, err := ReadCollection(nil, nil)
	if err != nil {
		t.Fatalf("Failed to load BPF objects: %v", err)
	}
	defer objs.Close()

	mapOps := NewMapOperations(objs)

	// Test data
	triggerPrefix := "192.0.2.0/24"
	srcAddr, _ := ParseIPv6("fc00::1")
	dstAddr, _ := ParseIPv6("fc00::100")
	segments, numSegments, _ := ParseSegments([]string{
		"fc00::200",
		"fc00::300",
	})

	entry := &HeadendEntry{
		Mode:        uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS),
		NumSegments: numSegments,
		SrcAddr:     srcAddr,
		DstAddr:     dstAddr,
		Segments:    segments,
	}

	// Test Create
	if err := mapOps.CreateHeadendV4(triggerPrefix, entry); err != nil {
		t.Fatalf("Failed to create headend v4 entry: %v", err)
	}

	// Test Get
	retrievedEntry, err := mapOps.GetHeadendV4(triggerPrefix)
	if err != nil {
		t.Fatalf("Failed to get headend v4 entry: %v", err)
	}

	if retrievedEntry.Mode != entry.Mode {
		t.Errorf("Expected mode %d, got %d", entry.Mode, retrievedEntry.Mode)
	}
	if retrievedEntry.NumSegments != entry.NumSegments {
		t.Errorf("Expected num_segments %d, got %d", entry.NumSegments, retrievedEntry.NumSegments)
	}
	if retrievedEntry.SrcAddr != entry.SrcAddr {
		t.Errorf("Expected src_addr %v, got %v", entry.SrcAddr, retrievedEntry.SrcAddr)
	}
	if retrievedEntry.DstAddr != entry.DstAddr {
		t.Errorf("Expected dst_addr %v, got %v", entry.DstAddr, retrievedEntry.DstAddr)
	}

	// Test List
	entries, err := mapOps.ListHeadendV4()
	if err != nil {
		t.Fatalf("Failed to list headend v4 entries: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("Expected 1 entry, got %d", len(entries))
	}
	if _, ok := entries[triggerPrefix]; !ok {
		t.Errorf("Expected to find entry with prefix %s", triggerPrefix)
	}

	// Test Delete
	if err := mapOps.DeleteHeadendV4(triggerPrefix); err != nil {
		t.Fatalf("Failed to delete headend v4 entry: %v", err)
	}

	// Verify deletion
	_, err = mapOps.GetHeadendV4(triggerPrefix)
	if err == nil {
		t.Error("Expected error when getting deleted entry, got nil")
	}
}

// TestHeadendV6MapOperations tests CRUD operations on HeadendV6 map
func TestHeadendV6MapOperations(t *testing.T) {
	// Load BPF program
	objs, err := ReadCollection(nil, nil)
	if err != nil {
		t.Fatalf("Failed to load BPF objects: %v", err)
	}
	defer objs.Close()

	mapOps := NewMapOperations(objs)

	// Test data
	triggerPrefix := "2001:db8::/32"
	srcAddr, _ := ParseIPv6("fc00::1")
	dstAddr, _ := ParseIPv6("fc00::100")
	segments, numSegments, _ := ParseSegments([]string{
		"fc00::200",
		"fc00::300",
		"fc00::400",
	})

	entry := &HeadendEntry{
		Mode:        uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS),
		NumSegments: numSegments,
		SrcAddr:     srcAddr,
		DstAddr:     dstAddr,
		Segments:    segments,
	}

	// Test Create
	if err := mapOps.CreateHeadendV6(triggerPrefix, entry); err != nil {
		t.Fatalf("Failed to create headend v6 entry: %v", err)
	}

	// Test Get
	retrievedEntry, err := mapOps.GetHeadendV6(triggerPrefix)
	if err != nil {
		t.Fatalf("Failed to get headend v6 entry: %v", err)
	}

	if retrievedEntry.Mode != entry.Mode {
		t.Errorf("Expected mode %d, got %d", entry.Mode, retrievedEntry.Mode)
	}
	if retrievedEntry.NumSegments != entry.NumSegments {
		t.Errorf("Expected num_segments %d, got %d", entry.NumSegments, retrievedEntry.NumSegments)
	}
	if retrievedEntry.SrcAddr != entry.SrcAddr {
		t.Errorf("Expected src_addr %v, got %v", entry.SrcAddr, retrievedEntry.SrcAddr)
	}
	if retrievedEntry.DstAddr != entry.DstAddr {
		t.Errorf("Expected dst_addr %v, got %v", entry.DstAddr, retrievedEntry.DstAddr)
	}

	// Test List
	entries, err := mapOps.ListHeadendV6()
	if err != nil {
		t.Fatalf("Failed to list headend v6 entries: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("Expected 1 entry, got %d", len(entries))
	}
	if _, ok := entries[triggerPrefix]; !ok {
		t.Errorf("Expected to find entry with prefix %s", triggerPrefix)
	}

	// Test Delete
	if err := mapOps.DeleteHeadendV6(triggerPrefix); err != nil {
		t.Fatalf("Failed to delete headend v6 entry: %v", err)
	}

	// Verify deletion
	_, err = mapOps.GetHeadendV6(triggerPrefix)
	if err == nil {
		t.Error("Expected error when getting deleted entry, got nil")
	}
}

// TestXDPProgHeadendV4Encaps tests H.Encaps operation for IPv4 packets
func TestXDPProgHeadendV4Encaps(t *testing.T) {
	// Load BPF program
	objs, err := ReadCollection(nil, nil)
	if err != nil {
		t.Fatalf("Failed to load BPF objects: %v", err)
	}
	defer objs.Close()

	mapOps := NewMapOperations(objs)

	tests := []struct {
		name           string
		triggerPrefix  string
		srcAddr        string
		dstAddr        string
		segmentStrs    []string
		pktSrcIP       string
		pktDstIP       string
		expectEncap    bool
		expectedAction uint32
	}{
		{
			name:           "Two segments encapsulation",
			triggerPrefix:  "192.0.2.0/24",
			srcAddr:        "fc00::1",
			dstAddr:        "fc00::100",
			segmentStrs:    []string{"fc00::200", "fc00::300"},
			pktSrcIP:       "10.0.0.1",
			pktDstIP:       "192.0.2.100",
			expectEncap:    true,
			expectedAction: XDP_PASS,
		},
		{
			name:           "Single segment encapsulation",
			triggerPrefix:  "198.51.100.0/24",
			srcAddr:        "fc00::10",
			dstAddr:        "fc00::200",
			segmentStrs:    []string{"fc00::200"},
			pktSrcIP:       "10.0.0.2",
			pktDstIP:       "198.51.100.50",
			expectEncap:    true,
			expectedAction: XDP_PASS,
		},
		{
			name:           "Three segments encapsulation",
			triggerPrefix:  "203.0.113.0/24",
			srcAddr:        "fc00::20",
			dstAddr:        "fc00::100",
			segmentStrs:    []string{"fc00::100", "fc00::200", "fc00::300"},
			pktSrcIP:       "10.0.0.3",
			pktDstIP:       "203.0.113.100",
			expectEncap:    true,
			expectedAction: XDP_PASS,
		},
		{
			name:           "Packet not matching trigger prefix",
			triggerPrefix:  "10.10.0.0/16",
			srcAddr:        "fc00::1",
			dstAddr:        "fc00::100",
			segmentStrs:    []string{"fc00::200"},
			pktSrcIP:       "10.0.0.1",
			pktDstIP:       "172.16.0.1",
			expectEncap:    false,
			expectedAction: XDP_PASS,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup entry for this test
			srcAddr, _ := ParseIPv6(tt.srcAddr)
			dstAddr, _ := ParseIPv6(tt.dstAddr)
			segments, numSegments, _ := ParseSegments(tt.segmentStrs)

			entry := &HeadendEntry{
				Mode:        uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS),
				NumSegments: numSegments,
				SrcAddr:     srcAddr,
				DstAddr:     dstAddr,
				Segments:    segments,
			}

			if err := mapOps.CreateHeadendV4(tt.triggerPrefix, entry); err != nil {
				t.Fatalf("Failed to create headend v4 entry: %v", err)
			}
			defer func() {
				_ = mapOps.DeleteHeadendV4(tt.triggerPrefix)
			}()

			// Build IPv4 packet
			pktSrcIP := net.ParseIP(tt.pktSrcIP).To4()
			pktDstIP := net.ParseIP(tt.pktDstIP).To4()

			pkt, err := buildSimpleIPv4Packet(pktSrcIP, pktDstIP)
			if err != nil {
				t.Fatalf("Failed to build IPv4 packet: %v", err)
			}

			originalLen := len(pkt)

			// Run BPF program
			opts := ebpf.RunOptions{
				Data:    pkt,
				DataOut: make([]byte, 1500),
				Repeat:  1,
			}

			ret, err := objs.VinberoMain.Run(&opts)
			if err != nil {
				t.Fatalf("Failed to run BPF program: %v", err)
			}

			if ret != tt.expectedAction {
				t.Errorf("Expected action %d, got %d", tt.expectedAction, ret)
			}

			if tt.expectEncap {
				outPkt := opts.DataOut

				// Calculate expected minimum length
				srhLen := srhBaseLen + int(numSegments)*ipv6AddrLen
				minExpectedLen := ethHeaderLen + ipv6HeaderLen + srhLen + ipv4HeaderLen

				if len(outPkt) < minExpectedLen {
					t.Fatalf("Output packet too short: got %d, want at least %d (original: %d)",
						len(outPkt), minExpectedLen, originalLen)
				}

				// Verify Ethernet header indicates IPv6
				if !verifyEthernetIPv6(t, outPkt) {
					return
				}

				// Verify outer IPv6 header
				// Note: RFC 8986 Section 5.1 - outer IPv6 DA is set to Segment List[0] (first segment)
				expectedDA := segments[0] // First segment becomes outer DA
				if !verifyOuterIPv6Header(t, outPkt, srcAddr, expectedDA) {
					return
				}

				// Verify SRH structure
				// Segments are stored in reverse order in SRH
				expectedSegs := convertSegmentsToBytes(segments, int(numSegments))
				if !verifySRHStructure(t, outPkt, int(numSegments), expectedSegs) {
					return
				}

				// Verify inner IPv4 packet is preserved
				if !verifyInnerIPv4Packet(t, outPkt, int(numSegments), pktSrcIP, pktDstIP) {
					return
				}

				t.Logf("SUCCESS: Encapsulation verified (original: %d bytes, encapsulated: %d bytes)",
					originalLen, len(outPkt))
			}
		})
	}
}

// TestXDPProgHeadendV6Encaps tests H.Encaps operation for IPv6 packets
func TestXDPProgHeadendV6Encaps(t *testing.T) {
	// Load BPF program
	objs, err := ReadCollection(nil, nil)
	if err != nil {
		t.Fatalf("Failed to load BPF objects: %v", err)
	}
	defer objs.Close()

	mapOps := NewMapOperations(objs)

	tests := []struct {
		name           string
		triggerPrefix  string
		srcAddr        string
		dstAddr        string
		segmentStrs    []string
		pktSrcIP       string
		pktDstIP       string
		expectEncap    bool
		expectedAction uint32
	}{
		{
			name:           "Three segments encapsulation",
			triggerPrefix:  "2001:db8::/32",
			srcAddr:        "fc00::1",
			dstAddr:        "fc00::100",
			segmentStrs:    []string{"fc00::200", "fc00::300", "fc00::400"},
			pktSrcIP:       "2001:db8:1::1",
			pktDstIP:       "2001:db8:2::1",
			expectEncap:    true,
			expectedAction: XDP_PASS,
		},
		{
			name:           "Single segment encapsulation",
			triggerPrefix:  "2001:db9::/32",
			srcAddr:        "fc00::10",
			dstAddr:        "fc00::200",
			segmentStrs:    []string{"fc00::200"},
			pktSrcIP:       "2001:db9:1::1",
			pktDstIP:       "2001:db9:2::1",
			expectEncap:    true,
			expectedAction: XDP_PASS,
		},
		{
			name:           "Two segments encapsulation",
			triggerPrefix:  "2001:dba::/32",
			srcAddr:        "fc00::20",
			dstAddr:        "fc00::100",
			segmentStrs:    []string{"fc00::100", "fc00::200"},
			pktSrcIP:       "2001:dba:1::1",
			pktDstIP:       "2001:dba:2::1",
			expectEncap:    true,
			expectedAction: XDP_PASS,
		},
		{
			name:           "Packet not matching trigger prefix",
			triggerPrefix:  "2001:dbb::/32",
			srcAddr:        "fc00::1",
			dstAddr:        "fc00::100",
			segmentStrs:    []string{"fc00::200"},
			pktSrcIP:       "fd00:1::1",
			pktDstIP:       "fd00:2::1",
			expectEncap:    false,
			expectedAction: XDP_PASS,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup entry for this test
			srcAddr, _ := ParseIPv6(tt.srcAddr)
			dstAddr, _ := ParseIPv6(tt.dstAddr)
			segments, numSegments, _ := ParseSegments(tt.segmentStrs)

			entry := &HeadendEntry{
				Mode:        uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS),
				NumSegments: numSegments,
				SrcAddr:     srcAddr,
				DstAddr:     dstAddr,
				Segments:    segments,
			}

			if err := mapOps.CreateHeadendV6(tt.triggerPrefix, entry); err != nil {
				t.Fatalf("Failed to create headend v6 entry: %v", err)
			}
			defer func() {
				_ = mapOps.DeleteHeadendV6(tt.triggerPrefix)
			}()

			// Build IPv6 packet
			pktSrcIP := net.ParseIP(tt.pktSrcIP)
			pktDstIP := net.ParseIP(tt.pktDstIP)

			pkt, err := buildSimpleIPv6Packet(pktSrcIP, pktDstIP)
			if err != nil {
				t.Fatalf("Failed to build IPv6 packet: %v", err)
			}

			originalLen := len(pkt)

			// Run BPF program
			opts := ebpf.RunOptions{
				Data:    pkt,
				DataOut: make([]byte, 1500),
				Repeat:  1,
			}

			ret, err := objs.VinberoMain.Run(&opts)
			if err != nil {
				t.Fatalf("Failed to run BPF program: %v", err)
			}

			if ret != tt.expectedAction {
				t.Errorf("Expected action %d, got %d", tt.expectedAction, ret)
			}

			if tt.expectEncap {
				outPkt := opts.DataOut

				// Calculate expected minimum length
				srhLen := srhBaseLen + int(numSegments)*ipv6AddrLen
				minExpectedLen := ethHeaderLen + ipv6HeaderLen + srhLen + ipv6HeaderLen

				if len(outPkt) < minExpectedLen {
					t.Fatalf("Output packet too short: got %d, want at least %d (original: %d)",
						len(outPkt), minExpectedLen, originalLen)
				}

				// Verify Ethernet header indicates IPv6
				if !verifyEthernetIPv6(t, outPkt) {
					return
				}

				// Verify outer IPv6 header
				// Note: RFC 8986 Section 5.1 - outer IPv6 DA is set to Segment List[0] (first segment)
				expectedDA := segments[0] // First segment becomes outer DA
				if !verifyOuterIPv6Header(t, outPkt, srcAddr, expectedDA) {
					return
				}

				// Verify SRH structure
				expectedSegs := convertSegmentsToBytes(segments, int(numSegments))
				if !verifySRHStructure(t, outPkt, int(numSegments), expectedSegs) {
					return
				}

				// Verify inner IPv6 packet is preserved
				if !verifyInnerIPv6Packet(t, outPkt, int(numSegments), pktSrcIP, pktDstIP) {
					return
				}

				t.Logf("SUCCESS: Encapsulation verified (original: %d bytes, encapsulated: %d bytes)",
					originalLen, len(outPkt))
			}
		})
	}
}
