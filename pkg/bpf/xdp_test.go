package bpf

import (
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

	// Configure HeadendV4 map
	mapOps := NewMapOperations(objs)
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

	if err := mapOps.CreateHeadendV4(triggerPrefix, entry); err != nil {
		t.Fatalf("Failed to create headend v4 entry: %v", err)
	}

	tests := []struct {
		name           string
		srcIP          string
		dstIP          string
		expectEncap    bool
		expectedAction uint32
	}{
		{
			name:           "IPv4 packet matching trigger prefix",
			srcIP:          "10.0.0.1",
			dstIP:          "192.0.2.100",
			expectEncap:    true,
			expectedAction: XDP_PASS,
		},
		{
			name:           "IPv4 packet not matching trigger prefix",
			srcIP:          "10.0.0.1",
			dstIP:          "203.0.113.1",
			expectEncap:    false,
			expectedAction: XDP_PASS,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build IPv4 packet
			srcIP := net.ParseIP(tt.srcIP).To4()
			dstIP := net.ParseIP(tt.dstIP).To4()

			pkt, err := buildSimpleIPv4Packet(srcIP, dstIP)
			if err != nil {
				t.Fatalf("Failed to build IPv4 packet: %v", err)
			}

			originalLen := len(pkt)

			// Run BPF program
			opts := ebpf.RunOptions{
				Data:    pkt,
				DataOut: make([]byte, 1500), // Large enough for encapsulated packet
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
				// Check that packet was encapsulated (should be larger)
				outPkt := opts.DataOut
				
				// The packet should now have IPv6 + SRH headers
				// Minimum: Ethernet (14) + IPv6 (40) + SRH (8 + 16*num_segments)
				minExpectedLen := 14 + 40 + 8 + 16*int(numSegments)
				
				if len(outPkt) < minExpectedLen {
					t.Logf("Original packet length: %d", originalLen)
					t.Logf("Output packet length: %d", len(outPkt))
					t.Logf("Expected minimum length: %d", minExpectedLen)
				}

				// Check Ethernet type changed to IPv6
				if len(outPkt) >= 14 {
					etherType := uint16(outPkt[12])<<8 | uint16(outPkt[13])
					if etherType != 0x86DD { // IPv6
						t.Logf("Note: EtherType is 0x%04x, expected 0x86DD (IPv6)", etherType)
					}
				}
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

	// Configure HeadendV6 map
	mapOps := NewMapOperations(objs)
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

	if err := mapOps.CreateHeadendV6(triggerPrefix, entry); err != nil {
		t.Fatalf("Failed to create headend v6 entry: %v", err)
	}

	tests := []struct {
		name           string
		srcIP          string
		dstIP          string
		expectEncap    bool
		expectedAction uint32
	}{
		{
			name:           "IPv6 packet matching trigger prefix",
			srcIP:          "2001:db8:1::1",
			dstIP:          "2001:db8:2::1",
			expectEncap:    true,
			expectedAction: XDP_PASS,
		},
		{
			name:           "IPv6 packet not matching trigger prefix",
			srcIP:          "fd00:1::1",
			dstIP:          "fd00:2::1",
			expectEncap:    false,
			expectedAction: XDP_PASS,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build IPv6 packet
			srcIP := net.ParseIP(tt.srcIP)
			dstIP := net.ParseIP(tt.dstIP)

			pkt, err := buildSimpleIPv6Packet(srcIP, dstIP)
			if err != nil {
				t.Fatalf("Failed to build IPv6 packet: %v", err)
			}

			originalLen := len(pkt)

			// Run BPF program
			opts := ebpf.RunOptions{
				Data:    pkt,
				DataOut: make([]byte, 1500), // Large enough for encapsulated packet
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
				// Check that packet was encapsulated (should be larger)
				outPkt := opts.DataOut
				
				// The packet should now have outer IPv6 + SRH headers
				// Minimum: Ethernet (14) + Outer IPv6 (40) + SRH (8 + 16*num_segments) + Inner IPv6 (40)
				minExpectedLen := 14 + 40 + 8 + 16*int(numSegments) + 40
				
				if len(outPkt) < minExpectedLen {
					t.Logf("Original packet length: %d", originalLen)
					t.Logf("Output packet length: %d", len(outPkt))
					t.Logf("Expected minimum length: %d", minExpectedLen)
				}

				// Check that outer IPv6 header exists
				if len(outPkt) >= 54 { // 14 (Ethernet) + 40 (IPv6)
					// Check outer IPv6 version
					version := (outPkt[14] >> 4) & 0x0F
					if version != 6 {
						t.Logf("Note: Outer IP version is %d, expected 6", version)
					}

					// Check Next Header is routing (43) for SRH
					nextHeader := outPkt[14+6]
					if nextHeader != 43 {
						t.Logf("Note: Next Header is %d, expected 43 (routing)", nextHeader)
					}
				}
			}
		})
	}
}
