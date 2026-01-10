package bpf

import (
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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

	icmp.SetNetworkLayerForChecksum(ip6)
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

	icmp.SetNetworkLayerForChecksum(ip6)
	if err := gopacket.SerializeLayers(buf, opts, eth, ip6, icmp, icmpEcho, gopacket.Payload(payload)); err != nil {
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

