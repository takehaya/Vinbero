package bpf

import (
	"net"
	"testing"

	vinberov1 "github.com/takehaya/vinbero/api/vinbero/v1"
)

func TestXDPProgEnd(t *testing.T) {
	h := newXDPTestHelper(t)
	h.createSidFunction("fd00:1:100::2/128", actionEnd)

	tests := []struct {
		name           string
		srcIP, dstIP   string
		segments       []string
		segmentsLeft   uint8
		expectedAction uint32
		checkDA        bool
		expectedDA     string
	}{
		{"End with SL=1", "fd00:1:1::1", "fd00:1:100::2", []string{"fd00:1:100::3", "fd00:1:100::2"}, 1, XDP_PASS, true, "fd00:1:100::3"},
		{"End with SL=0", "fd00:1:1::1", "fd00:1:100::2", []string{"fd00:1:100::3", "fd00:1:100::2"}, 0, XDP_PASS, false, ""},
		{"End with SL=2", "fd00:1:1::1", "fd00:1:100::2", []string{"fd00:1:100::4", "fd00:1:100::3", "fd00:1:100::2"}, 2, XDP_PASS, true, "fd00:1:100::3"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			segments := make([]net.IP, len(tt.segments))
			for i, s := range tt.segments {
				segments[i] = net.ParseIP(s)
			}
			pkt, err := buildSRv6Packet(net.ParseIP(tt.srcIP), net.ParseIP(tt.dstIP), segments, tt.segmentsLeft)
			if err != nil {
				t.Fatalf("Failed to build packet: %v", err)
			}

			ret, outPkt := h.run(pkt)
			if ret != tt.expectedAction {
				t.Errorf("Expected action %d, got %d", tt.expectedAction, ret)
			}

			if tt.checkDA && tt.segmentsLeft > 0 {
				da := net.IP(outPkt[38:54])
				if !da.Equal(net.ParseIP(tt.expectedDA)) {
					t.Errorf("Expected DA %s, got %s", tt.expectedDA, da)
				}
				if len(outPkt) > 57 {
					if newSL := outPkt[57]; newSL != tt.segmentsLeft-1 {
						t.Errorf("Expected segments_left %d, got %d", tt.segmentsLeft-1, newSL)
					}
				}
			}
		})
	}
}

func TestXDPProgNonSRv6(t *testing.T) {
	h := newXDPTestHelper(t)
	pkt, err := buildSimpleIPv6Packet(net.ParseIP("fd00:1:1::1"), net.ParseIP("fd00:1:2::1"))
	if err != nil {
		t.Fatalf("Failed to build packet: %v", err)
	}

	ret, _ := h.run(pkt)
	if ret != XDP_PASS {
		t.Errorf("Expected XDP_PASS for non-SRv6 packet, got %d", ret)
	}
}

func TestXDPProgNoSIDEntry(t *testing.T) {
	h := newXDPTestHelper(t)
	segments := []net.IP{net.ParseIP("fd00:1:100::3"), net.ParseIP("fd00:9:9::9")}
	pkt, err := buildSRv6Packet(net.ParseIP("fd00:1:1::1"), net.ParseIP("fd00:9:9::9"), segments, 1)
	if err != nil {
		t.Fatalf("Failed to build packet: %v", err)
	}

	ret, _ := h.run(pkt)
	if ret != XDP_PASS {
		t.Errorf("Expected XDP_PASS for packet without SID entry, got %d", ret)
	}
}

func TestHeadendMapOperations(t *testing.T) {
	testCases := []struct {
		name   string
		isIPv4 bool
		prefix string
	}{
		{"IPv4", true, "192.0.2.0/24"},
		{"IPv6", false, "2001:db8::/32"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := newXDPTestHelper(t)

			srcAddr, _ := ParseIPv6("fc00::1")
			dstAddr, _ := ParseIPv6("fc00::100")
			segments, numSegments, _ := ParseSegments([]string{"fc00::200", "fc00::300"})

			entry := &HeadendEntry{
				Mode:        uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS),
				NumSegments: numSegments,
				SrcAddr:     srcAddr,
				DstAddr:     dstAddr,
				Segments:    segments,
			}

			// Test Create
			var err error
			if tc.isIPv4 {
				err = h.mapOps.CreateHeadendV4(tc.prefix, entry)
			} else {
				err = h.mapOps.CreateHeadendV6(tc.prefix, entry)
			}
			if err != nil {
				t.Fatalf("Failed to create entry: %v", err)
			}

			// Test Get
			var retrieved *HeadendEntry
			if tc.isIPv4 {
				retrieved, err = h.mapOps.GetHeadendV4(tc.prefix)
			} else {
				retrieved, err = h.mapOps.GetHeadendV6(tc.prefix)
			}
			if err != nil {
				t.Fatalf("Failed to get entry: %v", err)
			}
			if retrieved.Mode != entry.Mode || retrieved.NumSegments != entry.NumSegments {
				t.Errorf("Entry mismatch: mode %d/%d, numSegments %d/%d",
					entry.Mode, retrieved.Mode, entry.NumSegments, retrieved.NumSegments)
			}

			// Test List
			var entries map[string]*HeadendEntry
			if tc.isIPv4 {
				entries, err = h.mapOps.ListHeadendV4()
			} else {
				entries, err = h.mapOps.ListHeadendV6()
			}
			if err != nil {
				t.Fatalf("Failed to list entries: %v", err)
			}
			if len(entries) != 1 {
				t.Errorf("Expected 1 entry, got %d", len(entries))
			}

			// Test Delete
			if tc.isIPv4 {
				err = h.mapOps.DeleteHeadendV4(tc.prefix)
			} else {
				err = h.mapOps.DeleteHeadendV6(tc.prefix)
			}
			if err != nil {
				t.Fatalf("Failed to delete entry: %v", err)
			}

			// Verify deletion
			if tc.isIPv4 {
				_, err = h.mapOps.GetHeadendV4(tc.prefix)
			} else {
				_, err = h.mapOps.GetHeadendV6(tc.prefix)
			}
			if err == nil {
				t.Error("Expected error when getting deleted entry")
			}
		})
	}
}

func TestXDPProgHeadendEncaps(t *testing.T) {
	tests := []struct {
		name          string
		isIPv4        bool
		triggerPrefix string
		srcAddr       string
		dstAddr       string
		segmentStrs   []string
		pktSrcIP      string
		pktDstIP      string
		expectEncap   bool
	}{
		// IPv4 tests
		{"IPv4 two segments", true, "192.0.2.0/24", "fc00::1", "fc00::100", []string{"fc00::200", "fc00::300"}, "10.0.0.1", "192.0.2.100", true},
		{"IPv4 single segment", true, "198.51.100.0/24", "fc00::10", "fc00::200", []string{"fc00::200"}, "10.0.0.2", "198.51.100.50", true},
		{"IPv4 three segments", true, "203.0.113.0/24", "fc00::20", "fc00::100", []string{"fc00::100", "fc00::200", "fc00::300"}, "10.0.0.3", "203.0.113.100", true},
		{"IPv4 no match", true, "10.10.0.0/16", "fc00::1", "fc00::100", []string{"fc00::200"}, "10.0.0.1", "172.16.0.1", false},
		// IPv6 tests
		{"IPv6 three segments", false, "2001:db8::/32", "fc00::1", "fc00::100", []string{"fc00::200", "fc00::300", "fc00::400"}, "2001:db8:1::1", "2001:db8:2::1", true},
		{"IPv6 single segment", false, "2001:db9::/32", "fc00::10", "fc00::200", []string{"fc00::200"}, "2001:db9:1::1", "2001:db9:2::1", true},
		{"IPv6 two segments", false, "2001:dba::/32", "fc00::20", "fc00::100", []string{"fc00::100", "fc00::200"}, "2001:dba:1::1", "2001:dba:2::1", true},
		{"IPv6 no match", false, "2001:dbb::/32", "fc00::1", "fc00::100", []string{"fc00::200"}, "fd00:1::1", "fd00:2::1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newXDPTestHelper(t)

			srcAddr, _ := ParseIPv6(tt.srcAddr)
			dstAddr, _ := ParseIPv6(tt.dstAddr)
			segments, numSegments, _ := ParseSegments(tt.segmentStrs)
			h.createHeadendEntry(tt.triggerPrefix, srcAddr, dstAddr, segments, numSegments, tt.isIPv4)

			var pkt []byte
			var err error
			var pktSrcIP, pktDstIP net.IP

			if tt.isIPv4 {
				pktSrcIP = net.ParseIP(tt.pktSrcIP).To4()
				pktDstIP = net.ParseIP(tt.pktDstIP).To4()
				pkt, err = buildSimpleIPv4Packet(pktSrcIP, pktDstIP)
			} else {
				pktSrcIP = net.ParseIP(tt.pktSrcIP)
				pktDstIP = net.ParseIP(tt.pktDstIP)
				pkt, err = buildSimpleIPv6Packet(pktSrcIP, pktDstIP)
			}
			if err != nil {
				t.Fatalf("Failed to build packet: %v", err)
			}

			originalLen := len(pkt)
			ret, outPkt := h.run(pkt)

			if ret != XDP_PASS {
				t.Errorf("Expected XDP_PASS, got %d", ret)
			}

			if tt.expectEncap {
				innerHeaderLen := ipv4HeaderLen
				if !tt.isIPv4 {
					innerHeaderLen = ipv6HeaderLen
				}
				srhLen := srhBaseLen + int(numSegments)*ipv6AddrLen
				minExpectedLen := ethHeaderLen + ipv6HeaderLen + srhLen + innerHeaderLen

				if len(outPkt) < minExpectedLen {
					t.Fatalf("Output packet too short: got %d, want at least %d", len(outPkt), minExpectedLen)
				}

				if !verifyEtherType(t, outPkt, 0x86DD) {
					return
				}
				if !verifyOuterIPv6Header(t, outPkt, srcAddr, segments[0]) {
					return
				}
				if !verifySRHStructure(t, outPkt, int(numSegments), convertSegmentsToBytes(segments, int(numSegments))) {
					return
				}
				if !verifyInnerPacket(t, outPkt, int(numSegments), pktSrcIP, pktDstIP, tt.isIPv4) {
					return
				}

				t.Logf("SUCCESS: Encapsulation verified (original: %d, encapsulated: %d)", originalLen, len(outPkt))
			}
		})
	}
}

func TestXDPProgEndDX(t *testing.T) {
	tests := []struct {
		name         string
		action       uint8
		isIPv4       bool
		triggerSID   string
		outerSrcIP   string
		outerDstIP   string
		segments     []string
		segmentsLeft uint8
		innerSrcIP   string
		innerDstIP   string
		expectDecap  bool
	}{
		// End.DX4 tests
		{"End.DX4 SL=0 (decap)", actionEndDX4, true, "fd00:1:100::10/128", "fd00:1:1::1", "fd00:1:100::10", []string{"fd00:1:100::10"}, 0, "10.0.0.1", "192.0.2.100", true},
		{"End.DX4 SL!=0 (pass)", actionEndDX4, true, "fd00:1:100::10/128", "fd00:1:1::1", "fd00:1:100::10", []string{"fd00:1:100::20", "fd00:1:100::10"}, 1, "10.0.0.1", "192.0.2.100", false},
		// End.DX6 tests
		{"End.DX6 SL=0 (decap)", actionEndDX6, false, "fd00:1:100::20/128", "fd00:1:1::1", "fd00:1:100::20", []string{"fd00:1:100::20"}, 0, "2001:db8:1::1", "2001:db8:2::1", true},
		{"End.DX6 SL!=0 (pass)", actionEndDX6, false, "fd00:1:100::20/128", "fd00:1:1::1", "fd00:1:100::20", []string{"fd00:1:100::30", "fd00:1:100::20"}, 1, "2001:db8:1::1", "2001:db8:2::1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newXDPTestHelper(t)
			h.createSidFunction(tt.triggerSID, tt.action)

			segments := make([]net.IP, len(tt.segments))
			for i, s := range tt.segments {
				segments[i] = net.ParseIP(s)
			}

			innerType := innerTypeIPv6
			if tt.isIPv4 {
				innerType = innerTypeIPv4
			}

			pkt, err := buildEncapsulatedPacket(
				net.ParseIP(tt.outerSrcIP), net.ParseIP(tt.outerDstIP),
				segments, tt.segmentsLeft,
				net.ParseIP(tt.innerSrcIP), net.ParseIP(tt.innerDstIP),
				innerType,
			)
			if err != nil {
				t.Fatalf("Failed to build packet: %v", err)
			}

			originalLen := len(pkt)
			ret, outPkt := h.run(pkt)

			if tt.expectDecap {
				// After decap: XDP_REDIRECT (FIB success) or XDP_DROP (FIB fail)
				if ret != XDP_REDIRECT && ret != XDP_DROP {
					t.Errorf("Expected XDP_REDIRECT or XDP_DROP after decap, got %d", ret)
				}
				if !verifyDecapsulated(t, outPkt, net.ParseIP(tt.innerSrcIP), net.ParseIP(tt.innerDstIP), tt.isIPv4) {
					return
				}
				t.Logf("SUCCESS: Decapsulation verified (original: %d, decapsulated: %d, action: %d)", originalLen, len(outPkt), ret)
			} else {
				if ret != XDP_PASS {
					t.Errorf("Expected XDP_PASS, got %d", ret)
				}
			}
		})
	}
}
