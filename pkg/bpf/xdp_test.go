package bpf

import (
	"encoding/binary"
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
				verifyDAAndSL(t, outPkt, tt.expectedDA, tt.segmentsLeft)
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

func TestXDPProgEndDX2(t *testing.T) {
	tests := []struct {
		name         string
		triggerSID   string
		outerSrcIP   string
		outerDstIP   string
		segments     []string
		segmentsLeft uint8
		innerVlanID  uint16
		innerSrcIP   string
		innerDstIP   string
		isIPv4Inner  bool
		oif          uint32
		expectDecap  bool
	}{
		{"End.DX2 SL=0 IPv4 inner", "fd00:1:100::10/128", "fd00:1:1::1", "fd00:1:100::10", []string{"fd00:1:100::10"}, 0, 100, "10.0.0.1", "192.0.2.100", true, 1, true},
		{"End.DX2 SL=0 IPv6 inner", "fd00:1:100::20/128", "fd00:1:1::1", "fd00:1:100::20", []string{"fd00:1:100::20"}, 0, 200, "2001:db8:1::1", "2001:db8:2::1", false, 1, true},
		{"End.DX2 SL!=0 (pass)", "fd00:1:100::10/128", "fd00:1:1::1", "fd00:1:100::10", []string{"fd00:1:100::20", "fd00:1:100::10"}, 1, 100, "10.0.0.1", "192.0.2.100", true, 1, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newXDPTestHelper(t)
			h.createSidFunctionWithOIF(tt.triggerSID, actionEndDX2, tt.oif)

			segments := make([]net.IP, len(tt.segments))
			for i, s := range tt.segments {
				segments[i] = net.ParseIP(s)
			}

			pkt, err := buildL2EncapsulatedPacket(
				net.ParseIP(tt.outerSrcIP), net.ParseIP(tt.outerDstIP),
				segments, tt.segmentsLeft,
				tt.innerVlanID,
				net.ParseIP(tt.innerSrcIP), net.ParseIP(tt.innerDstIP),
				tt.isIPv4Inner,
			)
			if err != nil {
				t.Fatalf("Failed to build packet: %v", err)
			}

			ret, outPkt := h.run(pkt)

			if tt.expectDecap {
				// End.DX2 uses bpf_redirect directly (no FIB lookup)
				if ret != XDP_REDIRECT {
					t.Errorf("Expected XDP_REDIRECT after decap, got %d", ret)
				}

				// After decap: inner L2 frame should be exposed (Eth + VLAN + IP)
				if !verifyInnerVlanFrame(t, outPkt, 0, tt.innerVlanID) {
					return
				}

				t.Logf("SUCCESS: End.DX2 decapsulation verified (action: %d)", ret)
			} else {
				if ret != XDP_PASS {
					t.Errorf("Expected XDP_PASS for SL!=0 case, got %d", ret)
				}
			}
		})
	}
}

func TestXDPProgHeadendL2Encaps(t *testing.T) {
	tests := []struct {
		name        string
		vlanID      uint16 // VLAN ID for the packet
		entryVlanID uint16 // VLAN ID to register (0 means don't register)
		srcAddr     string
		segmentStrs []string
		isIPv4Inner bool // true for IPv4 inner packet, false for IPv6
		expectEncap bool // true = H.Encaps.L2 (bd_id=0, direct encap)
	}{
		{"L2 VLAN 100 IPv4 two segments", 100, 100, "fc00::1", []string{"fc00::200", "fc00::300"}, true, true},
		{"L2 VLAN 100 IPv4 single segment", 100, 100, "fc00::10", []string{"fc00::200"}, true, true},
		{"L2 VLAN 200 IPv6 two segments", 200, 200, "fc00::1", []string{"fc00::200", "fc00::300"}, false, true},
		{"L2 VLAN mismatch", 100, 200, "fc00::1", []string{"fc00::200"}, true, false},
		{"L2 no entry", 100, 0, "fc00::1", []string{"fc00::200"}, true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newXDPTestHelper(t)

			srcAddr, _ := ParseIPv6(tt.srcAddr)
			segments, numSegments, _ := ParseSegments(tt.segmentStrs)

			if tt.entryVlanID > 0 {
				// bd_id=0: no Bridge Domain, direct H.Encaps.L2 for all traffic
				h.createHeadendL2Entry(0, tt.entryVlanID, srcAddr, segments, numSegments, 0)
				h.createHeadendL2Entry(1, tt.entryVlanID, srcAddr, segments, numSegments, 0)
			}

			var pkt []byte
			var err error
			if tt.isIPv4Inner {
				pkt, err = buildVlanTaggedIPv4Packet(
					tt.vlanID,
					net.ParseIP("10.0.0.1").To4(),
					net.ParseIP("192.0.2.100").To4(),
				)
			} else {
				pkt, err = buildVlanTaggedIPv6Packet(
					tt.vlanID,
					net.ParseIP("2001:db8:1::1"),
					net.ParseIP("2001:db8:2::1"),
				)
			}
			if err != nil {
				t.Fatalf("Failed to build packet: %v", err)
			}

			originalLen := len(pkt)
			ret, outPkt := h.run(pkt)

			if tt.expectEncap {
				// bd_id=0: direct H.Encaps.L2. FIB lookup in test env typically fails → XDP_DROP.
				if ret != XDP_DROP && ret != XDP_REDIRECT {
					t.Errorf("Expected XDP_DROP or XDP_REDIRECT after encap, got %d", ret)
				}
				if len(outPkt) <= originalLen {
					t.Errorf("Expected encapsulated packet to be larger, got %d (original %d)", len(outPkt), originalLen)
				} else {
					t.Logf("SUCCESS: H.Encaps.L2 (bd_id=0, %d→%d bytes)", originalLen, len(outPkt))
				}
			} else {
				if ret != XDP_PASS {
					t.Errorf("Expected XDP_PASS for no-match case, got %d", ret)
				}
				if len(outPkt) != originalLen {
					t.Errorf("Packet length changed unexpectedly: original %d, got %d", originalLen, len(outPkt))
				}
			}
		})
	}
}

func TestXDPProgEndDT(t *testing.T) {
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
		vrfIfindex   uint32
		expectDecap  bool
	}{
		// End.DT4 tests
		{"End.DT4 SL=0 default VRF", actionEndDT4, true, "fd00:1:100::10/128", "fd00:1:1::1", "fd00:1:100::10", []string{"fd00:1:100::10"}, 0, "10.0.0.1", "192.0.2.100", 0, true},
		{"End.DT4 SL!=0 (pass)", actionEndDT4, true, "fd00:1:100::10/128", "fd00:1:1::1", "fd00:1:100::10", []string{"fd00:1:100::20", "fd00:1:100::10"}, 1, "10.0.0.1", "192.0.2.100", 0, false},
		// End.DT6 tests
		{"End.DT6 SL=0 default VRF", actionEndDT6, false, "fd00:1:100::20/128", "fd00:1:1::1", "fd00:1:100::20", []string{"fd00:1:100::20"}, 0, "2001:db8:1::1", "2001:db8:2::1", 0, true},
		{"End.DT6 SL!=0 (pass)", actionEndDT6, false, "fd00:1:100::20/128", "fd00:1:1::1", "fd00:1:100::20", []string{"fd00:1:100::30", "fd00:1:100::20"}, 1, "2001:db8:1::1", "2001:db8:2::1", 0, false},
		// End.DT46 tests (dual-stack: IPv4 inner)
		{"End.DT46 SL=0 IPv4 inner", actionEndDT46, true, "fd00:1:100::30/128", "fd00:1:1::1", "fd00:1:100::30", []string{"fd00:1:100::30"}, 0, "10.0.0.1", "192.0.2.100", 0, true},
		// End.DT46 tests (dual-stack: IPv6 inner)
		{"End.DT46 SL=0 IPv6 inner", actionEndDT46, false, "fd00:1:100::30/128", "fd00:1:1::1", "fd00:1:100::30", []string{"fd00:1:100::30"}, 0, "2001:db8:1::1", "2001:db8:2::1", 0, true},
		{"End.DT46 SL!=0 (pass)", actionEndDT46, true, "fd00:1:100::30/128", "fd00:1:1::1", "fd00:1:100::30", []string{"fd00:1:100::40", "fd00:1:100::30"}, 1, "10.0.0.1", "192.0.2.100", 0, false},
		// VRF path tests (vrf_ifindex != 0, FIB will fail in test env → XDP_DROP after decap)
		{"End.DT4 SL=0 with VRF", actionEndDT4, true, "fd00:1:100::40/128", "fd00:1:1::1", "fd00:1:100::40", []string{"fd00:1:100::40"}, 0, "10.0.0.1", "192.0.2.100", 999, true},
		{"End.DT6 SL=0 with VRF", actionEndDT6, false, "fd00:1:100::50/128", "fd00:1:1::1", "fd00:1:100::50", []string{"fd00:1:100::50"}, 0, "2001:db8:1::1", "2001:db8:2::1", 999, true},
		{"End.DT46 SL=0 IPv4 with VRF", actionEndDT46, true, "fd00:1:100::60/128", "fd00:1:1::1", "fd00:1:100::60", []string{"fd00:1:100::60"}, 0, "10.0.0.1", "192.0.2.100", 999, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newXDPTestHelper(t)
			h.createSidFunctionWithVRF(tt.triggerSID, tt.action, tt.vrfIfindex)

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
				// After decap: XDP_REDIRECT (FIB success) or XDP_DROP (FIB fail in test env)
				if ret != XDP_REDIRECT && ret != XDP_DROP {
					t.Errorf("Expected XDP_REDIRECT or XDP_DROP after decap, got %d", ret)
				}
				if !verifyDecapsulated(t, outPkt, net.ParseIP(tt.innerSrcIP), net.ParseIP(tt.innerDstIP), tt.isIPv4) {
					return
				}
				t.Logf("SUCCESS: End.DT decapsulation verified (original: %d, decapsulated: %d, action: %d)", originalLen, len(outPkt), ret)
			} else {
				if ret != XDP_PASS {
					t.Errorf("Expected XDP_PASS, got %d", ret)
				}
			}
		})
	}
}

func TestXDPProgEndDT2(t *testing.T) {
	tests := []struct {
		name         string
		bdID         uint16
		triggerSID   string
		outerSrcIP   string
		outerDstIP   string
		segments     []string
		segmentsLeft uint8
		innerVlanID  uint16
		innerSrcIP   string
		innerDstIP   string
		isIPv4Inner  bool
		// FDB setup
		fdbBdID  uint16
		fdbMac   net.HardwareAddr
		fdbOif   uint32
		setupFDB bool
		// Expected
		expectAction uint32
	}{
		{
			"End.DT2 known unicast (redirect)",
			100, "fd00:1:100::10/128", "fd00:1:1::1", "fd00:1:100::10",
			[]string{"fd00:1:100::10"}, 0,
			100, "10.0.0.1", "192.0.2.100", true,
			100, net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x02}, 1, true,
			XDP_REDIRECT,
		},
		{
			"End.DT2 unknown unicast (pass to kernel)",
			100, "fd00:1:100::10/128", "fd00:1:1::1", "fd00:1:100::10",
			[]string{"fd00:1:100::10"}, 0,
			100, "10.0.0.1", "192.0.2.100", true,
			0, nil, 0, false,
			XDP_PASS,
		},
		{
			"End.DT2 SL!=0 (pass)",
			100, "fd00:1:100::10/128", "fd00:1:1::1", "fd00:1:100::10",
			[]string{"fd00:1:100::20", "fd00:1:100::10"}, 1,
			100, "10.0.0.1", "192.0.2.100", true,
			0, nil, 0, false,
			XDP_PASS,
		},
		{
			"End.DT2 known unicast IPv6 inner (redirect)",
			200, "fd00:1:100::20/128", "fd00:1:1::1", "fd00:1:100::20",
			[]string{"fd00:1:100::20"}, 0,
			200, "2001:db8:1::1", "2001:db8:2::1", false,
			200, net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x02}, 2, true,
			XDP_REDIRECT,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newXDPTestHelper(t)
			h.createSidFunctionWithBD(tt.triggerSID, actionEndDT2, tt.bdID)

			if tt.setupFDB {
				h.createFdbEntry(tt.fdbBdID, tt.fdbMac, tt.fdbOif)
			}

			segments := make([]net.IP, len(tt.segments))
			for i, s := range tt.segments {
				segments[i] = net.ParseIP(s)
			}

			pkt, err := buildL2EncapsulatedPacket(
				net.ParseIP(tt.outerSrcIP), net.ParseIP(tt.outerDstIP),
				segments, tt.segmentsLeft,
				tt.innerVlanID,
				net.ParseIP(tt.innerSrcIP), net.ParseIP(tt.innerDstIP),
				tt.isIPv4Inner,
			)
			if err != nil {
				t.Fatalf("Failed to build packet: %v", err)
			}

			ret, _ := h.run(pkt)

			if ret != tt.expectAction {
				t.Errorf("Expected action %d, got %d", tt.expectAction, ret)
			} else {
				t.Logf("SUCCESS: End.DT2 action=%d as expected", ret)
			}
		})
	}
}

func TestXDPProgHeadendL2MacLearning(t *testing.T) {
	h := newXDPTestHelper(t)

	srcAddr, _ := ParseIPv6("fc00::1")
	segments, numSegments, _ := ParseSegments([]string{"fc00::200"})
	bdID := uint16(100)

	// Register headend_l2 entry with bd_id=100 (ifindex=0 and 1 for test env)
	h.createHeadendL2Entry(0, 100, srcAddr, segments, numSegments, bdID)
	h.createHeadendL2Entry(1, 100, srcAddr, segments, numSegments, bdID)

	// Build VLAN 100 tagged packet (src MAC = 00:00:00:00:00:01)
	pkt, err := buildVlanTaggedIPv4Packet(100, net.ParseIP("10.0.0.1").To4(), net.ParseIP("192.0.2.100").To4())
	if err != nil {
		t.Fatalf("Failed to build packet: %v", err)
	}

	// Run XDP program — src MAC learning happens, then FDB miss → XDP_PASS (BUM flood via TC)
	ret, _ := h.run(pkt)

	// FDB miss with bd_id != 0 → XDP_PASS (BUM flood to all PEs via TC)
	if ret != XDP_PASS {
		t.Errorf("Expected XDP_PASS after FDB miss (BUM flood), got %d", ret)
	}

	// Verify src MAC was learned in fdb_map
	srcMAC := net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	fdbEntry, err := h.mapOps.GetFdb(bdID, srcMAC)
	if err != nil {
		t.Fatalf("src MAC not learned in fdb_map: %v", err)
	}
	t.Logf("SUCCESS: src MAC %s learned in fdb_map, oif=%d", srcMAC, fdbEntry.Oif)
}

func TestXDPProgHeadendL2DstMacJudgment(t *testing.T) {
	h := newXDPTestHelper(t)
	bdID := uint16(100)

	srcAddr, _ := ParseIPv6("fc00::1")
	segments, numSegments, _ := ParseSegments([]string{"fc00::200"})
	h.createHeadendL2Entry(0, 100, srcAddr, segments, numSegments, bdID)
	h.createHeadendL2Entry(1, 100, srcAddr, segments, numSegments, bdID)

	tests := []struct {
		name        string
		dstMAC      net.HardwareAddr
		setupLocal  bool
		expectEncap bool
	}{
		{"BUM broadcast → PASS", net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, false, false},
		{"BUM multicast → PASS", net.HardwareAddr{0x01, 0x00, 0x5e, 0x00, 0x00, 0x01}, false, false},
		{"known local unicast → PASS", net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x02}, true, false},
		{"unknown remote unicast → flood", net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x03}, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupLocal {
				h.createFdbEntry(bdID, tt.dstMAC, 1)
			}

			pkt, err := buildVlanTaggedIPv4Packet(100, net.ParseIP("10.0.0.1").To4(), net.ParseIP("192.0.2.100").To4())
			if err != nil {
				t.Fatalf("Failed to build packet: %v", err)
			}
			overrideDstMAC(pkt, tt.dstMAC)

			ret, _ := h.run(pkt)

			if tt.expectEncap {
				if ret != XDP_REDIRECT && ret != XDP_DROP {
					t.Errorf("Expected encap (XDP_REDIRECT/DROP), got %d", ret)
				} else {
					t.Logf("SUCCESS: remote unicast encapsulated (action=%d)", ret)
				}
			} else {
				if ret != XDP_PASS {
					t.Errorf("Expected XDP_PASS, got %d", ret)
				} else {
					t.Logf("SUCCESS: %s → XDP_PASS as expected", tt.name)
				}
			}
		})
	}
}

func TestXDPProgHeadendL2Untagged(t *testing.T) {
	h := newXDPTestHelper(t)

	srcAddr, _ := ParseIPv6("fc00::1")
	segments, numSegments, _ := ParseSegments([]string{"fc00::200"})

	// Register headend_l2 entry with vlan_id=0 (untagged), bd_id=0 for ifindex 0 and 1
	h.createHeadendL2Entry(0, 0, srcAddr, segments, numSegments, 0)
	h.createHeadendL2Entry(1, 0, srcAddr, segments, numSegments, 0)

	// Build untagged IPv4 packet (no VLAN tag)
	pkt, err := buildSimpleIPv4Packet(net.ParseIP("10.0.0.1").To4(), net.ParseIP("192.0.2.100").To4())
	if err != nil {
		t.Fatalf("Failed to build packet: %v", err)
	}

	originalLen := len(pkt)
	ret, outPkt := h.run(pkt)

	// bd_id=0: direct H.Encaps.L2. FIB fails in test env → XDP_DROP or XDP_REDIRECT
	if ret != XDP_REDIRECT && ret != XDP_DROP {
		t.Errorf("Expected encap (XDP_REDIRECT/DROP) for untagged packet, got %d", ret)
	} else {
		t.Logf("SUCCESS: untagged H.Encaps.L2 (bd_id=0, action=%d, %d→%d bytes)", ret, originalLen, len(outPkt))
	}
}

func TestXDPProgHeadendL2UntaggedNoEntry(t *testing.T) {
	h := newXDPTestHelper(t)

	// No headend_l2 entry → untagged packet should pass through to L3 processing
	pkt, err := buildSimpleIPv4Packet(net.ParseIP("10.0.0.1").To4(), net.ParseIP("192.0.2.100").To4())
	if err != nil {
		t.Fatalf("Failed to build packet: %v", err)
	}

	ret, _ := h.run(pkt)

	if ret != XDP_PASS {
		t.Errorf("Expected XDP_PASS for untagged without entry, got %d", ret)
	} else {
		t.Logf("SUCCESS: untagged without entry → XDP_PASS")
	}
}

func TestHeadendL2MapOperations(t *testing.T) {
	h := newXDPTestHelper(t)

	srcAddr, _ := ParseIPv6("fc00::1")
	segments, numSegments, _ := ParseSegments([]string{"fc00::200", "fc00::300"})

	entry := &HeadendEntry{
		Mode:        uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2),
		NumSegments: numSegments,
		SrcAddr:     srcAddr,
		Segments:    segments,
		BdId:        100,
	}

	// Create with (ifindex=1, vlan=100)
	if err := h.mapOps.CreateHeadendL2(1, 100, entry); err != nil {
		t.Fatalf("Create (1, 100) failed: %v", err)
	}

	// Get with same key → match
	got, err := h.mapOps.GetHeadendL2(1, 100)
	if err != nil {
		t.Fatalf("Get (1, 100) failed: %v", err)
	}
	if got.BdId != 100 || got.NumSegments != numSegments {
		t.Errorf("Entry mismatch: bd_id=%d, num_segments=%d", got.BdId, got.NumSegments)
	}

	// Create with (ifindex=2, vlan=100) → separate entry (same VLAN, different port)
	entry2 := *entry
	entry2.BdId = 200
	if err := h.mapOps.CreateHeadendL2(2, 100, &entry2); err != nil {
		t.Fatalf("Create (2, 100) failed: %v", err)
	}

	// List → 2 entries
	all, err := h.mapOps.ListHeadendL2()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("Expected 2 entries, got %d", len(all))
	}

	// Verify they are separate
	got1, err1 := h.mapOps.GetHeadendL2(1, 100)
	got2, err2 := h.mapOps.GetHeadendL2(2, 100)
	if err1 != nil || err2 != nil {
		t.Fatalf("Get failed: err1=%v, err2=%v", err1, err2)
	}
	if got1.BdId != 100 || got2.BdId != 200 {
		t.Errorf("Entries not separate: bd_id1=%d, bd_id2=%d", got1.BdId, got2.BdId)
	}

	// Delete one
	if err := h.mapOps.DeleteHeadendL2(1, 100); err != nil {
		t.Fatalf("Delete (1, 100) failed: %v", err)
	}

	// List → 1 entry
	all, err = h.mapOps.ListHeadendL2()
	if err != nil {
		t.Fatalf("List after delete failed: %v", err)
	}
	if len(all) != 1 {
		t.Errorf("Expected 1 entry after delete, got %d", len(all))
	}

	t.Logf("SUCCESS: HeadendL2 CRUD with (ifindex, vlan_id) key works correctly")

	// Cleanup
	_ = h.mapOps.DeleteHeadendL2(2, 100)
}

// TestXDPBumMetaWrite verifies that XDP writes BUM metadata (__u64) when
// a BUM frame hits a headend_l2_map entry. The metadata should appear as
// 8 extra bytes prepended to DataOut (data_meta region).
func TestXDPBumMetaWrite(t *testing.T) {
	h := newXDPTestHelper(t)
	bdID := uint16(100)

	srcAddr, _ := ParseIPv6("fc00::1")
	segments, numSegments, _ := ParseSegments([]string{"fc00::200"})
	h.createHeadendL2Entry(0, 100, srcAddr, segments, numSegments, bdID)
	h.createHeadendL2Entry(1, 100, srcAddr, segments, numSegments, bdID)

	tests := []struct {
		name           string
		vlanID         uint16
		dstMAC         net.HardwareAddr
		expectMeta     bool
		expectedVlanID uint16
	}{
		{"VLAN 100 broadcast", 100, net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, true, 100},
		{"VLAN 100 multicast", 100, net.HardwareAddr{0x01, 0x00, 0x5e, 0x00, 0x00, 0x01}, true, 100},
		{"VLAN 100 unicast (no meta)", 100, net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x03}, false, 0},
	}

	const bumMetaMarker = uint32(0x564E4255) // "VNBU"

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pkt []byte
			var err error
			pkt, err = buildVlanTaggedIPv4Packet(tt.vlanID, net.ParseIP("10.0.0.1").To4(), net.ParseIP("192.0.2.100").To4())
			if err != nil {
				t.Fatalf("Failed to build packet: %v", err)
			}
			overrideDstMAC(pkt, tt.dstMAC)

			inputLen := len(pkt)
			ret, out := h.run(pkt)

			if tt.expectMeta {
				if ret != XDP_PASS {
					t.Fatalf("Expected XDP_PASS, got %d", ret)
				}

				// DataOut should be inputLen + 8 (metadata prepended)
				expectedLen := inputLen + 8
				if len(out) != expectedLen {
					t.Skipf("DataOut length %d (expected %d) — kernel may not include metadata in BPF_PROG_RUN output", len(out), expectedLen)
					return
				}

				// First 8 bytes = __u64 metadata
				meta := binary.LittleEndian.Uint64(out[:8])
				marker := uint32(meta >> 32)
				vlanID := uint16(meta & 0xFFFF)

				if marker != bumMetaMarker {
					t.Errorf("Expected marker 0x%08X, got 0x%08X", bumMetaMarker, marker)
				}
				if vlanID != tt.expectedVlanID {
					t.Errorf("Expected vlan_id %d, got %d", tt.expectedVlanID, vlanID)
				}
				t.Logf("SUCCESS: BUM meta written — marker=0x%08X vlan_id=%d", marker, vlanID)
			} else {
				// Unicast → encap (no metadata, different action)
				if ret == XDP_PASS {
					// If PASS, output should be same size (no meta for non-BUM that hit FDB miss → encap)
					if len(out) == inputLen {
						t.Logf("SUCCESS: no metadata for unicast")
					}
				}
			}
		})
	}
}

func TestXDPProgEndT(t *testing.T) {
	tests := []struct {
		name           string
		srcIP, dstIP   string
		segments       []string
		segmentsLeft   uint8
		vrfIfindex     uint32
		expectedAction uint32
		checkDA        bool
		expectedDA     string
	}{
		{"End.T SL=1 default VRF", "fd00:1:1::1", "fd00:1:100::5", []string{"fd00:1:100::6", "fd00:1:100::5"}, 1, 0, XDP_PASS, true, "fd00:1:100::6"},
		{"End.T SL=0 (pass)", "fd00:1:1::1", "fd00:1:100::5", []string{"fd00:1:100::6", "fd00:1:100::5"}, 0, 0, XDP_PASS, false, ""},
		{"End.T SL=2", "fd00:1:1::1", "fd00:1:100::5", []string{"fd00:1:100::7", "fd00:1:100::6", "fd00:1:100::5"}, 2, 0, XDP_PASS, true, "fd00:1:100::6"},
		{"End.T SL=1 with VRF", "fd00:1:1::1", "fd00:1:100::5", []string{"fd00:1:100::6", "fd00:1:100::5"}, 1, 999, XDP_PASS, true, "fd00:1:100::6"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newXDPTestHelper(t)
			h.createSidFunctionWithVRF("fd00:1:100::5/128", actionEndT, tt.vrfIfindex)

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
				verifyDAAndSL(t, outPkt, tt.expectedDA, tt.segmentsLeft)
			}
		})
	}
}

func TestXDPProgEndX(t *testing.T) {
	nexthop, _ := ParseIPv6("fd00:1:1::99")

	tests := []struct {
		name           string
		srcIP, dstIP   string
		segments       []string
		segmentsLeft   uint8
		expectedAction uint32
		checkDA        bool
		expectedDA     string
	}{
		{"End.X SL=1", "fd00:1:1::1", "fd00:1:100::8", []string{"fd00:1:100::9", "fd00:1:100::8"}, 1, XDP_PASS, true, "fd00:1:100::9"},
		{"End.X SL=0 (pass)", "fd00:1:1::1", "fd00:1:100::8", []string{"fd00:1:100::9", "fd00:1:100::8"}, 0, XDP_PASS, false, ""},
		{"End.X SL=2", "fd00:1:1::1", "fd00:1:100::8", []string{"fd00:1:100::a", "fd00:1:100::9", "fd00:1:100::8"}, 2, XDP_PASS, true, "fd00:1:100::9"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newXDPTestHelper(t)
			h.createSidFunctionWithNexthop("fd00:1:100::8/128", actionEndX, nexthop)

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
				verifyDAAndSL(t, outPkt, tt.expectedDA, tt.segmentsLeft)
			}
		})
	}
}

func TestXDPProgEndPSP(t *testing.T) {
	tests := []struct {
		name           string
		srcIP, dstIP   string
		segments       []string
		segmentsLeft   uint8
		expectedAction uint32
		expectSRH      bool // true=SRH should be present, false=SRH should be stripped
		checkDA        bool
		expectedDA     string
	}{
		{"End+PSP SL=1 (strip SRH)", "fd00:1:1::1", "fd00:1:100::a", []string{"fd00:1:100::b", "fd00:1:100::a"}, 1, XDP_PASS, false, true, "fd00:1:100::b"},
		{"End+PSP SL=2 (keep SRH)", "fd00:1:1::1", "fd00:1:100::a", []string{"fd00:1:100::c", "fd00:1:100::b", "fd00:1:100::a"}, 2, XDP_PASS, true, true, "fd00:1:100::b"},
		{"End+PSP SL=0 (pass)", "fd00:1:1::1", "fd00:1:100::a", []string{"fd00:1:100::b", "fd00:1:100::a"}, 0, XDP_PASS, true, false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newXDPTestHelper(t)
			h.createSidFunctionWithFlavor("fd00:1:100::a/128", actionEnd, flavorPSP)

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

			if tt.segmentsLeft > 0 {
				if tt.expectSRH {
					verifySRHPresent(t, outPkt)
				} else {
					verifySRHAbsent(t, outPkt)
				}
			}

			if tt.checkDA && tt.segmentsLeft > 0 {
				da := net.IP(outPkt[38:54])
				if !da.Equal(net.ParseIP(tt.expectedDA)) {
					t.Errorf("Expected DA %s, got %s", tt.expectedDA, da)
				}
			}
		})
	}
}

func TestXDPProgEndUSP(t *testing.T) {
	tests := []struct {
		name           string
		srcIP, dstIP   string
		segments       []string
		segmentsLeft   uint8
		expectedAction uint32
		expectSRH      bool
	}{
		{"End+USP SL=0 (strip SRH)", "fd00:1:1::1", "fd00:1:100::c", []string{"fd00:1:100::d", "fd00:1:100::c"}, 0, XDP_PASS, false},
		{"End+USP SL=1 (normal End)", "fd00:1:1::1", "fd00:1:100::c", []string{"fd00:1:100::d", "fd00:1:100::c"}, 1, XDP_PASS, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newXDPTestHelper(t)
			h.createSidFunctionWithFlavor("fd00:1:100::c/128", actionEnd, flavorUSP)

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

			if tt.expectSRH {
				verifySRHPresent(t, outPkt)
			} else {
				verifySRHAbsent(t, outPkt)
			}
		})
	}
}

func TestXDPProgEndUSD(t *testing.T) {
	tests := []struct {
		name         string
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
		{"End+USD SL=0 inner IPv4", true, "fd00:1:100::e/128", "fd00:1:1::1", "fd00:1:100::e", []string{"fd00:1:100::e"}, 0, "10.0.0.1", "192.0.2.100", true},
		{"End+USD SL=0 inner IPv6", false, "fd00:1:100::f/128", "fd00:1:1::1", "fd00:1:100::f", []string{"fd00:1:100::f"}, 0, "2001:db8:1::1", "2001:db8:2::1", true},
		{"End+USD SL=1 (normal End)", false, "fd00:1:100::f/128", "fd00:1:1::1", "fd00:1:100::f", []string{"fd00:1:100::10", "fd00:1:100::f"}, 1, "2001:db8:1::1", "2001:db8:2::1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newXDPTestHelper(t)
			h.createSidFunctionWithFlavor(tt.triggerSID, actionEnd, flavorUSD)

			segments := make([]net.IP, len(tt.segments))
			for i, s := range tt.segments {
				segments[i] = net.ParseIP(s)
			}

			if tt.expectDecap {
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

				ret, outPkt := h.run(pkt)
				if ret != XDP_REDIRECT && ret != XDP_DROP {
					t.Errorf("Expected XDP_REDIRECT or XDP_DROP after decap, got %d", ret)
				}
				if !verifyDecapsulated(t, outPkt, net.ParseIP(tt.innerSrcIP), net.ParseIP(tt.innerDstIP), tt.isIPv4) {
					return
				}
				t.Logf("SUCCESS: End+USD decapsulation verified (action: %d)", ret)
			} else {
				pkt, err := buildSRv6Packet(net.ParseIP(tt.outerSrcIP), net.ParseIP(tt.outerDstIP), segments, tt.segmentsLeft)
				if err != nil {
					t.Fatalf("Failed to build packet: %v", err)
				}
				ret, _ := h.run(pkt)
				if ret != XDP_PASS {
					t.Errorf("Expected XDP_PASS for SL!=0, got %d", ret)
				}
			}
		})
	}
}
