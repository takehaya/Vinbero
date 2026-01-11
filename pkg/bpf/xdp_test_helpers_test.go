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

// ========== Test Constants ==========

// SID Function action constants
const (
	actionEnd    = uint8(vinberov1.Srv6LocalAction_SRV6_LOCAL_ACTION_END)
	actionEndDX4 = uint8(vinberov1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DX4)
	actionEndDX6 = uint8(vinberov1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DX6)
)

// Packet header lengths
const (
	ethHeaderLen  = 14
	ipv6HeaderLen = 40
	srhBaseLen    = 8 // SRH header without segments
	ipv6AddrLen   = 16
	ipv4HeaderLen = 20
)

// ========== Test Helper ==========

// xdpTestHelper provides common test utilities for XDP program testing
type xdpTestHelper struct {
	t      *testing.T
	objs   *BpfObjects
	mapOps *MapOperations
}

func newXDPTestHelper(t *testing.T) *xdpTestHelper {
	t.Helper()
	objs, err := ReadCollection(nil, nil)
	if err != nil {
		t.Fatalf("Failed to load BPF objects: %v", err)
	}
	t.Cleanup(func() { objs.Close() })
	return &xdpTestHelper{
		t:      t,
		objs:   objs,
		mapOps: NewMapOperations(objs),
	}
}

func (h *xdpTestHelper) run(pkt []byte) (uint32, []byte) {
	h.t.Helper()
	opts := ebpf.RunOptions{
		Data:    pkt,
		DataOut: make([]byte, 1500),
		Repeat:  1,
	}
	ret, err := h.objs.VinberoMain.Run(&opts)
	if err != nil {
		h.t.Fatalf("Failed to run BPF program: %v", err)
	}
	return ret, opts.DataOut
}

func (h *xdpTestHelper) createSidFunction(prefix string, action uint8) {
	h.t.Helper()
	entry := &SidFunctionEntry{Action: action, Flavor: 0}
	if err := h.mapOps.CreateSidFunction(prefix, entry); err != nil {
		h.t.Fatalf("Failed to create SID function entry: %v", err)
	}
}

func (h *xdpTestHelper) createHeadendEntry(prefix string, srcAddr, dstAddr [16]byte, segments [10][16]byte, numSegments uint8, isIPv4 bool) {
	h.t.Helper()
	entry := &HeadendEntry{
		Mode:        uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS),
		NumSegments: numSegments,
		SrcAddr:     srcAddr,
		DstAddr:     dstAddr,
		Segments:    segments,
	}
	var err error
	if isIPv4 {
		err = h.mapOps.CreateHeadendV4(prefix, entry)
	} else {
		err = h.mapOps.CreateHeadendV6(prefix, entry)
	}
	if err != nil {
		h.t.Fatalf("Failed to create headend entry: %v", err)
	}
	h.t.Cleanup(func() {
		if isIPv4 {
			_ = h.mapOps.DeleteHeadendV4(prefix)
		} else {
			_ = h.mapOps.DeleteHeadendV6(prefix)
		}
	})
}

// ========== Packet Builders ==========

func newTestEthernet(etherType layers.EthernetType) *layers.Ethernet {
	return &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: etherType,
	}
}

func newTestICMPv6Echo() (*layers.ICMPv6, *layers.ICMPv6Echo) {
	return &layers.ICMPv6{
			TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0),
		}, &layers.ICMPv6Echo{
			Identifier: 1234,
			SeqNumber:  1,
		}
}

func newTestPayload(size int) []byte {
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i)
	}
	return payload
}

func segmentsToNetipAddr(segments []net.IP) []netip.Addr {
	addrs := make([]netip.Addr, len(segments))
	for i, seg := range segments {
		addr, _ := netip.AddrFromSlice(seg.To16())
		addrs[i] = addr
	}
	return addrs
}

// buildSRv6Packet constructs an SRv6 packet with ICMPv6 payload
func buildSRv6Packet(srcIP, dstIP net.IP, segments []net.IP, segmentsLeft uint8) ([]byte, error) {
	eth := newTestEthernet(layers.EthernetTypeIPv6)
	ip6 := &layers.IPv6{
		Version: 6, SrcIP: srcIP, DstIP: dstIP,
		NextHeader: layers.IPProtocol(43), HopLimit: 64,
	}

	numSegments := len(segments)
	srv6 := &packet.Srv6Layer{
		NextHeader: 58, HdrExtLen: uint8(numSegments * 2),
		RoutingType: 4, SegmentsLeft: segmentsLeft,
		LastEntry: uint8(numSegments - 1), Segments: segmentsToNetipAddr(segments),
	}

	icmp, icmpEcho := newTestICMPv6Echo()
	_ = icmp.SetNetworkLayerForChecksum(ip6)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip6, srv6, icmp, icmpEcho, gopacket.Payload(newTestPayload(64))); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// buildSimpleIPv6Packet constructs a simple IPv6 packet without SRH
func buildSimpleIPv6Packet(srcIP, dstIP net.IP) ([]byte, error) {
	eth := newTestEthernet(layers.EthernetTypeIPv6)
	ip6 := &layers.IPv6{
		Version: 6, SrcIP: srcIP, DstIP: dstIP,
		NextHeader: layers.IPProtocolICMPv6, HopLimit: 64,
	}

	icmp, icmpEcho := newTestICMPv6Echo()
	_ = icmp.SetNetworkLayerForChecksum(ip6)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip6, icmp, icmpEcho, gopacket.Payload(newTestPayload(64))); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// buildSimpleIPv4Packet constructs a simple IPv4 packet
func buildSimpleIPv4Packet(srcIP, dstIP net.IP) ([]byte, error) {
	eth := newTestEthernet(layers.EthernetTypeIPv4)
	ip4 := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		Protocol: layers.IPProtocolICMPv4, SrcIP: srcIP, DstIP: dstIP,
	}
	icmp := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		Id: 1234, Seq: 1,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip4, icmp, gopacket.Payload(newTestPayload(64))); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// innerPacketType represents the type of inner packet for encapsulation
type innerPacketType int

const (
	innerTypeIPv4 innerPacketType = iota
	innerTypeIPv6
)

// buildEncapsulatedPacket constructs an outer IPv6+SRH packet with inner IP packet
func buildEncapsulatedPacket(
	outerSrcIP, outerDstIP net.IP,
	segments []net.IP, segmentsLeft uint8,
	innerSrcIP, innerDstIP net.IP,
	innerType innerPacketType,
) ([]byte, error) {
	eth := newTestEthernet(layers.EthernetTypeIPv6)
	outerIP6 := &layers.IPv6{
		Version: 6, SrcIP: outerSrcIP, DstIP: outerDstIP,
		NextHeader: layers.IPProtocol(43), HopLimit: 64,
	}

	numSegments := len(segments)
	nextHeader := uint8(4) // IPPROTO_IPIP for IPv4
	if innerType == innerTypeIPv6 {
		nextHeader = 41 // IPPROTO_IPV6
	}

	srv6 := &packet.Srv6Layer{
		NextHeader: nextHeader, HdrExtLen: uint8(numSegments * 2),
		RoutingType: 4, SegmentsLeft: segmentsLeft,
		LastEntry: uint8(numSegments - 1), Segments: segmentsToNetipAddr(segments),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	if innerType == innerTypeIPv4 {
		innerIP4 := &layers.IPv4{
			Version: 4, IHL: 5, TTL: 64,
			Protocol: layers.IPProtocolICMPv4, SrcIP: innerSrcIP.To4(), DstIP: innerDstIP.To4(),
		}
		icmp := &layers.ICMPv4{
			TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
			Id: 1234, Seq: 1,
		}
		if err := gopacket.SerializeLayers(buf, opts, eth, outerIP6, srv6, innerIP4, icmp, gopacket.Payload(newTestPayload(64))); err != nil {
			return nil, err
		}
	} else {
		innerIP6 := &layers.IPv6{
			Version: 6, SrcIP: innerSrcIP, DstIP: innerDstIP,
			NextHeader: layers.IPProtocolICMPv6, HopLimit: 64,
		}
		icmp, icmpEcho := newTestICMPv6Echo()
		_ = icmp.SetNetworkLayerForChecksum(innerIP6)
		if err := gopacket.SerializeLayers(buf, opts, eth, outerIP6, srv6, innerIP6, icmp, icmpEcho, gopacket.Payload(newTestPayload(64))); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// ========== Verification Helpers ==========

func verifyEtherType(t *testing.T, pkt []byte, expectedType uint16) bool {
	t.Helper()
	if len(pkt) < ethHeaderLen {
		t.Errorf("Packet too short for Ethernet header: %d bytes", len(pkt))
		return false
	}
	etherType := binary.BigEndian.Uint16(pkt[12:14])
	if etherType != expectedType {
		t.Errorf("Expected EtherType 0x%04X, got 0x%04X", expectedType, etherType)
		return false
	}
	return true
}

func verifyOuterIPv6Header(t *testing.T, pkt []byte, expectedSrc, expectedDst [16]byte) bool {
	t.Helper()
	offset := ethHeaderLen
	if len(pkt) < offset+ipv6HeaderLen {
		t.Errorf("Packet too short for IPv6 header: %d bytes", len(pkt))
		return false
	}

	if version := (pkt[offset] >> 4) & 0x0F; version != 6 {
		t.Errorf("Expected IPv6 version 6, got %d", version)
		return false
	}
	if nextHeader := pkt[offset+6]; nextHeader != 43 {
		t.Errorf("Expected Next Header 43 (Routing), got %d", nextHeader)
		return false
	}

	var actualSrc, actualDst [16]byte
	copy(actualSrc[:], pkt[offset+8:offset+24])
	copy(actualDst[:], pkt[offset+24:offset+40])

	if !bytes.Equal(actualSrc[:], expectedSrc[:]) {
		t.Errorf("Source address mismatch: expected %x, got %x", expectedSrc, actualSrc)
		return false
	}
	if !bytes.Equal(actualDst[:], expectedDst[:]) {
		t.Errorf("Destination address mismatch: expected %x, got %x", expectedDst, actualDst)
		return false
	}
	return true
}

func verifySRHStructure(t *testing.T, pkt []byte, numSegments int, expectedSegments [][16]byte) bool {
	t.Helper()
	srhOffset := ethHeaderLen + ipv6HeaderLen
	srhLen := srhBaseLen + numSegments*ipv6AddrLen

	if len(pkt) < srhOffset+srhLen {
		t.Errorf("Packet too short for SRH: need %d bytes, have %d", srhOffset+srhLen, len(pkt))
		return false
	}

	if routingType := pkt[srhOffset+2]; routingType != 4 {
		t.Errorf("Expected Routing Type 4 (SR), got %d", routingType)
		return false
	}

	expectedSL := uint8(numSegments - 1)
	if segmentsLeft := pkt[srhOffset+3]; segmentsLeft != expectedSL {
		t.Errorf("Expected Segments Left %d, got %d", expectedSL, segmentsLeft)
		return false
	}

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

func verifyInnerPacket(t *testing.T, pkt []byte, numSegments int, expectedSrc, expectedDst net.IP, isIPv4 bool) bool {
	t.Helper()
	srhLen := srhBaseLen + numSegments*ipv6AddrLen
	innerOffset := ethHeaderLen + ipv6HeaderLen + srhLen

	if isIPv4 {
		if len(pkt) < innerOffset+ipv4HeaderLen {
			t.Errorf("Packet too short for inner IPv4: %d bytes", len(pkt))
			return false
		}
		if version := (pkt[innerOffset] >> 4) & 0x0F; version != 4 {
			t.Errorf("Expected inner IPv4 version 4, got %d", version)
			return false
		}
		actualSrc := net.IP(pkt[innerOffset+12 : innerOffset+16])
		actualDst := net.IP(pkt[innerOffset+16 : innerOffset+20])
		if !actualSrc.Equal(expectedSrc) || !actualDst.Equal(expectedDst) {
			t.Errorf("Inner IPv4 mismatch: src %s/%s, dst %s/%s", expectedSrc, actualSrc, expectedDst, actualDst)
			return false
		}
	} else {
		if len(pkt) < innerOffset+ipv6HeaderLen {
			t.Errorf("Packet too short for inner IPv6: %d bytes", len(pkt))
			return false
		}
		if version := (pkt[innerOffset] >> 4) & 0x0F; version != 6 {
			t.Errorf("Expected inner IPv6 version 6, got %d", version)
			return false
		}
		actualSrc := net.IP(pkt[innerOffset+8 : innerOffset+24])
		actualDst := net.IP(pkt[innerOffset+24 : innerOffset+40])
		if !actualSrc.Equal(expectedSrc) || !actualDst.Equal(expectedDst) {
			t.Errorf("Inner IPv6 mismatch: src %s/%s, dst %s/%s", expectedSrc, actualSrc, expectedDst, actualDst)
			return false
		}
	}
	return true
}

func verifyDecapsulated(t *testing.T, pkt []byte, expectedSrc, expectedDst net.IP, isIPv4 bool) bool {
	t.Helper()
	expectedEtherType := uint16(0x86DD) // IPv6
	headerLen := ipv6HeaderLen
	srcOffset, dstOffset := 8, 24

	if isIPv4 {
		expectedEtherType = 0x0800
		headerLen = ipv4HeaderLen
		srcOffset, dstOffset = 12, 16
	}

	if !verifyEtherType(t, pkt, expectedEtherType) {
		return false
	}
	if len(pkt) < ethHeaderLen+headerLen {
		t.Errorf("Packet too short for IP header: %d bytes", len(pkt))
		return false
	}

	expectedVersion := uint8(6)
	if isIPv4 {
		expectedVersion = 4
	}
	if version := (pkt[ethHeaderLen] >> 4) & 0x0F; version != expectedVersion {
		t.Errorf("Expected IP version %d, got %d", expectedVersion, version)
		return false
	}

	var actualSrc, actualDst net.IP
	if isIPv4 {
		actualSrc = net.IP(pkt[ethHeaderLen+srcOffset : ethHeaderLen+srcOffset+4])
		actualDst = net.IP(pkt[ethHeaderLen+dstOffset : ethHeaderLen+dstOffset+4])
		if !actualSrc.Equal(expectedSrc.To4()) || !actualDst.Equal(expectedDst.To4()) {
			t.Errorf("IPv4 address mismatch: src %s/%s, dst %s/%s", expectedSrc, actualSrc, expectedDst, actualDst)
			return false
		}
	} else {
		actualSrc = net.IP(pkt[ethHeaderLen+srcOffset : ethHeaderLen+srcOffset+16])
		actualDst = net.IP(pkt[ethHeaderLen+dstOffset : ethHeaderLen+dstOffset+16])
		if !actualSrc.Equal(expectedSrc) || !actualDst.Equal(expectedDst) {
			t.Errorf("IPv6 address mismatch: src %s/%s, dst %s/%s", expectedSrc, actualSrc, expectedDst, actualDst)
			return false
		}
	}
	return true
}

// convertSegmentsToBytes converts segment addresses to byte arrays (reversed order for SRH)
func convertSegmentsToBytes(segments [10][16]byte, numSegments int) [][16]byte {
	result := make([][16]byte, numSegments)
	for i := range numSegments {
		result[i] = segments[numSegments-1-i]
	}
	return result
}
