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
	actionEnd     = uint8(vinberov1.Srv6LocalAction_SRV6_LOCAL_ACTION_END)
	actionEndX    = uint8(vinberov1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_X)
	actionEndT    = uint8(vinberov1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_T)
	actionEndDX2  = uint8(vinberov1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DX2)
	actionEndDX4  = uint8(vinberov1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DX4)
	actionEndDX6  = uint8(vinberov1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DX6)
	actionEndDT4  = uint8(vinberov1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DT4)
	actionEndDT6  = uint8(vinberov1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DT6)
	actionEndDT46 = uint8(vinberov1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DT46)
	actionEndDT2      = uint8(vinberov1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DT2)
	actionEndB6       = uint8(vinberov1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_B6)
	actionEndB6Encaps = uint8(vinberov1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_B6_ENCAPS)
)

// SRv6 Flavor constants (must match srv6_local_flavor enum in src/srv6.h)
const (
	flavorPSP = uint8(vinberov1.Srv6LocalFlavor_SRV6_LOCAL_FLAVOR_PSP)
	flavorUSP = uint8(vinberov1.Srv6LocalFlavor_SRV6_LOCAL_FLAVOR_USP)
	flavorUSD = uint8(vinberov1.Srv6LocalFlavor_SRV6_LOCAL_FLAVOR_USD)
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
	t.Cleanup(func() { _ = objs.Close() })
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
	if err := h.mapOps.CreateSidFunction(prefix, entry, nil); err != nil {
		h.t.Fatalf("Failed to create SID function entry: %v", err)
	}
}

func (h *xdpTestHelper) createFdbEntry(bdID uint16, mac net.HardwareAddr, oif uint32) {
	h.t.Helper()
	entry := &FdbEntry{Oif: oif}
	if err := h.mapOps.CreateFdb(bdID, mac, entry); err != nil {
		h.t.Fatalf("Failed to create FDB entry: %v", err)
	}
}

func (h *xdpTestHelper) createSidFunctionWithBD(prefix string, action uint8, bdID uint16) {
	h.t.Helper()
	entry := &SidFunctionEntry{Action: action, Flavor: 0}
	aux := NewSidAuxL2(bdID, 0)
	if err := h.mapOps.CreateSidFunction(prefix, entry, aux); err != nil {
		h.t.Fatalf("Failed to create SID function entry: %v", err)
	}
}

func (h *xdpTestHelper) createSidFunctionWithVRF(prefix string, action uint8, vrfIfindex uint32) {
	h.t.Helper()
	entry := &SidFunctionEntry{Action: action, Flavor: 0, VrfIfindex: vrfIfindex}
	if err := h.mapOps.CreateSidFunction(prefix, entry, nil); err != nil {
		h.t.Fatalf("Failed to create SID function entry: %v", err)
	}
}

func (h *xdpTestHelper) createSidFunctionWithNexthop(prefix string, action uint8, nexthop [16]byte) {
	h.t.Helper()
	entry := &SidFunctionEntry{Action: action}
	aux := NewSidAuxNexthop(nexthop)
	if err := h.mapOps.CreateSidFunction(prefix, entry, aux); err != nil {
		h.t.Fatalf("Failed to create SID function entry: %v", err)
	}
}

func (h *xdpTestHelper) createSidFunctionWithFlavor(prefix string, action uint8, flavor uint8) {
	h.t.Helper()
	entry := &SidFunctionEntry{Action: action, Flavor: flavor}
	if err := h.mapOps.CreateSidFunction(prefix, entry, nil); err != nil {
		h.t.Fatalf("Failed to create SID function entry: %v", err)
	}
}

func (h *xdpTestHelper) createSidFunctionWithOIF(prefix string, action uint8, oif uint32) {
	h.t.Helper()
	entry := &SidFunctionEntry{Action: action, Flavor: 0}
	// OIF is stored as uint32 in the first 4 bytes of aux nexthop (native endian)
	aux := &SidAuxEntry{}
	binary.NativeEndian.PutUint32(aux.Nexthop.Nexthop[:4], oif)
	if err := h.mapOps.CreateSidFunction(prefix, entry, aux); err != nil {
		h.t.Fatalf("Failed to create SID function entry: %v", err)
	}
}

func (h *xdpTestHelper) createSidFunctionB6(prefix string, action uint8, headendMode uint8, srcAddr [16]byte, segments [10][16]byte, numSegments uint8) {
	h.t.Helper()
	// Create SID function entry in sid_function_map
	entry := &SidFunctionEntry{Action: action}
	// Policy is stored in sid_aux_map (b6_policy variant)
	policy := &HeadendEntry{
		Mode:        headendMode,
		NumSegments: numSegments,
		SrcAddr:     srcAddr,
		Segments:    segments,
	}
	aux := NewSidAuxB6Policy(policy)
	if err := h.mapOps.CreateSidFunction(prefix, entry, aux); err != nil {
		h.t.Fatalf("Failed to create SID function entry for End.B6: %v", err)
	}
}

func (h *xdpTestHelper) createHeadendEntry(prefix string, srcAddr, dstAddr [16]byte, segments [10][16]byte, numSegments uint8, isIPv4 bool) {
	h.t.Helper()
	h.createHeadendEntryWithMode(prefix, srcAddr, dstAddr, segments, numSegments, isIPv4,
		vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS)
}

func (h *xdpTestHelper) createHeadendL2Entry(ifindex uint32, vlanID uint16, srcAddr [16]byte, segments [10][16]byte, numSegments uint8, bdID uint16) {
	h.t.Helper()
	h.createHeadendL2EntryWithMode(ifindex, vlanID, srcAddr, segments, numSegments, bdID,
		vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2)
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

// buildVlanTaggedIPv4Packet constructs a VLAN-tagged IPv4 packet
func buildVlanTaggedIPv4Packet(vlanID uint16, srcIP, dstIP net.IP) ([]byte, error) {
	eth := newTestEthernet(layers.EthernetTypeDot1Q)
	vlan := &layers.Dot1Q{
		VLANIdentifier: vlanID,
		Type:           layers.EthernetTypeIPv4,
	}
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
	if err := gopacket.SerializeLayers(buf, opts, eth, vlan, ip4, icmp, gopacket.Payload(newTestPayload(64))); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// buildVlanTaggedIPv6Packet constructs a VLAN-tagged IPv6 packet
func buildVlanTaggedIPv6Packet(vlanID uint16, srcIP, dstIP net.IP) ([]byte, error) {
	eth := newTestEthernet(layers.EthernetTypeDot1Q)
	vlan := &layers.Dot1Q{
		VLANIdentifier: vlanID,
		Type:           layers.EthernetTypeIPv6,
	}
	ip6 := &layers.IPv6{
		Version: 6, HopLimit: 64,
		NextHeader: layers.IPProtocolICMPv6, SrcIP: srcIP, DstIP: dstIP,
	}
	icmp, icmpEcho := newTestICMPv6Echo()
	_ = icmp.SetNetworkLayerForChecksum(ip6)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, vlan, ip6, icmp, icmpEcho, gopacket.Payload(newTestPayload(64))); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// buildL2EncapsulatedPacket constructs an SRv6 packet with inner L2 frame (for End.DX2 testing)
func buildL2EncapsulatedPacket(
	outerSrcIP, outerDstIP net.IP,
	segments []net.IP, segmentsLeft uint8,
	innerVlanID uint16,
	innerSrcIP, innerDstIP net.IP,
	isIPv4Inner bool,
) ([]byte, error) {
	// Build inner L2 frame first
	var innerFrame []byte
	var err error
	if isIPv4Inner {
		innerFrame, err = buildVlanTaggedIPv4Packet(innerVlanID, innerSrcIP.To4(), innerDstIP.To4())
	} else {
		innerFrame, err = buildVlanTaggedIPv6Packet(innerVlanID, innerSrcIP, innerDstIP)
	}
	if err != nil {
		return nil, err
	}

	// Build outer headers with inner L2 frame as payload
	eth := newTestEthernet(layers.EthernetTypeIPv6)
	outerIP6 := &layers.IPv6{
		Version: 6, SrcIP: outerSrcIP, DstIP: outerDstIP,
		NextHeader: layers.IPProtocol(43), HopLimit: 64,
	}

	numSegments := len(segments)
	srv6 := &packet.Srv6Layer{
		NextHeader:  143, // IPPROTO_ETHERNET
		HdrExtLen:   uint8(numSegments * 2),
		RoutingType: 4, SegmentsLeft: segmentsLeft,
		LastEntry: uint8(numSegments - 1), Segments: segmentsToNetipAddr(segments),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, outerIP6, srv6, gopacket.Payload(innerFrame)); err != nil {
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

// verifyOuterIPv6Header verifies an outer IPv6 header with Next Header = 43 (Routing/SRH)
func verifyOuterIPv6Header(t *testing.T, pkt []byte, expectedSrc, expectedDst [16]byte) bool {
	t.Helper()
	return verifyOuterIPv6HeaderWithNextHdr(t, pkt, expectedSrc, expectedDst, 43)
}

// verifyOuterIPv6HeaderWithNextHdr verifies an outer IPv6 header with a specified Next Header value
func verifyOuterIPv6HeaderWithNextHdr(t *testing.T, pkt []byte, expectedSrc, expectedDst [16]byte, expectedNextHdr uint8) bool {
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
	if nextHeader := pkt[offset+6]; nextHeader != expectedNextHdr {
		t.Errorf("Expected Next Header %d, got %d", expectedNextHdr, nextHeader)
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

// verifyInnerVlanFrame verifies that the inner VLAN-tagged Ethernet frame is preserved
func verifyInnerVlanFrame(t *testing.T, pkt []byte, innerOffset int, expectedVlanID uint16) bool {
	t.Helper()

	vlanFrameMinLen := ethHeaderLen + 4
	if len(pkt) < innerOffset+vlanFrameMinLen {
		t.Errorf("Packet too short for inner VLAN frame: got %d, need at least %d", len(pkt), innerOffset+vlanFrameMinLen)
		return false
	}

	expectedDstMAC := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x02}
	if !bytes.Equal(pkt[innerOffset:innerOffset+6], expectedDstMAC) {
		t.Errorf("Inner Ethernet DstMAC mismatch: expected %x, got %x", expectedDstMAC, pkt[innerOffset:innerOffset+6])
		return false
	}

	expectedSrcMAC := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	if !bytes.Equal(pkt[innerOffset+6:innerOffset+12], expectedSrcMAC) {
		t.Errorf("Inner Ethernet SrcMAC mismatch: expected %x, got %x", expectedSrcMAC, pkt[innerOffset+6:innerOffset+12])
		return false
	}

	innerEtherType := binary.BigEndian.Uint16(pkt[innerOffset+12 : innerOffset+14])
	if innerEtherType != 0x8100 {
		t.Errorf("Inner EtherType: expected 0x8100 (802.1Q), got 0x%04x", innerEtherType)
		return false
	}

	actualVlanID := binary.BigEndian.Uint16(pkt[innerOffset+14:innerOffset+16]) & 0x0FFF
	if actualVlanID != expectedVlanID {
		t.Errorf("Inner VLAN ID mismatch: expected %d, got %d", expectedVlanID, actualVlanID)
		return false
	}

	return true
}

// verifyDAAndSL verifies that the IPv6 Destination Address and SRH Segments Left
// were updated correctly after an End/End.X/End.T operation
func verifyDAAndSL(t *testing.T, pkt []byte, expectedDA string, originalSL uint8) {
	t.Helper()
	daOffset := ethHeaderLen + 24 // IPv6 DA starts at byte 24 of IPv6 header
	if len(pkt) < daOffset+ipv6AddrLen {
		t.Errorf("Packet too short for DA check: %d bytes", len(pkt))
		return
	}
	da := net.IP(pkt[daOffset : daOffset+ipv6AddrLen])
	if !da.Equal(net.ParseIP(expectedDA)) {
		t.Errorf("Expected DA %s, got %s", expectedDA, da)
	}
	slOffset := ethHeaderLen + ipv6HeaderLen + 3 // SRH segments_left field
	if len(pkt) > slOffset {
		if newSL := pkt[slOffset]; newSL != originalSL-1 {
			t.Errorf("Expected segments_left %d, got %d", originalSL-1, newSL)
		}
	}
}

// verifySRHAbsent verifies the output packet has no SRH (IPv6 nexthdr != 43)
func verifySRHAbsent(t *testing.T, pkt []byte) bool {
	t.Helper()
	if len(pkt) < ethHeaderLen+ipv6HeaderLen {
		t.Errorf("Packet too short for IPv6 header: %d bytes", len(pkt))
		return false
	}
	nextHeader := pkt[ethHeaderLen+6]
	if nextHeader == 43 {
		t.Errorf("Expected SRH to be stripped (nexthdr != 43), but got nexthdr=%d", nextHeader)
		return false
	}
	return true
}

// verifySRHPresent verifies the output packet still has an SRH (IPv6 nexthdr == 43)
func verifySRHPresent(t *testing.T, pkt []byte) bool {
	t.Helper()
	if len(pkt) < ethHeaderLen+ipv6HeaderLen {
		t.Errorf("Packet too short for IPv6 header: %d bytes", len(pkt))
		return false
	}
	nextHeader := pkt[ethHeaderLen+6]
	if nextHeader != 43 {
		t.Errorf("Expected SRH to be present (nexthdr == 43), but got nexthdr=%d", nextHeader)
		return false
	}
	return true
}

// overrideDstMAC overwrites the destination MAC in an Ethernet frame
func overrideDstMAC(pkt []byte, mac net.HardwareAddr) {
	copy(pkt[0:6], mac)
}

// convertSegmentsToBytes converts segment addresses to byte arrays (reversed order for SRH)
func convertSegmentsToBytes(segments [10][16]byte, numSegments int) [][16]byte {
	result := make([][16]byte, numSegments)
	for i := range numSegments {
		result[i] = segments[numSegments-1-i]
	}
	return result
}

// createHeadendL2EntryWithMode creates a headend L2 entry with a specific mode
func (h *xdpTestHelper) createHeadendL2EntryWithMode(ifindex uint32, vlanID uint16, srcAddr [16]byte, segments [10][16]byte, numSegments uint8, bdID uint16, mode vinberov1.Srv6HeadendBehavior) {
	h.t.Helper()
	entry := &HeadendEntry{
		Mode:        uint8(mode),
		NumSegments: numSegments,
		SrcAddr:     srcAddr,
		Segments:    segments,
		BdId:        bdID,
	}
	if err := h.mapOps.CreateHeadendL2(ifindex, vlanID, entry); err != nil {
		h.t.Fatalf("Failed to create headend L2 entry: %v", err)
	}
	h.t.Cleanup(func() {
		_ = h.mapOps.DeleteHeadendL2(ifindex, vlanID)
	})
}

// ========== Reduced SRH (.Red) Test Helpers ==========

// createHeadendEntryWithMode creates a headend entry with a specific mode
func (h *xdpTestHelper) createHeadendEntryWithMode(prefix string, srcAddr, dstAddr [16]byte, segments [10][16]byte, numSegments uint8, isIPv4 bool, mode vinberov1.Srv6HeadendBehavior) {
	h.t.Helper()
	entry := &HeadendEntry{
		Mode:        uint8(mode),
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

// verifyOuterIPv6HeaderNoSRH verifies IPv6 header where nexthdr is inner proto (not routing)
func verifyOuterIPv6HeaderNoSRH(t *testing.T, pkt []byte, expectedSrc, expectedDst [16]byte, expectedNextHdr uint8) bool {
	t.Helper()
	return verifyOuterIPv6HeaderWithNextHdr(t, pkt, expectedSrc, expectedDst, expectedNextHdr)
}

// verifyInnerPacketNoSRH verifies inner packet after outer IPv6 with no SRH
func verifyInnerPacketNoSRH(t *testing.T, pkt []byte, expectedSrc, expectedDst net.IP, isIPv4 bool) bool {
	t.Helper()
	innerOffset := ethHeaderLen + ipv6HeaderLen // no SRH

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
		if !actualSrc.Equal(expectedSrc) {
			t.Errorf("Inner src mismatch: expected %v, got %v", expectedSrc, actualSrc)
			return false
		}
		if !actualDst.Equal(expectedDst) {
			t.Errorf("Inner dst mismatch: expected %v, got %v", expectedDst, actualDst)
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
		if !actualSrc.Equal(expectedSrc) {
			t.Errorf("Inner src mismatch: expected %v, got %v", expectedSrc, actualSrc)
			return false
		}
		if !actualDst.Equal(expectedDst) {
			t.Errorf("Inner dst mismatch: expected %v, got %v", expectedDst, actualDst)
			return false
		}
	}
	return true
}

// verifyReducedSRHStructure verifies a reduced SRH structure
// Reduced SRH has segments_left = numSegmentsInSRH (points beyond the segment list)
func verifyReducedSRHStructure(t *testing.T, pkt []byte, numSegmentsInSRH int, expectedSegments [][16]byte) bool {
	t.Helper()
	srhOffset := ethHeaderLen + ipv6HeaderLen
	srhLen := srhBaseLen + numSegmentsInSRH*ipv6AddrLen

	if len(pkt) < srhOffset+srhLen {
		t.Errorf("Packet too short for reduced SRH: need %d bytes, have %d", srhOffset+srhLen, len(pkt))
		return false
	}

	if routingType := pkt[srhOffset+2]; routingType != 4 {
		t.Errorf("Expected Routing Type 4 (SR), got %d", routingType)
		return false
	}

	expectedSL := uint8(numSegmentsInSRH)
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

// buildEncapsulatedPacketNoSRH builds outer IPv6 (no SRH) + inner packet for nosrh endpoint tests
func buildEncapsulatedPacketNoSRH(
	outerSrcIP, outerDstIP net.IP,
	innerSrcIP, innerDstIP net.IP,
	innerType innerPacketType,
) ([]byte, error) {
	eth := newTestEthernet(layers.EthernetTypeIPv6)
	nextHdrProto := layers.IPProtocol(4)
	if innerType == innerTypeIPv6 {
		nextHdrProto = layers.IPProtocol(41)
	}
	outerIP6 := &layers.IPv6{
		Version: 6, SrcIP: outerSrcIP, DstIP: outerDstIP,
		NextHeader: nextHdrProto, HopLimit: 64,
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
		if err := gopacket.SerializeLayers(buf, opts, eth, outerIP6, innerIP4, icmp, gopacket.Payload(newTestPayload(64))); err != nil {
			return nil, err
		}
	} else {
		innerIP6 := &layers.IPv6{
			Version: 6, SrcIP: innerSrcIP, DstIP: innerDstIP,
			NextHeader: layers.IPProtocolICMPv6, HopLimit: 64,
		}
		icmp, icmpEcho := newTestICMPv6Echo()
		_ = icmp.SetNetworkLayerForChecksum(innerIP6)
		if err := gopacket.SerializeLayers(buf, opts, eth, outerIP6, innerIP6, icmp, icmpEcho, gopacket.Payload(newTestPayload(64))); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// buildL2EncapsulatedPacketNoSRH builds outer IPv6 (nexthdr=IPPROTO_ETHERNET) + inner L2 frame
func buildL2EncapsulatedPacketNoSRH(
	outerSrcIP, outerDstIP net.IP,
	innerVlanID uint16,
	innerSrcIP, innerDstIP net.IP,
	isIPv4Inner bool,
) ([]byte, error) {
	var innerFrame []byte
	var err error
	if isIPv4Inner {
		innerFrame, err = buildVlanTaggedIPv4Packet(innerVlanID, innerSrcIP.To4(), innerDstIP.To4())
	} else {
		innerFrame, err = buildVlanTaggedIPv6Packet(innerVlanID, innerSrcIP, innerDstIP)
	}
	if err != nil {
		return nil, err
	}
	eth := newTestEthernet(layers.EthernetTypeIPv6)
	outerIP6 := &layers.IPv6{
		Version: 6, SrcIP: outerSrcIP, DstIP: outerDstIP,
		NextHeader: layers.IPProtocol(143), HopLimit: 64,
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, outerIP6, gopacket.Payload(innerFrame)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// buildSRv6PacketWithInnerIPv4 builds an SRv6 packet encapsulating an inner IPv4 packet.
// SRH nexthdr = IPPROTO_IPIP (4)
func buildSRv6PacketWithInnerIPv4(srcIP, dstIP net.IP, segments []net.IP, segmentsLeft uint8, innerSrc, innerDst net.IP) ([]byte, error) {
	eth := newTestEthernet(layers.EthernetTypeIPv6)
	ip6 := &layers.IPv6{
		Version: 6, SrcIP: srcIP, DstIP: dstIP,
		NextHeader: layers.IPProtocol(43), HopLimit: 64,
	}

	numSegments := len(segments)
	srv6 := &packet.Srv6Layer{
		NextHeader: 4, // IPPROTO_IPIP
		HdrExtLen:  uint8(numSegments * 2),
		RoutingType: 4, SegmentsLeft: segmentsLeft,
		LastEntry: uint8(numSegments - 1), Segments: segmentsToNetipAddr(segments),
	}

	// Inner IPv4 packet
	innerIP := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		Protocol: layers.IPProtocolICMPv4,
		SrcIP: innerSrc, DstIP: innerDst,
	}
	innerICMP := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		Id: 5678, Seq: 1,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip6, srv6, innerIP, innerICMP, gopacket.Payload(newTestPayload(32))); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// GTP-U action/mode constants
const (
	actionEndMGTP4E = uint8(vinberov1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_M_GTP4_E)
	actionEndMGTP6D = uint8(vinberov1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_M_GTP6_D)
	actionEndMGTP6E = uint8(vinberov1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_M_GTP6_E)
	modeHMGTP4D     = uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_M_GTP4_D)
)

// createHeadendEntryGTP creates a headend v4 entry with H.M.GTP4.D mode and args_offset
func (h *xdpTestHelper) createHeadendEntryGTP(prefix string, srcAddr [16]byte, segments [10][16]byte, numSegments uint8, argsOffset uint8) {
	h.t.Helper()
	entry := &HeadendEntry{
		Mode:          modeHMGTP4D,
		NumSegments:   numSegments,
		SrcAddr:       srcAddr,
		Segments:      segments,
		ArgsOffset: argsOffset,
	}
	if err := h.mapOps.CreateHeadendV4(prefix, entry); err != nil {
		h.t.Fatalf("Failed to create GTP headend entry: %v", err)
	}
	h.t.Cleanup(func() { _ = h.mapOps.DeleteHeadendV4(prefix) })
}

// createSidFunctionGTP4E creates a SID function entry for End.M.GTP4.E
func (h *xdpTestHelper) createSidFunctionGTP4E(prefix string, gtpV4SrcAddr [4]byte, argsOffset uint8) {
	h.t.Helper()
	entry := &SidFunctionEntry{
		Action: actionEndMGTP4E,
	}
	aux := NewSidAuxGtp4e(argsOffset, gtpV4SrcAddr)
	if err := h.mapOps.CreateSidFunction(prefix, entry, aux); err != nil {
		h.t.Fatalf("Failed to create SID function entry for End.M.GTP4.E: %v", err)
	}
	h.t.Cleanup(func() { _ = h.mapOps.DeleteSidFunction(prefix) })
}

// buildGTPUv4Packet builds a GTP-U/IPv4 packet with optional PDU Session Container.
// Structure: [Eth][IPv4][UDP:2152][GTP-U][opt+PSC (if qfi>0)][Inner IPv4 ICMP]
func buildGTPUv4Packet(outerSrc, outerDst net.IP, teid uint32, qfi uint8, innerSrc, innerDst net.IP) ([]byte, error) {
	innerIP := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		Protocol: layers.IPProtocolICMPv4,
		SrcIP:    innerSrc.To4(),
		DstIP:    innerDst.To4(),
	}
	innerICMP := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		Id: 5678, Seq: 1,
	}

	gtp := &packet.GTPULayer{TEID: teid, QFI: qfi}
	udp := &layers.UDP{SrcPort: 2152, DstPort: 2152}
	outerIP := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    outerSrc.To4(),
		DstIP:    outerDst.To4(),
	}
	_ = udp.SetNetworkLayerForChecksum(outerIP)
	eth := newTestEthernet(layers.EthernetTypeIPv4)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, outerIP, udp, gtp, innerIP, innerICMP, gopacket.Payload(newTestPayload(32))); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// createSidFunctionGTP6D creates a SID function entry for End.M.GTP6.D
func (h *xdpTestHelper) createSidFunctionGTP6D(prefix string, argsOffset uint8) {
	h.t.Helper()
	entry := &SidFunctionEntry{Action: actionEndMGTP6D}
	aux := NewSidAuxGtp6d(argsOffset)
	if err := h.mapOps.CreateSidFunction(prefix, entry, aux); err != nil {
		h.t.Fatalf("Failed to create SID function entry for End.M.GTP6.D: %v", err)
	}
	h.t.Cleanup(func() { _ = h.mapOps.DeleteSidFunction(prefix) })
}

// createSidFunctionGTP6E creates a SID function entry for End.M.GTP6.E
func (h *xdpTestHelper) createSidFunctionGTP6E(prefix string, argsOffset uint8, srcAddr, dstAddr [16]byte) {
	h.t.Helper()
	entry := &SidFunctionEntry{Action: actionEndMGTP6E}
	aux := NewSidAuxGtp6e(argsOffset, srcAddr, dstAddr)
	if err := h.mapOps.CreateSidFunction(prefix, entry, aux); err != nil {
		h.t.Fatalf("Failed to create SID function entry for End.M.GTP6.E: %v", err)
	}
	h.t.Cleanup(func() { _ = h.mapOps.DeleteSidFunction(prefix) })
}

// buildSRv6WithGTPUPayload builds an SRv6 packet carrying GTP-U as inner payload.
// Structure: [Eth][IPv6][SRH(nexthdr=UDP, SL=1)][UDP:2152][GTP-U][Inner IPv4 ICMP]
// Used for testing End.M.GTP6.D which receives SRv6 with GTP-U inside.
func buildSRv6WithGTPUPayload(outerSrc net.IP, sid net.IP, nextSeg net.IP, teid uint32, qfi uint8, argsOffset uint8, innerSrc, innerDst net.IP) ([]byte, error) {
	// Build inner: [IPv4][ICMP][payload]
	innerIP := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		Protocol: layers.IPProtocolICMPv4,
		SrcIP:    innerSrc.To4(), DstIP: innerDst.To4(),
	}
	innerICMP := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		Id: 5678, Seq: 1,
	}
	innerBuf := gopacket.NewSerializeBuffer()
	innerOpts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(innerBuf, innerOpts, innerIP, innerICMP, gopacket.Payload(newTestPayload(32))); err != nil {
		return nil, err
	}
	innerBytes := innerBuf.Bytes()

	// Build GTP-U + UDP
	gtp := &packet.GTPULayer{TEID: teid, QFI: qfi}
	gtpBuf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(gtpBuf, innerOpts, gtp, gopacket.Payload(innerBytes)); err != nil {
		return nil, err
	}
	gtpPayload := gtpBuf.Bytes()

	udpHdr := make([]byte, 8)
	binary.BigEndian.PutUint16(udpHdr[0:2], 2152) // src port
	binary.BigEndian.PutUint16(udpHdr[2:4], 2152) // dst port
	binary.BigEndian.PutUint16(udpHdr[4:6], uint16(8+len(gtpPayload)))
	// checksum = 0

	udpGtpPayload := append(udpHdr, gtpPayload...)

	// SRH: 2 segments [nextSeg, sid], SL=1, nexthdr=17 (UDP)
	numSegments := 2
	srhLen := 8 + numSegments*16
	srh := make([]byte, srhLen)
	srh[0] = 17 // nexthdr = UDP
	srh[1] = byte((srhLen - 8) / 8) // hdrlen
	srh[2] = 4  // routing type = SRH
	srh[3] = 1  // segments_left = 1
	srh[4] = byte(numSegments - 1) // last_entry
	// segments: [0]=nextSeg, [1]=sid (reversed order per RFC)
	copy(srh[8:24], nextSeg.To16())
	copy(srh[24:40], sid.To16())

	// IPv6 header
	ipv6 := make([]byte, 40)
	ipv6[0] = 0x60 // version=6
	payloadLen := srhLen + len(udpGtpPayload)
	binary.BigEndian.PutUint16(ipv6[4:6], uint16(payloadLen))
	ipv6[6] = 43 // nexthdr = Routing (SRH)
	ipv6[7] = 64 // hop limit
	copy(ipv6[8:24], outerSrc.To16())
	copy(ipv6[24:40], sid.To16())

	// Ethernet
	eth := make([]byte, 14)
	eth[12] = 0x86
	eth[13] = 0xDD

	pkt := make([]byte, 0, 14+40+srhLen+len(udpGtpPayload))
	pkt = append(pkt, eth...)
	pkt = append(pkt, ipv6...)
	pkt = append(pkt, srh...)
	pkt = append(pkt, udpGtpPayload...)
	return pkt, nil
}

// convertReducedSegmentsToBytes converts segments for Reduced SRH verification
// For H.Encaps.Red: omit segments[0], reverse the rest
// Input: segments[0..N-1], Output: [SN-1, ..., S1] (segments[1..N-1] reversed)
func convertReducedSegmentsToBytes(segments [10][16]byte, numSegments int) [][16]byte {
	reducedCount := numSegments - 1
	result := make([][16]byte, reducedCount)
	for i := range reducedCount {
		result[i] = segments[numSegments-1-i]
	}
	return result
}
