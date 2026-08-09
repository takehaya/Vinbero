package bpf

import (
	"fmt"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	vinberov1 "github.com/takehaya/vinbero/api/vinbero/v1"
)

// buildVlanTaggedUDPPacket builds {eth, 802.1Q, IPv4, UDP} toward dstMAC so
// aliasing tests can vary the inner 5-tuple per flow.
func buildVlanTaggedUDPPacket(vlanID uint16, dstMAC net.HardwareAddr, srcPort uint16) ([]byte, error) {
	eth := newTestEthernet(layers.EthernetTypeDot1Q)
	eth.DstMAC = dstMAC
	vlan := &layers.Dot1Q{VLANIdentifier: vlanID, Type: layers.EthernetTypeIPv4}
	ip4 := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.ParseIP("10.0.0.1").To4(),
		DstIP:    net.ParseIP("10.0.0.2").To4(),
	}
	udp := &layers.UDP{SrcPort: layers.UDPPort(srcPort), DstPort: 443}
	if err := udp.SetNetworkLayerForChecksum(ip4); err != nil {
		return nil, err
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, vlan, ip4, udp, gopacket.Payload(newTestPayload(32))); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// buildVlanTaggedARPPacket builds a non-IP frame (ARP request) toward
// dstMAC, the fallback-hash case: no inner L3 flow to hash, only MACs.
func buildVlanTaggedARPPacket(vlanID uint16, srcMAC, dstMAC net.HardwareAddr) ([]byte, error) {
	eth := &layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeDot1Q}
	vlan := &layers.Dot1Q{VLANIdentifier: vlanID, Type: layers.EthernetTypeARP}
	arp := &layers.ARP{
		AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4,
		HwAddressSize: 6, ProtAddressSize: 4, Operation: layers.ARPRequest,
		SourceHwAddress: srcMAC, SourceProtAddress: net.ParseIP("10.0.0.1").To4(),
		DstHwAddress: make([]byte, 6), DstProtAddress: net.ParseIP("10.0.0.2").To4(),
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, vlan, arp); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// aliasFixture models an EVPN-aliased segment the way the applier programs
// it: the FDB points a remote MAC at a synthetic ES bd_peer parked above the
// flood range, whose entry references an ECMP group holding one H.Encaps.L2
// entry per member PE.
type aliasFixture struct {
	h    *xdpTestHelper
	sids [][16]byte
}

func newAliasFixture(t *testing.T, h *xdpTestHelper, groupID uint32, bdID uint16, macs []net.HardwareAddr) *aliasFixture {
	t.Helper()
	srcAddr, _ := ParseIPv6("fc00::1")
	esi := [ESILen]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}

	sids := make([][16]byte, 2)
	paths := make([]EcmpPath, 2)
	for i := range paths {
		sid, _ := ParseIPv6(fmt.Sprintf("fd00:a11a:%d::d2", i+2))
		sids[i] = sid
		var segs [MaxSegments][IPv6AddrLen]uint8
		segs[0] = sid
		paths[i] = EcmpPath{
			Entry: &HeadendEntry{
				Mode:        uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2),
				NumSegments: 1,
				SrcAddr:     srcAddr,
				Segments:    segs,
				BdId:        bdID,
			},
			Weight: 1,
		}
	}
	if err := h.mapOps.PutEcmpGroup(groupID, paths, OwnerRPC); err != nil {
		t.Fatalf("PutEcmpGroup: %v", err)
	}

	// Ingress AC: {ifindex, vlan} -> bridge domain.
	var segs [MaxSegments][IPv6AddrLen]uint8
	segs[0] = sids[0]
	h.createHeadendL2Entry(0, 100, srcAddr, segs, 1, bdID)
	h.createHeadendL2Entry(1, 100, srcAddr, segs, 1, bdID)

	// Synthetic ES peer: first member's segments as the fallback, plus the
	// group reference, parked in the ES index range.
	esEntry := &HeadendEntry{
		Mode:         uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2),
		NumSegments:  1,
		SrcAddr:      srcAddr,
		Segments:     segs,
		BdId:         bdID,
		GroupId:      groupID,
		FloodExclude: 1,
	}
	var noRemoteSrc [IPv6AddrLen]byte
	esIdx := uint16(EsPeerIndexBase)
	if err := h.mapOps.CreateBdPeer(bdID, esIdx, esEntry, esi, noRemoteSrc, false); err != nil {
		t.Fatalf("CreateBdPeer: %v", err)
	}
	for _, mac := range macs {
		fdb := &FdbEntry{IsRemote: 1, PeerIndex: esIdx, BdId: bdID, Esi: esi}
		if err := h.mapOps.CreateFdb(bdID, mac, fdb); err != nil {
			t.Fatalf("CreateFdb: %v", err)
		}
	}
	return &aliasFixture{h: h, sids: sids}
}

// classify runs one frame and reports which member SID the outer DA hit.
func (f *aliasFixture) classify(t *testing.T, pkt []byte) (int, []byte) {
	t.Helper()
	ret, out := f.h.run(pkt)
	// H.Encaps.L2 ends in a FIB lookup that fails in the test netns, so the
	// verdict is XDP_DROP; the buffer still carries the encapsulated frame.
	if ret != XDP_DROP && ret != XDP_REDIRECT {
		t.Fatalf("expected encap (XDP_DROP/XDP_REDIRECT), got %d", ret)
	}
	da := outerIPv6DA(t, out)
	for i, sid := range f.sids {
		if da == sid {
			return i, out
		}
	}
	t.Fatalf("outer DA %v matches no member SID", da)
	return -1, nil
}

// TestXDPProgEndDT2LearnPreservesESPeer covers the RX side of aliasing: the
// End.DT2 remote-MAC learn path must not rewrite an FDB entry the control
// plane pointed at a synthetic ES peer. The frame's sender is one member PE
// of the segment; adopting its per-PE index would pin every flow for that
// MAC onto whichever PE delivered the last frame.
func TestXDPProgEndDT2LearnPreservesESPeer(t *testing.T) {
	h := newXDPTestHelper(t)
	bdID := uint16(100)
	esi := [ESILen]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}

	h.createSidFunctionWithBD("fd00:1:100::10/128", actionEndDT2, bdID)

	// The sending PE's unicast peer, resolvable through the reverse map.
	peerSrc, _ := ParseIPv6("fd00:1:1::1")
	peerEntry := &HeadendEntry{
		Mode:        uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2),
		NumSegments: 1,
		SrcAddr:     peerSrc,
	}
	if err := h.mapOps.CreateBdPeer(bdID, 0, peerEntry, esi, peerEntry.SrcAddr, true); err != nil {
		t.Fatalf("CreateBdPeer: %v", err)
	}

	// The applier's aliasing pointer for the inner frame's source MAC
	// (newTestEthernet's fixed 00:00:00:00:00:01).
	srcMAC := net.HardwareAddr{0, 0, 0, 0, 0, 1}
	aliased := &FdbEntry{IsRemote: 1, PeerIndex: uint16(EsPeerIndexBase), BdId: bdID, Esi: esi}
	if err := h.mapOps.CreateFdb(bdID, srcMAC, aliased); err != nil {
		t.Fatalf("CreateFdb: %v", err)
	}

	pkt, err := buildL2EncapsulatedPacket(
		net.ParseIP("fd00:1:1::1"), net.ParseIP("fd00:1:100::10"),
		[]net.IP{net.ParseIP("fd00:1:100::10")}, 0,
		100, net.ParseIP("10.0.0.1"), net.ParseIP("192.0.2.100"), true,
	)
	if err != nil {
		t.Fatalf("buildL2EncapsulatedPacket: %v", err)
	}
	h.run(pkt)

	got, err := h.mapOps.GetFdb(bdID, srcMAC)
	if err != nil {
		t.Fatalf("GetFdb: %v", err)
	}
	if got.PeerIndex != uint16(EsPeerIndexBase) {
		t.Errorf("RX learn rewrote the ES-peer pointer: PeerIndex = %d, want %d",
			got.PeerIndex, EsPeerIndexBase)
	}
	if got.Esi != esi {
		t.Errorf("RX learn erased the split-horizon ESI: %v", got.Esi)
	}
}

// TestXDPProgHeadendL2Aliasing exercises the aliasing data plane: an FDB hit
// on an ES peer resolves the group per inner flow, spreads across the
// members, stays per-flow stable, stamps the outer flow label, and hashes
// non-IP frames on the MAC pair.
func TestXDPProgHeadendL2Aliasing(t *testing.T) {
	h := newXDPTestHelper(t)
	remoteMAC := net.HardwareAddr{0x00, 0xaa, 0x00, 0x00, 0x00, 0x10}

	// Extra remote MACs for the non-IP fallback subtest.
	macs := []net.HardwareAddr{remoteMAC}
	for i := range 16 {
		macs = append(macs, net.HardwareAddr{0x00, 0xaa, 0x00, 0x00, 0x01, byte(i)})
	}
	f := newAliasFixture(t, h, 0x80000001, 100, macs)

	t.Run("inner flows spread across members", func(t *testing.T) {
		counts := make([]int, len(f.sids))
		for i := range 32 {
			pkt, err := buildVlanTaggedUDPPacket(100, remoteMAC, uint16(20000+i))
			if err != nil {
				t.Fatalf("build packet: %v", err)
			}
			sel, out := f.classify(t, pkt)
			counts[sel]++
			if label := outerFlowLabel(t, out); label == 0 {
				t.Errorf("flow %d: outer flow label is 0, want inner-hash entropy", i)
			}
		}
		for i, c := range counts {
			if c == 0 {
				t.Errorf("member %d received no flows: %v", i, counts)
			}
		}
	})

	t.Run("one flow stays on one member", func(t *testing.T) {
		pkt, err := buildVlanTaggedUDPPacket(100, remoteMAC, 30000)
		if err != nil {
			t.Fatalf("build packet: %v", err)
		}
		first, _ := f.classify(t, pkt)
		for range 8 {
			if sel, _ := f.classify(t, pkt); sel != first {
				t.Fatalf("flow moved between members: %d then %d", first, sel)
			}
		}
	})

	t.Run("non-IP frames hash on the MAC pair", func(t *testing.T) {
		srcMAC := net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
		counts := make([]int, len(f.sids))
		for _, mac := range macs[1:] {
			pkt, err := buildVlanTaggedARPPacket(100, srcMAC, mac)
			if err != nil {
				t.Fatalf("build packet: %v", err)
			}
			sel, _ := f.classify(t, pkt)
			counts[sel]++
			if again, _ := f.classify(t, pkt); again != sel {
				t.Fatalf("MAC pair moved between members: %d then %d", sel, again)
			}
		}
		for i, c := range counts {
			if c == 0 {
				t.Errorf("member %d received no MAC pairs: %v", i, counts)
			}
		}
	})
}
