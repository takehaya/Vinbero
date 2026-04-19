package bpf

import (
	"net"
	"testing"

	vinberov1 "github.com/takehaya/vinbero/api/vinbero/v1"
)

// Shared across the three split-horizon benchmarks to avoid repeating the
// same test vectors three times.
const (
	benchTriggerSID   = "fd00:1:100::10/128"
	benchPeerIPv6     = "fd00:1:1::1"
	benchTriggerIPv6  = "fd00:1:100::10"
	benchLocalESIStr  = "aa:aa:aa:aa:aa:aa:aa:aa:aa:01"
	benchRemoteESIStr = "bb:bb:bb:bb:bb:bb:bb:bb:bb:01"
	benchBdID         = uint16(100)
	benchVlanID       = uint16(100)
)

// benchL2Peer builds the HeadendEntry used as the sender peer in all three
// benchmarks. A separate function so the benchmarks stay noise-free.
func benchL2Peer(tb testing.TB) (*HeadendEntry, [16]byte) {
	tb.Helper()
	src, err := ParseIPv6(benchPeerIPv6)
	if err != nil {
		tb.Fatalf("ParseIPv6: %v", err)
	}
	return &HeadendEntry{
		Mode:        uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2),
		NumSegments: 1,
		SrcAddr:     src,
	}, src
}

func benchPacket(tb testing.TB) []byte {
	tb.Helper()
	pkt, err := buildL2EncapsulatedPacket(
		net.ParseIP(benchPeerIPv6), net.ParseIP(benchTriggerIPv6),
		[]net.IP{net.ParseIP(benchTriggerIPv6)}, 0,
		benchVlanID, net.ParseIP("10.0.0.1"), net.ParseIP("192.0.2.100"), true,
	)
	if err != nil {
		tb.Fatalf("buildL2EncapsulatedPacket: %v", err)
	}
	return pkt
}

// BenchmarkEndDT2MSplitHorizonDrop: RX split-horizon hit -> XDP_DROP.
func BenchmarkEndDT2MSplitHorizonDrop(b *testing.B) {
	h := newXDPTestHelper(b)
	esi, _ := ParseESI(benchLocalESIStr)

	h.createSidFunctionWithBD(benchTriggerSID, actionEndDT2M, benchBdID)
	if err := h.mapOps.CreateEsi(esi, NewEsiEntry(EsiConfig{LocalAttached: true})); err != nil {
		b.Fatalf("CreateEsi: %v", err)
	}
	peer, _ := benchL2Peer(b)
	if err := h.mapOps.CreateBdPeer(benchBdID, 0, peer, esi); err != nil {
		b.Fatalf("CreateBdPeer: %v", err)
	}

	b.ResetTimer()
	h.runRepeat(benchPacket(b), uint32(b.N))
}

// BenchmarkEndDT2MForward: ESI mismatch, gate passes -> DT2 forward path.
func BenchmarkEndDT2MForward(b *testing.B) {
	h := newXDPTestHelper(b)
	localESI, _ := ParseESI(benchLocalESIStr)
	remoteESI, _ := ParseESI(benchRemoteESIStr)

	h.createSidFunctionWithBD(benchTriggerSID, actionEndDT2M, benchBdID)
	if err := h.mapOps.CreateEsi(localESI, NewEsiEntry(EsiConfig{LocalAttached: true})); err != nil {
		b.Fatalf("CreateEsi: %v", err)
	}
	peer, _ := benchL2Peer(b)
	if err := h.mapOps.CreateBdPeer(benchBdID, 0, peer, remoteESI); err != nil {
		b.Fatalf("CreateBdPeer: %v", err)
	}

	b.ResetTimer()
	h.runRepeat(benchPacket(b), uint32(b.N))
}

// BenchmarkEndDT2Baseline: DT2U path, no split-horizon gate, as reference.
func BenchmarkEndDT2Baseline(b *testing.B) {
	h := newXDPTestHelper(b)
	h.createSidFunctionWithBD(benchTriggerSID, actionEndDT2, benchBdID)

	b.ResetTimer()
	h.runRepeat(benchPacket(b), uint32(b.N))
}
