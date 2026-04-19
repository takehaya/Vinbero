package bpf

import (
	"net"
	"testing"

	"github.com/cilium/ebpf"
	vinberov1 "github.com/takehaya/vinbero/api/vinbero/v1"
)

// benchHelper mirrors xdpTestHelper but takes testing.TB so benchmarks and
// tests can share setup. Kept local to split_horizon_bench_test.go because
// the bench file is the only user so far.
type benchHelper struct {
	objs   *BpfObjects
	mapOps *MapOperations
}

func newBenchHelper(tb testing.TB) *benchHelper {
	tb.Helper()
	objs, err := ReadCollection(nil, nil)
	if err != nil {
		tb.Fatalf("ReadCollection: %v", err)
	}
	tb.Cleanup(func() { _ = objs.Close() })
	return &benchHelper{objs: objs, mapOps: NewMapOperations(objs)}
}

// runBPF executes the XDP program `repeat` times in a single
// BPF_PROG_TEST_RUN syscall. Pair with b.N as the repeat count so Go's
// benchmark timer divides the syscall's wall-clock by the iteration count.
func (h *benchHelper) runBPF(tb testing.TB, pkt []byte, repeat uint32) {
	tb.Helper()
	opts := ebpf.RunOptions{
		Data:    pkt,
		DataOut: make([]byte, 1500),
		Repeat:  repeat,
	}
	if _, err := h.objs.VinberoMain.Run(&opts); err != nil {
		tb.Fatalf("Run: %v", err)
	}
}

// BenchmarkEndDT2MSplitHorizonDrop measures the DT2M RX drop path when the
// sender's ESI matches the local PE's attached ES (fail-safe split-horizon).
func BenchmarkEndDT2MSplitHorizonDrop(b *testing.B) {
	h := newBenchHelper(b)
	esi, _ := ParseESI("aa:aa:aa:aa:aa:aa:aa:aa:aa:01")
	bdID := uint16(100)

	entry := &SidFunctionEntry{Action: actionEndDT2M, Flavor: 0}
	aux := NewSidAuxL2(bdID, 0)
	if err := h.mapOps.CreateSidFunction("fd00:1:100::10/128", entry, aux); err != nil {
		b.Fatalf("CreateSidFunction: %v", err)
	}
	if err := h.mapOps.CreateEsi(esi, NewEsiEntry(EsiConfig{LocalAttached: true})); err != nil {
		b.Fatalf("CreateEsi: %v", err)
	}
	peerSrc, _ := ParseIPv6("fd00:1:1::1")
	peer := &HeadendEntry{
		Mode:        uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2),
		NumSegments: 1,
		SrcAddr:     peerSrc,
	}
	if err := h.mapOps.CreateBdPeer(bdID, 0, peer, esi); err != nil {
		b.Fatalf("CreateBdPeer: %v", err)
	}

	pkt, err := buildL2EncapsulatedPacket(
		net.ParseIP("fd00:1:1::1"), net.ParseIP("fd00:1:100::10"),
		[]net.IP{net.ParseIP("fd00:1:100::10")}, 0,
		100, net.ParseIP("10.0.0.1"), net.ParseIP("192.0.2.100"), true,
	)
	if err != nil {
		b.Fatalf("buildL2EncapsulatedPacket: %v", err)
	}

	b.ResetTimer()
	h.runBPF(b, pkt, uint32(b.N))
}

// BenchmarkEndDT2MForward measures the DT2M RX path when the sender's ESI
// differs from the local ES (split-horizon passes through to FDB lookup).
// No bridge is wired so the program PASSes after the DT2M gate — this
// isolates the split-horizon + DF overhead from FDB forwarding cost.
func BenchmarkEndDT2MForward(b *testing.B) {
	h := newBenchHelper(b)
	localESI, _ := ParseESI("aa:aa:aa:aa:aa:aa:aa:aa:aa:01")
	remoteESI, _ := ParseESI("bb:bb:bb:bb:bb:bb:bb:bb:bb:01")
	bdID := uint16(100)

	entry := &SidFunctionEntry{Action: actionEndDT2M, Flavor: 0}
	aux := NewSidAuxL2(bdID, 0)
	if err := h.mapOps.CreateSidFunction("fd00:1:100::10/128", entry, aux); err != nil {
		b.Fatalf("CreateSidFunction: %v", err)
	}
	if err := h.mapOps.CreateEsi(localESI, NewEsiEntry(EsiConfig{LocalAttached: true})); err != nil {
		b.Fatalf("CreateEsi: %v", err)
	}
	peerSrc, _ := ParseIPv6("fd00:1:1::1")
	peer := &HeadendEntry{
		Mode:        uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2),
		NumSegments: 1,
		SrcAddr:     peerSrc,
	}
	if err := h.mapOps.CreateBdPeer(bdID, 0, peer, remoteESI); err != nil {
		b.Fatalf("CreateBdPeer: %v", err)
	}

	pkt, err := buildL2EncapsulatedPacket(
		net.ParseIP("fd00:1:1::1"), net.ParseIP("fd00:1:100::10"),
		[]net.IP{net.ParseIP("fd00:1:100::10")}, 0,
		100, net.ParseIP("10.0.0.1"), net.ParseIP("192.0.2.100"), true,
	)
	if err != nil {
		b.Fatalf("buildL2EncapsulatedPacket: %v", err)
	}

	b.ResetTimer()
	h.runBPF(b, pkt, uint32(b.N))
}

// BenchmarkEndDT2Baseline measures the DT2 (DT2U) RX path as a split-horizon-
// free baseline: identical decap + FDB lookup without the DT2M ESI gate.
func BenchmarkEndDT2Baseline(b *testing.B) {
	h := newBenchHelper(b)
	bdID := uint16(100)

	entry := &SidFunctionEntry{Action: actionEndDT2, Flavor: 0}
	aux := NewSidAuxL2(bdID, 0)
	if err := h.mapOps.CreateSidFunction("fd00:1:100::10/128", entry, aux); err != nil {
		b.Fatalf("CreateSidFunction: %v", err)
	}

	pkt, err := buildL2EncapsulatedPacket(
		net.ParseIP("fd00:1:1::1"), net.ParseIP("fd00:1:100::10"),
		[]net.IP{net.ParseIP("fd00:1:100::10")}, 0,
		100, net.ParseIP("10.0.0.1"), net.ParseIP("192.0.2.100"), true,
	)
	if err != nil {
		b.Fatalf("buildL2EncapsulatedPacket: %v", err)
	}

	b.ResetTimer()
	h.runBPF(b, pkt, uint32(b.N))
}
