package bpf

import (
	"net"
	"testing"

	"github.com/cilium/ebpf"
)

// skBuffCtx mirrors struct __sk_buff from linux/bpf.h.
// Only fields allowed by convert___skb_to_skb() ctx_in are set;
// the rest must remain zero or the kernel returns EINVAL.
//
// Allowed fields: mark, priority, ingress_ifindex, ifindex, cb[5],
//                 tstamp, wire_len, gso_segs, gso_size, hwtstamp
//
// NOT allowed (must be zero): data, data_end, data_meta, and others
// in the range offsetofend(cb)..offsetof(tstamp).
type skBuffCtx struct {
	Len            uint32
	PktType        uint32
	Mark           uint32
	QueueMapping   uint32
	Protocol       uint32
	VlanPresent    uint32
	VlanTci        uint32
	VlanProto      uint32
	Priority       uint32
	IngressIfindex uint32
	Ifindex        uint32
	TcIndex        uint32
	Cb             [5]uint32
	Hash           uint32
	TcClassid      uint32
	Data           uint32
	DataEnd        uint32
	NapiId         uint32
	Family         uint32
	RemoteIp4      uint32
	LocalIp4       uint32
	RemoteIp6      [4]uint32
	LocalIp6       [4]uint32
	RemotePort     uint32
	LocalPort      uint32
	DataMeta       uint32
	FlowKeys       uint64
	Tstamp         uint64
	WireLen        uint32
	GsoSegs        uint32
	Sk             uint64
	GsoSize        uint32
	TstampType     uint8
	Pad            [3]uint8
	Hwtstamp       uint64
}

// tcTestHelper provides common test utilities for TC program testing
type tcTestHelper struct {
	t      *testing.T
	objs   *BpfObjects
	mapOps *MapOperations
}

func newTCTestHelper(t *testing.T) *tcTestHelper {
	t.Helper()
	objs, err := ReadCollection(nil, nil)
	if err != nil {
		t.Fatalf("Failed to load BPF objects: %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })
	return &tcTestHelper{
		t:      t,
		objs:   objs,
		mapOps: NewMapOperations(objs),
	}
}

// run executes the TC program with proper __sk_buff context.
func (h *tcTestHelper) run(pkt []byte, ifindex uint32) (uint32, []byte) {
	h.t.Helper()
	ctx := skBuffCtx{
		Ifindex: ifindex,
	}
	ctxOut := skBuffCtx{}
	opts := ebpf.RunOptions{
		Data:       pkt,
		DataOut:    make([]byte, 1500),
		Context:    ctx,
		ContextOut: &ctxOut,
		Repeat:     1,
	}
	ret, err := h.objs.VinberoTcIngress.Run(&opts)
	if err != nil {
		h.t.Fatalf("Failed to run TC BPF program: %v", err)
	}
	return ret, opts.DataOut
}

// TestTCBumNoMeta verifies that packets without XDP BUM metadata pass through.
// skb->data_meta == skb->data in BPF_PROG_RUN (no metadata area),
// so tc_read_bum_meta returns false → TC_ACT_OK immediately.
func TestTCBumNoMeta(t *testing.T) {
	h := newTCTestHelper(t)

	tests := []struct {
		name    string
		ifindex uint32
		pkt     func() ([]byte, error)
	}{
		{
			"unicast IPv4 → TC_ACT_OK",
			1,
			func() ([]byte, error) {
				return buildSimpleIPv4Packet(net.ParseIP("10.0.0.1").To4(), net.ParseIP("192.0.2.1").To4())
			},
		},
		{
			"unicast IPv6 → TC_ACT_OK",
			1,
			func() ([]byte, error) {
				return buildSimpleIPv6Packet(net.ParseIP("fd00::1"), net.ParseIP("fd00::2"))
			},
		},
		{
			"VLAN tagged IPv4 → TC_ACT_OK",
			2,
			func() ([]byte, error) {
				return buildVlanTaggedIPv4Packet(100, net.ParseIP("10.0.0.1").To4(), net.ParseIP("192.0.2.1").To4())
			},
		},
		{
			"broadcast MAC without meta → TC_ACT_OK",
			3,
			func() ([]byte, error) {
				pkt, err := buildVlanTaggedIPv4Packet(100, net.ParseIP("10.0.0.1").To4(), net.ParseIP("192.0.2.1").To4())
				if err != nil {
					return nil, err
				}
				overrideDstMAC(pkt, net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
				return pkt, nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt, err := tt.pkt()
			if err != nil {
				t.Fatalf("Failed to build packet: %v", err)
			}

			ret, _ := h.run(pkt, tt.ifindex)
			if ret != uint32(TC_ACT_OK) {
				t.Errorf("Expected TC_ACT_OK (%d), got %d", TC_ACT_OK, ret)
			} else {
				t.Logf("SUCCESS: %s (ifindex=%d)", tt.name, tt.ifindex)
			}
		})
	}
}

// TestTCBumProgramLoaded verifies the TC program is loaded alongside the XDP program
// and shares the same maps (headend_l2_map, fdb_map).
func TestTCBumProgramLoaded(t *testing.T) {
	h := newTCTestHelper(t)

	if h.objs.VinberoTcIngress == nil {
		t.Fatal("TC BUM program not loaded")
	}

	srcAddr, _ := ParseIPv6("fc00::1")
	segments, numSegments, _ := ParseSegments([]string{"fc00::200"})
	entry := &HeadendEntry{
		Mode:        3, // H.Encaps.L2
		NumSegments: numSegments,
		SrcAddr:     srcAddr,
		Segments:    segments,
		BdId:        100,
	}

	if err := h.mapOps.CreateHeadendL2(1, 100, entry, [ESILen]byte{}); err != nil {
		t.Fatalf("Failed to create headend L2 entry: %v", err)
	}
	t.Cleanup(func() { _ = h.mapOps.DeleteHeadendL2(1, 100) })

	got, err := h.mapOps.GetHeadendL2(1, 100)
	if err != nil {
		t.Fatalf("Failed to get headend L2 entry: %v", err)
	}
	if got.NumSegments != numSegments || got.BdId != 100 {
		t.Errorf("Map entry mismatch: segments=%d bd_id=%d", got.NumSegments, got.BdId)
	}

	t.Logf("SUCCESS: TC program loaded, maps shared with XDP")
}

// NOTE on TC BUM encap path testing:
//
// BPF_PROG_TEST_RUN for SchedCLS does NOT support injecting skb->data_meta.
// The kernel's convert___skb_to_skb() requires the range from
// offsetofend(__sk_buff, cb) to offsetof(__sk_buff, tstamp) — which includes
// data, data_end, and data_meta — to be zero (EINVAL otherwise).
// See: net/bpf/test_run.c L907-912
//
// The BUM encap+clone path (which reads XDP metadata via skb->data_meta)
// requires integration testing with network namespaces where XDP→TC chain
// runs on real interfaces.
//
// What IS unit-tested:
//   - TC fast-path: no metadata → TC_ACT_OK with proper ifindex (TestTCBumNoMeta)
//   - TC program loads and shares maps with XDP (TestTCBumProgramLoaded)
//   - XDP writes correct BUM metadata marker+vlan_id (TestXDPBumMetaWrite)
