package bpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"runtime"
	"slices"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	vinberov1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"golang.org/x/sys/unix"
)

// xdpBumConstants loads the collection with every BD in xdp BUM mode, the
// way config.BpfConstants does for settings.l2.bum_mode: xdp.
var xdpBumConstants = map[string]any{
	"enable_stats":     uint8(1),
	"bum_xdp_enabled":  uint8(1),
	"bum_mode_default": BumModeXDP,
}

const bumTestBD = uint16(100)

func newXDPBumHelper(t *testing.T) *xdpTestHelper {
	t.Helper()
	return newXDPTestHelperWithConstants(t, xdpBumConstants)
}

// bumAC registers ifindex/vlan 100 as a local AC of bumTestBD.
func (h *xdpTestHelper) bumAC(ifindex uint32) {
	h.t.Helper()
	src, _ := ParseIPv6("fc00::1")
	segs, n, _ := ParseSegments([]string{"fc00::200"})
	h.createHeadendL2Entry(ifindex, 100, src, segs, n, bumTestBD)
}

// installDevmap puts an inner devmap holding lo into outer[bumTestBD], the
// shape BumDevmapSync builds. BPF_PROG_TEST_RUN does not perform the
// redirect, so the member only has to be a device that exists.
func installDevmap(t *testing.T, outer *ebpf.Map) {
	t.Helper()
	inner, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.DevMapHash, KeySize: 4, ValueSize: 8, MaxEntries: bumDevmapMaxEntries,
	})
	if err != nil {
		t.Fatalf("create inner devmap: %v", err)
	}
	defer func() { _ = inner.Close() }()
	if err := inner.Put(uint32(1), devmapVal{Ifindex: 1}); err != nil {
		t.Fatalf("add lo to the devmap: %v", err)
	}
	if err := outer.Put(uint32(bumTestBD), inner); err != nil {
		t.Fatalf("install devmap: %v", err)
	}
}

func statCount(t *testing.T, m *MapOperations, name string) uint64 {
	t.Helper()
	stats, err := m.ReadStats()
	if err != nil {
		t.Fatalf("ReadStats: %v", err)
	}
	for _, s := range stats {
		if s.Name == name {
			return s.Packets
		}
	}
	t.Fatalf("no counter %s", name)
	return 0
}

func vlanFrame(t *testing.T, dst net.HardwareAddr) []byte {
	t.Helper()
	pkt, err := buildVlanTaggedIPv4Packet(100, net.ParseIP("10.0.0.1").To4(), net.ParseIP("192.0.2.100").To4())
	if err != nil {
		t.Fatal(err)
	}
	overrideDstMAC(pkt, dst)
	return pkt
}

var bcast = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

const vnbuMarker = uint32(0x564E4255)

// tc stays the default: with xdp mode compiled in but the BD overridden to
// tc, a broadcast still gets today's 8-byte VNBU meta and XDP_PASS, and no
// xdp-mode counter moves.
func TestXDPBumTCOverrideKeepsTCPath(t *testing.T) {
	h := newXDPBumHelper(t)
	h.bumAC(1)
	installDevmap(t, h.objs.BumFloodMap)
	if err := h.mapOps.SetBdBumMode(bumTestBD, BumModeTC); err != nil {
		t.Fatal(err)
	}
	pkt := vlanFrame(t, bcast)
	ret, out := h.run(pkt)
	if ret != XDP_PASS {
		t.Fatalf("action = %d, want XDP_PASS", ret)
	}
	if len(out) != len(pkt)+8 || binary.LittleEndian.Uint64(out[:8])>>32 != uint64(vnbuMarker) {
		t.Fatalf("want the 8-byte VNBU meta in front of the frame (len %d, input %d)", len(out), len(pkt))
	}
	if n := statCount(t, h.mapOps, "BUM_XDP_FLOOD"); n != 0 {
		t.Errorf("BUM_XDP_FLOOD = %d, want 0", n)
	}
}

// A BD configured for xdp mode on a host that cannot run it takes the tc
// path even with a devmap installed. Its AC-side frames are counted as
// BUM_XDP_FALLBACK by TC (tc_dispatch_bum_clones), so not here; frames after
// decap are counted in XDP.
func TestXDPBumTCFallbackMode(t *testing.T) {
	h := newXDPTestHelperWithConstants(t, map[string]any{
		"enable_stats":     uint8(1),
		"bum_xdp_enabled":  uint8(1),
		"bum_mode_default": BumModeTCFallback,
	})
	h.bumAC(1)
	installDevmap(t, h.objs.BumFloodMap)
	pkt := vlanFrame(t, bcast)
	ret, out := h.run(pkt)
	if ret != XDP_PASS {
		t.Fatalf("action = %d, want XDP_PASS", ret)
	}
	if len(out) != len(pkt)+8 || binary.LittleEndian.Uint64(out[:8])>>32 != uint64(vnbuMarker) {
		t.Fatalf("want the 8-byte VNBU meta in front of the frame (len %d, input %d)", len(out), len(pkt))
	}
	// Counted on the TC side, not here (tc_dispatch_bum_clones).
	if n := statCount(t, h.mapOps, "BUM_XDP_FALLBACK"); n != 0 {
		t.Errorf("BUM_XDP_FALLBACK = %d, want 0", n)
	}
	if n := statCount(t, h.mapOps, "BUM_XDP_FLOOD"); n != 0 {
		t.Errorf("BUM_XDP_FLOOD = %d, want 0", n)
	}

	// After decap: the bridge path (here: no bridge, so XDP_PASS).
	h.createSidFunctionWithBD("fd00:1:100::10/128", actionEndDT2M, bumTestBD)
	installDevmap(t, h.objs.BumLocalMap)
	enc, err := buildL2EncapsulatedPacket(
		net.ParseIP("fd00:1:1::1"), net.ParseIP("fd00:1:100::10"),
		[]net.IP{net.ParseIP("fd00:1:100::10")}, 0,
		100, net.ParseIP("10.0.0.1"), net.ParseIP("192.0.2.100"), true,
	)
	if err != nil {
		t.Fatal(err)
	}
	if ret, _ := h.run(enc); ret != XDP_PASS {
		t.Fatalf("after decap: action = %d, want XDP_PASS", ret)
	}
	if n := statCount(t, h.mapOps, "BUM_XDP_FALLBACK"); n != 1 {
		t.Errorf("BUM_XDP_FALLBACK = %d, want 1", n)
	}
	if n := statCount(t, h.mapOps, "BUM_XDP_LOCAL_FLOOD"); n != 0 {
		t.Errorf("BUM_XDP_LOCAL_FLOOD = %d, want 0", n)
	}
}

func TestXDPBumFloodFromAC(t *testing.T) {
	h := newXDPBumHelper(t)
	h.bumAC(1)

	t.Run("no devmap falls back to the tc path", func(t *testing.T) {
		pkt := vlanFrame(t, bcast)
		ret, out := h.run(pkt)
		if ret != XDP_PASS {
			t.Fatalf("action = %d, want XDP_PASS", ret)
		}
		if len(out) != len(pkt)+8 || binary.LittleEndian.Uint64(out[:8])>>32 != uint64(vnbuMarker) {
			t.Fatalf("fallback must write the VNBU meta (len %d, input %d)", len(out), len(pkt))
		}
		// Counted on the TC side, not here (tc_dispatch_bum_clones).
		if n := statCount(t, h.mapOps, "BUM_XDP_FALLBACK"); n != 0 {
			t.Errorf("BUM_XDP_FALLBACK = %d, want 0", n)
		}
	})

	installDevmap(t, h.objs.BumFloodMap)
	for _, tc := range []struct {
		name string
		dst  net.HardwareAddr
	}{
		{"broadcast", bcast},
		{"multicast", net.HardwareAddr{0x01, 0x00, 0x5e, 0x00, 0x00, 0x01}},
		{"unknown unicast", net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x77}},
	} {
		t.Run(tc.name+" is broadcast through the devmap", func(t *testing.T) {
			before := statCount(t, h.mapOps, "BUM_XDP_FLOOD")
			pkt := vlanFrame(t, tc.dst)
			ret, out := h.run(pkt)
			if ret != XDP_REDIRECT {
				t.Fatalf("action = %d, want XDP_REDIRECT", ret)
			}
			if !bytes.Equal(out, pkt) {
				t.Errorf("frame must leave unchanged and without meta (len %d, input %d)", len(out), len(pkt))
			}
			if n := statCount(t, h.mapOps, "BUM_XDP_FLOOD"); n != before+1 {
				t.Errorf("BUM_XDP_FLOOD = %d, want %d", n, before+1)
			}
		})
	}
}

func TestXDPBumLocalUnicast(t *testing.T) {
	h := newXDPBumHelper(t)
	h.bumAC(1)
	installDevmap(t, h.objs.BumFloodMap)
	dst := net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x02}

	h.createFdbEntry(bumTestBD, dst, 7)
	if ret, _ := h.run(vlanFrame(t, dst)); ret != XDP_REDIRECT {
		t.Errorf("known local unicast: action = %d, want XDP_REDIRECT (no bridge in xdp mode)", ret)
	}

	// Learned on the ingress port itself: the bridge would not hairpin it.
	h.createFdbEntry(bumTestBD, dst, 1)
	if ret, _ := h.run(vlanFrame(t, dst)); ret != XDP_DROP {
		t.Errorf("hairpin: action = %d, want XDP_DROP", ret)
	}

	// A BD the control plane does not serve in xdp mode (no devmap) leaves
	// its unicast to the bridge, like its BUM.
	if err := h.objs.BumFloodMap.Delete(uint32(bumTestBD)); err != nil {
		t.Fatal(err)
	}
	h.createFdbEntry(bumTestBD, dst, 7)
	if ret, _ := h.run(vlanFrame(t, dst)); ret != XDP_PASS {
		t.Errorf("known unicast without a devmap: action = %d, want XDP_PASS", ret)
	}
}

// TestXDPBumTCModeLocalUnicastPasses pins today's tc-mode behavior, which
// the xdp-mode branch must not leak into.
func TestXDPBumTCModeLocalUnicastPasses(t *testing.T) {
	h := newXDPTestHelper(t)
	h.bumAC(1)
	dst := net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x02}
	h.createFdbEntry(bumTestBD, dst, 7)
	if ret, _ := h.run(vlanFrame(t, dst)); ret != XDP_PASS {
		t.Errorf("tc mode known local unicast: action = %d, want XDP_PASS", ret)
	}
}

func TestXDPBumFloodFromTunnel(t *testing.T) {
	h := newXDPBumHelper(t)
	h.createSidFunctionWithBD("fd00:1:100::10/128", actionEndDT2M, bumTestBD)
	pkt, err := buildL2EncapsulatedPacket(
		net.ParseIP("fd00:1:1::1"), net.ParseIP("fd00:1:100::10"),
		[]net.IP{net.ParseIP("fd00:1:100::10")}, 0,
		100, net.ParseIP("10.0.0.1"), net.ParseIP("192.0.2.100"), true,
	)
	if err != nil {
		t.Fatal(err)
	}

	// No devmap: the bridge path (here: no bridge, so XDP_PASS).
	if ret, _ := h.run(pkt); ret != XDP_PASS {
		t.Fatalf("without a devmap: action = %d, want XDP_PASS", ret)
	}
	if n := statCount(t, h.mapOps, "BUM_XDP_FALLBACK"); n != 1 {
		t.Errorf("BUM_XDP_FALLBACK = %d, want 1", n)
	}

	installDevmap(t, h.objs.BumLocalMap)
	if ret, _ := h.run(pkt); ret != XDP_REDIRECT {
		t.Fatalf("FDB miss: action = %d, want XDP_REDIRECT through the local devmap", ret)
	}
	if n := statCount(t, h.mapOps, "BUM_XDP_LOCAL_FLOOD"); n != 1 {
		t.Errorf("BUM_XDP_LOCAL_FLOOD = %d, want 1", n)
	}
}

// drainFdbEvents opens a reader and empties whatever earlier tests left in
// the shared ring buffer.
func drainFdbEvents(t *testing.T, objs *BpfObjects) *ringbuf.Reader {
	t.Helper()
	rd, err := ringbuf.NewReader(objs.FdbEventRb)
	if err != nil {
		t.Fatalf("ringbuf reader: %v", err)
	}
	t.Cleanup(func() { _ = rd.Close() })
	for {
		rd.SetDeadline(time.Now().Add(10 * time.Millisecond))
		if _, err := rd.Read(); err != nil {
			return rd
		}
	}
}

func nextFdbEvent(t *testing.T, rd *ringbuf.Reader) (FdbEvent, bool) {
	t.Helper()
	rd.SetDeadline(time.Now().Add(200 * time.Millisecond))
	rec, err := rd.Read()
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return FdbEvent{}, false
	}
	if err != nil {
		t.Fatalf("ringbuf read: %v", err)
	}
	ev, err := ParseFdbEvent(rec.RawSample)
	if err != nil {
		t.Fatal(err)
	}
	return ev, true
}

func TestXDPBumLearningEvents(t *testing.T) {
	src := net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01} // newTestEthernet's source

	t.Run("xdp mode reports adds and moves", func(t *testing.T) {
		h := newXDPBumHelper(t)
		h.bumAC(1)
		installDevmap(t, h.objs.BumFloodMap)
		rd := drainFdbEvents(t, h.objs)

		h.run(vlanFrame(t, bcast))
		ev, ok := nextFdbEvent(t, rd)
		if !ok || ev.Kind != FdbEventAdd || ev.BdID != bumTestBD || ev.MAC.String() != src.String() || ev.Oif != 1 {
			t.Fatalf("first frame: event %+v (ok=%v), want ADD bd %d mac %s oif 1", ev, ok, bumTestBD, src)
		}
		h.run(vlanFrame(t, bcast))
		if ev, ok := nextFdbEvent(t, rd); ok {
			t.Fatalf("a refresh must not report: got %+v", ev)
		}

		// The MAC moves: it was last seen on ifindex 9.
		if err := h.objs.FdbMap.Put(buildFdbKey(bumTestBD, src), &FdbEntry{Oif: 9, LastSeen: 1}); err != nil {
			t.Fatal(err)
		}
		h.run(vlanFrame(t, bcast))
		ev, ok = nextFdbEvent(t, rd)
		if !ok || ev.Kind != FdbEventMove || ev.Oif != 1 {
			t.Fatalf("after a move: event %+v (ok=%v), want MOVE to oif 1", ev, ok)
		}
	})

	t.Run("tc mode reports nothing", func(t *testing.T) {
		h := newXDPTestHelper(t)
		h.bumAC(1)
		rd := drainFdbEvents(t, h.objs)
		h.run(vlanFrame(t, bcast))
		if _, err := h.mapOps.GetFdb(bumTestBD, src); err != nil {
			t.Fatalf("tc mode still learns: %v", err)
		}
		if ev, ok := nextFdbEvent(t, rd); ok {
			t.Fatalf("tc mode must not emit events: got %+v", ev)
		}
	})
}

// ===== replication plan and devmap egress program =====
//
// BPF_PROG_TEST_RUN does not perform the broadcast, so a test plays both
// halves itself on one CPU: vinbero_main writes the frame's plan into that
// CPU's ring and returns XDP_REDIRECT, then each run of the egress test
// entry stands for one devmap copy.

// TestBumPlanMapsArePerCPU pins the map types the plan relies on: the
// sequence counter and the ring are per-CPU, so the egress program finds
// its frame's plan without locking.
func TestBumPlanMapsArePerCPU(t *testing.T) {
	spec, err := LoadBpf()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []struct {
		name       string
		maxEntries uint32
		valueSize  uint32
	}{
		{"bum_seq", 1, 8},
		{"bum_plan_ring", 1024, uint32(unsafe.Sizeof(BpfBumPlan{}))},
	} {
		m, ok := spec.Maps[want.name]
		if !ok {
			t.Fatalf("no map %s", want.name)
		}
		if m.Type != ebpf.PerCPUArray || m.MaxEntries != want.maxEntries || m.ValueSize != want.valueSize {
			t.Errorf("%s: type %v, %d entries of %d bytes; want PerCPUArray, %d of %d",
				want.name, m.Type, m.MaxEntries, m.ValueSize, want.maxEntries, want.valueSize)
		}
	}
	if unsafe.Sizeof(BpfBumPlan{}) != 96 {
		t.Errorf("struct bum_plan is %d bytes, want 96", unsafe.Sizeof(BpfBumPlan{}))
	}
}

// pinCPU keeps the calling goroutine on one CPU, the same one every time,
// until the test ends, and returns it: the plan the ingress run writes is
// per-CPU, and so is the egress run's view. A subtest runs on a goroutine
// of its own and pins again.
func pinCPU(t *testing.T) int {
	t.Helper()
	runtime.LockOSThread()
	var prev unix.CPUSet
	if err := unix.SchedGetaffinity(0, &prev); err != nil {
		t.Fatal(err)
	}
	cpu := -1
	for i := 0; i < 1024; i++ {
		if prev.IsSet(i) {
			cpu = i
			break
		}
	}
	var one unix.CPUSet
	one.Set(cpu)
	if err := unix.SchedSetaffinity(0, &one); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = unix.SchedSetaffinity(0, &prev)
		runtime.UnlockOSThread()
	})
	return cpu
}

type egressCase struct {
	h       *xdpTestHelper
	cpu     int
	nexthop net.IP
	uplink  uint32
	sync    *BumDevmapSync
	// uplinkOf maps a peer's first segment to its uplink; anything else
	// resolves to uplink.
	uplinkOf map[string]uint32
}

// newEgressCase sets up the adjacency the FIB lookup resolves through and
// an AC on lo (vlan 100) in bumTestBD.
func newEgressCase(t *testing.T) *egressCase {
	t.Helper()
	return newEgressCaseWithConstants(t, xdpBumConstants)
}

func newEgressCaseWithConstants(t *testing.T, consts map[string]any) *egressCase {
	t.Helper()
	h := newXDPTestHelperWithConstants(t, consts)
	nexthop, _ := adjacencyEnv(t)
	link, err := net.InterfaceByName("uadj-a")
	if err != nil {
		t.Fatal(err)
	}
	h.bumAC(1)
	c := &egressCase{h: h, cpu: pinCPU(t), nexthop: nexthop, uplink: uint32(link.Index), uplinkOf: map[string]uint32{}}
	c.sync = NewBumDevmapSync(h.objs, func(uint16) uint8 { return BumModeXDP }, func(q UplinkQuery) (BumUplink, error) {
		if up, ok := c.uplinkOf[net.IP(q.Dst[:]).String()]; ok {
			return BumUplink{Ifindex: up}, nil
		}
		return BumUplink{Ifindex: c.uplink}, nil
	}, nil)
	return c
}

func (c *egressCase) peer(t *testing.T, index uint16, mode vinberov1.Srv6HeadendBehavior, segs []string, esi [ESILen]byte, floodExclude bool) {
	t.Helper()
	src, _ := ParseIPv6("fc00::1")
	s, n, err := ParseSegments(segs)
	if err != nil {
		t.Fatal(err)
	}
	e := &HeadendEntry{Mode: uint8(mode), NumSegments: n, SrcAddr: src, Segments: s}
	if floodExclude {
		e.FloodExclude = 1
	}
	if err := c.h.mapOps.CreateBdPeer(bumTestBD, index, e, esi, [IPv6AddrLen]byte{}, false); err != nil {
		t.Fatalf("CreateBdPeer: %v", err)
	}
}

// ingress builds the BD's devmaps and runs one AC-side broadcast through
// vinbero_main, which plans it; it returns the plan.
func (c *egressCase) ingress(t *testing.T, pkt []byte) BpfBumPlan {
	t.Helper()
	if err := c.sync.SyncBD(bumTestBD); err != nil {
		t.Fatal(err)
	}
	if ret, _ := c.h.run(pkt); ret != XDP_REDIRECT {
		t.Fatalf("ingress: action = %d, want XDP_REDIRECT", ret)
	}
	seq, plan := c.latestPlan(t)
	if plan.Seq != seq {
		t.Fatalf("ingress wrote seq %d into the ring, counter says %d", plan.Seq, seq)
	}
	return plan
}

// latestPlan reads this CPU's latest seq and its ring entry.
func (c *egressCase) latestPlan(t *testing.T) (uint64, BpfBumPlan) {
	t.Helper()
	var next []uint64
	if err := c.h.objs.BumSeq.Lookup(uint32(0), &next); err != nil {
		t.Fatal(err)
	}
	if next[c.cpu] == 0 {
		t.Fatal("no plan on this CPU")
	}
	seq := next[c.cpu] - 1
	var plans []BpfBumPlan
	if err := c.h.objs.BumPlanRing.Lookup(uint32(seq%1024), &plans); err != nil {
		t.Fatal(err)
	}
	return seq, plans[c.cpu]
}

// editPlan rewrites this CPU's latest plan.
func (c *egressCase) editPlan(t *testing.T, edit func(*BpfBumPlan)) {
	t.Helper()
	seq, _ := c.latestPlan(t)
	var plans []BpfBumPlan
	if err := c.h.objs.BumPlanRing.Lookup(uint32(seq%1024), &plans); err != nil {
		t.Fatal(err)
	}
	edit(&plans[c.cpu])
	if err := c.h.objs.BumPlanRing.Put(uint32(seq%1024), plans); err != nil {
		t.Fatal(err)
	}
}

// egress runs one copy through the egress test entry. sameBuffer makes the
// copy look as if it ran on the ingress program's buffer.
func (c *egressCase) egress(t *testing.T, srcIf, egressIf uint32, sameBuffer bool, pkt []byte) (uint32, []byte) {
	t.Helper()
	p := BpfBumTestParams{IngressIfindex: srcIf, EgressIfindex: egressIf}
	if sameBuffer {
		p.SameBuffer = 1
	}
	if err := c.h.objs.BumTestParamsMap.Put(uint32(0), &p); err != nil {
		t.Fatal(err)
	}
	opts := ebpf.RunOptions{Data: pkt, DataOut: make([]byte, 1600), Repeat: 1}
	ret, err := c.h.objs.BumRemoteEgressTest.Run(&opts)
	if err != nil {
		t.Fatalf("test run: %v", err)
	}
	return ret, opts.DataOut
}

func lastSegment(i uint16) net.IP {
	return net.IP{0xfc, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, byte(i)}
}

// The plan is what the tc path's per-peer checks would let through,
// grouped by uplink: flood_exclude and same-ES peers are left out at
// ingress, and the copies for one uplink hand out its slots in order.
func TestBumPlanFromIngress(t *testing.T) {
	c := newEgressCase(t)
	nh := c.nexthop.String()
	l2 := bumFrame(t)
	esi, _ := ParseESI("01:00:00:00:00:00:00:00:00:01")
	src, _ := ParseIPv6("fc00::1")
	segs, n, _ := ParseSegments([]string{"fc00::200"})
	if err := c.h.mapOps.CreateHeadendL2(1, 100, &HeadendEntry{
		Mode: uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2), NumSegments: n,
		SrcAddr: src, Segments: segs, BdId: bumTestBD,
	}, esi); err != nil {
		t.Fatal(err)
	}
	l2Mode := vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2
	c.peer(t, 0, l2Mode, []string{nh, lastSegment(0).String()}, [ESILen]byte{}, false)
	c.peer(t, 2, l2Mode, []string{nh, lastSegment(2).String()}, [ESILen]byte{}, false)
	c.peer(t, 3, l2Mode, []string{nh, lastSegment(3).String()}, [ESILen]byte{}, true) // RT2 unicast peer
	c.peer(t, 4, l2Mode, []string{nh, lastSegment(4).String()}, esi, false)           // same ES as the AC
	c.peer(t, 6, l2Mode, []string{nh, lastSegment(6).String()}, [ESILen]byte{}, false)
	c.uplinkOf["fc00::99"] = 1 // a second uplink (lo)
	c.peer(t, 7, l2Mode, []string{"fc00::99", lastSegment(7).String()}, [ESILen]byte{}, false)

	shBefore := statCount(t, c.h.mapOps, "SPLIT_HORIZON_TX")
	plan := c.ingress(t, l2)
	if plan.SrcIfindex != 1 || plan.BdId != bumTestBD || int(plan.Len) != len(l2) {
		t.Errorf("plan header = src %d bd %d len %d, want 1/%d/%d",
			plan.SrcIfindex, plan.BdId, plan.Len, bumTestBD, len(l2))
	}
	type up struct {
		ifindex uint32
		slots   uint8
		n       uint8
	}
	var got []up
	for i := range int(plan.N_uplinks) {
		got = append(got, up{plan.Up[i].Ifindex, plan.Up[i].Slots, plan.Up[i].N})
	}
	want := []up{{c.uplink, 1<<0 | 1<<2 | 1<<6, 3}, {1, 1 << 7, 1}}
	if !slices.Equal(got, want) {
		t.Fatalf("plan uplinks = %+v, want %+v", got, want)
	}
	if n := statCount(t, c.h.mapOps, "SPLIT_HORIZON_TX"); n != shBefore+1 {
		t.Errorf("SPLIT_HORIZON_TX = %d, want %d (peer 4)", n, shBefore+1)
	}

	// The three copies headed for the uplink get slots 0, 2, 6 in turn.
	for _, slot := range []uint16{0, 2, 6} {
		ret, out := c.egress(t, 1, c.uplink, false, l2)
		if ret != XDP_PASS {
			t.Fatalf("copy for slot %d: action = %d, want XDP_PASS", slot, ret)
		}
		if got := net.IP(out[ethHeaderLen+ipv6HeaderLen+srhBaseLen : ethHeaderLen+ipv6HeaderLen+srhBaseLen+ipv6AddrLen]); !got.Equal(lastSegment(slot)) {
			t.Errorf("copy for slot %d: SRH[0] = %v, want %v", slot, got, lastSegment(slot))
		}
	}
	// The devmap holds an entry for every peer behind the uplink (four:
	// the same-ES one too), so one copy too many arrives.
	before := statCount(t, c.h.mapOps, "BUM_PLAN_SURPLUS")
	if ret, _ := c.egress(t, 1, c.uplink, false, l2); ret != XDP_DROP {
		t.Fatalf("surplus copy: action = %d, want XDP_DROP", ret)
	}
	if n := statCount(t, c.h.mapOps, "BUM_PLAN_SURPLUS"); n != before+1 {
		t.Errorf("BUM_PLAN_SURPLUS = %d, want %d", n, before+1)
	}
	// A device the plan has no item for has no slot entry: the copy is a
	// local AC's (native XDP gives local entries the program too), and it
	// leaves unchanged.
	if ret, out := c.egress(t, 1, 4242, false, l2); ret != XDP_PASS || !bytes.Equal(out[:len(l2)], l2) {
		t.Fatalf("copy for a device without slots: action = %d, want XDP_PASS and the frame unchanged", ret)
	}
	flood := devmapEntries(t, c.h.objs.BumFloodMap, bumTestBD)
	if got := sortedKeys(flood); !slices.Equal(got, []uint32{1, BumSlotKeyBase, BumSlotKeyBase | 2, BumSlotKeyBase | 4, BumSlotKeyBase | 6, BumSlotKeyBase | 7}) {
		t.Errorf("flood devmap keys = %#x", got)
	}
}

// An AC on the device that is also the uplink of the BD's slots: that
// device's local entry carries the egress program too, and its copies are
// the slots' encapsulated ones plus one unchanged for the AC.
func TestBumACOnUplink(t *testing.T) {
	c := newEgressCase(t)
	nh := c.nexthop.String()
	l2 := bumFrame(t)
	c.h.bumAC(c.uplink)
	l2Mode := vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2
	c.peer(t, 0, l2Mode, []string{nh, lastSegment(0).String()}, [ESILen]byte{}, false)
	c.peer(t, 1, l2Mode, []string{nh, lastSegment(1).String()}, [ESILen]byte{}, false)

	plan := c.ingress(t, l2)
	if plan.N_uplinks != 1 || plan.Up[0].Ifindex != c.uplink || plan.Up[0].Slots != 0b11 || plan.Up[0].N != 2 || plan.Up[0].Local != 1 {
		t.Fatalf("plan = %d uplinks, first %+v; want uplink %d, slots 0b11, n 2, local 1", plan.N_uplinks, plan.Up[0], c.uplink)
	}
	flood := devmapEntries(t, c.h.objs.BumFloodMap, bumTestBD)
	if flood[c.uplink].ProgFD == 0 {
		t.Error("the AC on the uplink has no egress program in the flood devmap")
	}
	if flood[1].ProgFD != 0 {
		t.Error("an AC that is no uplink got the egress program")
	}
	if local := devmapEntries(t, c.h.objs.BumLocalMap, bumTestBD); local[c.uplink].ProgFD != 0 {
		t.Error("the post-decap devmap got the egress program")
	}

	for _, slot := range []uint16{0, 1} {
		ret, out := c.egress(t, 1, c.uplink, false, l2)
		if ret != XDP_PASS {
			t.Fatalf("copy for slot %d: action = %d, want XDP_PASS", slot, ret)
		}
		if got := net.IP(out[ethHeaderLen+ipv6HeaderLen+srhBaseLen : ethHeaderLen+ipv6HeaderLen+srhBaseLen+ipv6AddrLen]); !got.Equal(lastSegment(slot)) {
			t.Errorf("copy for slot %d: SRH[0] = %v, want %v", slot, got, lastSegment(slot))
		}
	}
	ret, out := c.egress(t, 1, c.uplink, false, l2)
	if ret != XDP_PASS || !bytes.Equal(out[:len(l2)], l2) {
		t.Fatalf("local copy: action = %d, frame changed = %v; want XDP_PASS, unchanged", ret, !bytes.Equal(out[:len(l2)], l2))
	}
	before := statCount(t, c.h.mapOps, "BUM_PLAN_SURPLUS")
	if ret, _ := c.egress(t, 1, c.uplink, false, l2); ret != XDP_DROP {
		t.Fatalf("copy past the local one: action = %d, want XDP_DROP", ret)
	}
	if n := statCount(t, c.h.mapOps, "BUM_PLAN_SURPLUS"); n != before+1 {
		t.Errorf("BUM_PLAN_SURPLUS = %d, want %d", n, before+1)
	}

	t.Run("frame from the AC on the uplink", func(t *testing.T) {
		pinCPU(t)
		// The test runner's ingress device is lo: make lo the uplink of
		// slot 1, so the source AC is on a planned slot's uplink.
		c.uplinkOf[nh] = 1
		plan := c.ingress(t, l2)
		if plan.N_uplinks != 1 || plan.Up[0].Ifindex != 1 || plan.Up[0].N != 2 || plan.Up[0].Local != 0 {
			t.Fatalf("plan = %d uplinks, first %+v; want uplink 1 (the source AC), n 2, local 0", plan.N_uplinks, plan.Up[0])
		}
		// Two slot copies (sent elsewhere by the FIB: dropped as a
		// mismatch here), then the source AC's own copy: surplus.
		for range 2 {
			c.egress(t, 1, 1, false, l2)
		}
		before := statCount(t, c.h.mapOps, "BUM_PLAN_SURPLUS")
		if ret, _ := c.egress(t, 1, 1, false, l2); ret != XDP_DROP {
			t.Fatalf("hairpin copy: action = %d, want XDP_DROP", ret)
		}
		if n := statCount(t, c.h.mapOps, "BUM_PLAN_SURPLUS"); n != before+1 {
			t.Errorf("BUM_PLAN_SURPLUS = %d, want %d", n, before+1)
		}
	})
}

func TestBumRemoteEgressEncap(t *testing.T) {
	c := newEgressCase(t)
	nh := c.nexthop.String()
	l2 := bumFrame(t)

	// Slots 0..7, each its own peer (distinct last segment), all behind the
	// one uplink: one shared program, and every copy gets its own peer's
	// headers.
	for i := range uint16(MaxBumNexthops) {
		c.peer(t, i, vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2, []string{nh, lastSegment(i).String()}, [ESILen]byte{}, false)
	}
	if plan := c.ingress(t, l2); plan.N_uplinks != 1 || plan.Up[0].N != MaxBumNexthops || plan.Up[0].Slots != 0xff {
		t.Fatalf("plan = %d uplinks, first %+v; want one uplink with all 8 slots", plan.N_uplinks, plan.Up[0])
	}
	for i := range uint16(MaxBumNexthops) {
		ret, out := c.egress(t, 1, c.uplink, false, l2)
		if ret != XDP_PASS {
			t.Fatalf("copy %d: action = %d, want XDP_PASS (devmap transmit)", i, ret)
		}
		const hdr = ethHeaderLen + ipv6HeaderLen + srhBaseLen + 2*ipv6AddrLen
		if len(out) != hdr+len(l2) {
			t.Fatalf("copy %d: len %d, want %d", i, len(out), hdr+len(l2))
		}
		if binary.BigEndian.Uint16(out[12:14]) != 0x86dd {
			t.Fatalf("copy %d: outer ethertype %#x", i, out[12:14])
		}
		ip6 := out[ethHeaderLen:]
		if got := net.IP(ip6[24:40]); !got.Equal(c.nexthop) {
			t.Errorf("copy %d: outer DA %v, want segments[0] %v", i, got, c.nexthop)
		}
		srh := ip6[ipv6HeaderLen:]
		if srh[0] != 143 || srh[2] != 4 || srh[3] != 1 || srh[4] != 1 {
			t.Errorf("copy %d: SRH nh=%d type=%d SL=%d LE=%d, want 143/4/1/1", i, srh[0], srh[2], srh[3], srh[4])
		}
		// SRH segment list is reversed: [0] is the last segment.
		if got := net.IP(srh[8:24]); !got.Equal(lastSegment(i)) {
			t.Errorf("copy %d: SRH[0] = %v, want slot %d's peer", i, got, i)
		}
		if !bytes.Equal(out[hdr:], l2) {
			t.Errorf("copy %d: inner frame changed", i)
		}
	}
	if n := statCount(t, c.h.mapOps, "BUM_EGRESS_TX"); n != MaxBumNexthops {
		t.Errorf("BUM_EGRESS_TX = %d, want %d", n, MaxBumNexthops)
	}

	t.Run("reduced, one segment: no SRH", func(t *testing.T) {
		pinCPU(t)
		if _, err := c.h.mapOps.DeleteBdPeer(bumTestBD, 3); err != nil {
			t.Fatal(err)
		}
		c.peer(t, 3, vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2_RED, []string{nh}, [ESILen]byte{}, false)
		c.ingress(t, l2)
		// Copies 0..2 take slots 0..2; the fourth is slot 3.
		for range 3 {
			c.egress(t, 1, c.uplink, false, l2)
		}
		ret, out := c.egress(t, 1, c.uplink, false, l2)
		if ret != XDP_PASS {
			t.Fatalf("action = %d, want XDP_PASS", ret)
		}
		if len(out) != ethHeaderLen+ipv6HeaderLen+len(l2) || out[ethHeaderLen+6] != 143 {
			t.Fatalf("len %d nexthdr %d, want %d and 143 (Ethernet)", len(out), out[ethHeaderLen+6], ethHeaderLen+ipv6HeaderLen+len(l2))
		}
		if !bytes.Equal(out[ethHeaderLen+ipv6HeaderLen:], l2) {
			t.Error("inner frame changed")
		}
	})

	t.Run("FIB egress differs from the devmap uplink", func(t *testing.T) {
		pinCPU(t)
		// The control plane resolved slot 0's peer to lo; the FIB says
		// uadj-a.
		c.uplinkOf[nh] = 1
		c.ingress(t, l2)
		ret, _ := c.egress(t, 1, 1, false, l2)
		if ret != XDP_DROP {
			t.Fatalf("action = %d, want XDP_DROP", ret)
		}
		if n := statCount(t, c.h.mapOps, "BUM_UPLINK_MISMATCH"); n != 1 {
			t.Errorf("BUM_UPLINK_MISMATCH = %d, want 1", n)
		}
	})
}

// A copy is only sent with a plan that is provably its frame's.
func TestBumRemoteEgressPlanChecks(t *testing.T) {
	c := newEgressCase(t)
	nh := c.nexthop.String()
	l2 := bumFrame(t)
	for i := range uint16(3) {
		c.peer(t, i, vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2, []string{nh, lastSegment(i).String()}, [ESILen]byte{}, false)
	}

	expectDrop := func(t *testing.T, stat string, srcIf uint32, sameBuffer bool, pkt []byte) {
		t.Helper()
		before := statCount(t, c.h.mapOps, stat)
		ret, out := c.egress(t, srcIf, c.uplink, sameBuffer, pkt)
		if ret != XDP_DROP {
			t.Fatalf("action = %d, want XDP_DROP", ret)
		}
		if !bytes.Equal(out[:len(pkt)], pkt) {
			t.Error("a dropped copy must not have been rewritten")
		}
		if n := statCount(t, c.h.mapOps, stat); n != before+1 {
			t.Errorf("%s = %d, want %d", stat, n, before+1)
		}
	}

	t.Run("no plan yet", func(t *testing.T) {
		pinCPU(t)
		expectDrop(t, "BUM_PLAN_STALE", 1, false, l2)
	})
	t.Run("ring entry overwritten by a later frame", func(t *testing.T) {
		pinCPU(t)
		c.ingress(t, l2)
		c.editPlan(t, func(p *BpfBumPlan) { p.Seq += 1024 })
		expectDrop(t, "BUM_PLAN_STALE", 1, false, l2)
	})
	t.Run("copy of a frame from another AC", func(t *testing.T) {
		pinCPU(t)
		c.ingress(t, l2)
		expectDrop(t, "BUM_PLAN_STALE", 4242, false, l2)
	})
	t.Run("copy of a frame of another length", func(t *testing.T) {
		pinCPU(t)
		c.ingress(t, l2)
		expectDrop(t, "BUM_PLAN_STALE", 1, false, append(slices.Clone(l2), 0))
	})
	t.Run("peer deleted after the plan", func(t *testing.T) {
		pinCPU(t)
		c.ingress(t, l2)
		if err := c.h.objs.BdPeerMap.Delete(&BdPeerKey{BdId: bumTestBD, Index: 0}); err != nil {
			t.Fatal(err)
		}
		expectDrop(t, "BUM_EGRESS_DROP", 1, false, l2)
		if ret, _ := c.egress(t, 1, c.uplink, false, l2); ret != XDP_PASS {
			t.Errorf("next copy (slot 1): action = %d, want XDP_PASS", ret)
		}
	})
	t.Run("copies sharing the ingress buffer", func(t *testing.T) {
		pinCPU(t)
		c.peer(t, 0, vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2, []string{nh, lastSegment(0).String()}, [ESILen]byte{}, false)
		c.ingress(t, l2)
		// The first remote copy on the shared buffer is encapsulated; a
		// second would overwrite its headers, so it is dropped.
		if ret, _ := c.egress(t, 1, c.uplink, true, l2); ret != XDP_PASS {
			t.Fatalf("first copy: action = %d, want XDP_PASS", ret)
		}
		expectDrop(t, "BUM_SHARED_BUFFER", 1, true, l2)
		// A copy on a buffer of its own is fine.
		if ret, _ := c.egress(t, 1, c.uplink, false, l2); ret != XDP_PASS {
			t.Errorf("private copy: action = %d, want XDP_PASS", ret)
		}
	})
}

// bumFrame is the VLAN 100 broadcast an AC hands to the devmap.
func bumFrame(t *testing.T) []byte {
	return vlanFrame(t, bcast)
}

// ListLocalDynamicFdb is what the xdp-mode replay and reconciliation read:
// data-plane-learned local MACs only.
func TestListLocalDynamicFdb(t *testing.T) {
	h := newXDPBumHelper(t)
	h.bumAC(1)
	installDevmap(t, h.objs.BumFloodMap)
	h.run(vlanFrame(t, bcast)) // learns 00:..:01 on ifindex 1

	static := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x0a}
	if err := h.objs.FdbMap.Put(buildFdbKey(bumTestBD, static), &FdbEntry{Oif: 1, IsStatic: 1}); err != nil {
		t.Fatal(err)
	}
	managed := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x0b}
	h.createFdbEntry(bumTestBD, managed, 1) // RPC-owned
	remote := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x0c}
	if err := h.objs.FdbMap.Put(buildFdbKey(bumTestBD, remote), &FdbEntry{IsRemote: 1, LastSeen: 1}); err != nil {
		t.Fatal(err)
	}

	got, err := h.mapOps.ListLocalDynamicFdb(bumTestBD)
	if err != nil {
		t.Fatal(err)
	}
	if macs := got[bumTestBD]; len(got) != 1 || len(macs) != 1 || macs[0].String() != "00:00:00:00:00:01" {
		t.Fatalf("ListLocalDynamicFdb = %v, want only the XDP-learned 00:00:00:00:00:01", got)
	}
	if other, _ := h.mapOps.ListLocalDynamicFdb(bumTestBD + 1); len(other) != 0 {
		t.Errorf("a BD filter must exclude other BDs: %v", other)
	}
}

// AgeLocalFdbEntries ages only the local entries of the BDs it is given.
func TestAgeLocalFdbEntries(t *testing.T) {
	h := newXDPBumHelper(t)
	put := func(bd uint16, last byte, remote bool) net.HardwareAddr {
		t.Helper()
		mac := net.HardwareAddr{0x02, 0, 0, 0, 0, last}
		e := &FdbEntry{Oif: 1, LastSeen: 1}
		if remote {
			e.Oif, e.IsRemote = 0, 1
		}
		if err := h.mapOps.CreateFdb(bd, mac, e); err != nil {
			t.Fatal(err)
		}
		return mac
	}
	local := put(bumTestBD, 1, false)
	remote := put(bumTestBD, 2, true)
	other := put(200, 3, false)
	aged, err := h.mapOps.AgeLocalFdbEntries(1e9, func(bd uint16) bool { return bd == bumTestBD }, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(aged) != 1 || aged[0].BDID != bumTestBD || aged[0].MAC.String() != local.String() {
		t.Fatalf("aged = %+v, want only %s in bd %d", aged, local, bumTestBD)
	}
	if _, err := h.mapOps.GetFdb(bumTestBD, remote); err != nil {
		t.Error("remote entry aged out")
	}
	if _, err := h.mapOps.GetFdb(200, other); err != nil {
		t.Error("another BD's entry aged out")
	}
}
