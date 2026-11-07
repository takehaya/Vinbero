package bpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	vinberov1 "github.com/takehaya/vinbero/api/vinbero/v1"
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
		if n := statCount(t, h.mapOps, "BUM_XDP_FALLBACK"); n != 1 {
			t.Errorf("BUM_XDP_FALLBACK = %d, want 1", n)
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

// ===== devmap egress program (through its BPF_PROG_TEST_RUN entry) =====

type egressCase struct {
	h       *xdpTestHelper
	nexthop net.IP
	uplink  uint32
}

// newEgressCase sets up the adjacency the FIB lookup resolves through and
// an AC on lo (vlan 100) in bumTestBD.
func newEgressCase(t *testing.T) *egressCase {
	t.Helper()
	h := newXDPBumHelper(t)
	nexthop, _ := adjacencyEnv(t)
	link, err := net.InterfaceByName("uadj-a")
	if err != nil {
		t.Fatal(err)
	}
	h.bumAC(1)
	return &egressCase{h: h, nexthop: nexthop, uplink: uint32(link.Index)}
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

func (c *egressCase) run(t *testing.T, slot, srcIf, egressIf uint32, pkt []byte) (uint32, []byte) {
	t.Helper()
	p := BpfBumTestParams{Slot: slot, SrcIfindex: srcIf, EgressIfindex: egressIf}
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

func TestBumRemoteEgressEncap(t *testing.T) {
	c := newEgressCase(t)
	nh := c.nexthop.String()
	l2 := bumFrame(t)

	// Slots 0..7, each its own peer (distinct last segment), all behind the
	// one uplink: every slot must build its own peer's headers.
	for i := range uint16(MaxBumNexthops) {
		last := net.IP{0xfc, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, byte(i)}
		c.peer(t, i, vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2, []string{nh, last.String()}, [ESILen]byte{}, false)
	}
	for i := range uint32(MaxBumNexthops) {
		ret, out := c.run(t, i, 1, c.uplink, l2)
		if ret != XDP_PASS {
			t.Fatalf("slot %d: action = %d, want XDP_PASS (devmap transmit)", i, ret)
		}
		const hdr = ethHeaderLen + ipv6HeaderLen + srhBaseLen + 2*ipv6AddrLen
		if len(out) != hdr+len(l2) {
			t.Fatalf("slot %d: len %d, want %d", i, len(out), hdr+len(l2))
		}
		if binary.BigEndian.Uint16(out[12:14]) != 0x86dd {
			t.Fatalf("slot %d: outer ethertype %#x", i, out[12:14])
		}
		ip6 := out[ethHeaderLen:]
		if got := net.IP(ip6[24:40]); !got.Equal(c.nexthop) {
			t.Errorf("slot %d: outer DA %v, want segments[0] %v", i, got, c.nexthop)
		}
		srh := ip6[ipv6HeaderLen:]
		if srh[0] != 143 || srh[2] != 4 || srh[3] != 1 || srh[4] != 1 {
			t.Errorf("slot %d: SRH nh=%d type=%d SL=%d LE=%d, want 143/4/1/1", i, srh[0], srh[2], srh[3], srh[4])
		}
		// SRH segment list is reversed: [0] is the last segment.
		if got := net.IP(srh[8:24]); got[15] != byte(i) || got[14] != 0x10 {
			t.Errorf("slot %d: SRH[0] = %v, want the slot's own peer", i, got)
		}
		if !bytes.Equal(out[hdr:], l2) {
			t.Errorf("slot %d: inner frame changed", i)
		}
	}
	if n := statCount(t, c.h.mapOps, "BUM_EGRESS_TX"); n != MaxBumNexthops {
		t.Errorf("BUM_EGRESS_TX = %d, want %d", n, MaxBumNexthops)
	}

	t.Run("reduced, one segment: no SRH", func(t *testing.T) {
		c.peer(t, 3, vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2_RED, []string{nh}, [ESILen]byte{}, false)
		ret, out := c.run(t, 3, 1, c.uplink, l2)
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
		ret, _ := c.run(t, 0, 1, c.uplink+1000, l2)
		if ret != XDP_DROP {
			t.Fatalf("action = %d, want XDP_DROP", ret)
		}
		if n := statCount(t, c.h.mapOps, "BUM_UPLINK_MISMATCH"); n != 1 {
			t.Errorf("BUM_UPLINK_MISMATCH = %d, want 1", n)
		}
	})
}

func TestBumRemoteEgressDrops(t *testing.T) {
	c := newEgressCase(t)
	nh := c.nexthop.String()
	l2 := bumFrame(t)
	esi, _ := ParseESI("01:00:00:00:00:00:00:00:00:01")

	c.peer(t, 0, vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2, []string{nh}, [ESILen]byte{}, true) // RT2 unicast peer
	c.peer(t, 1, vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2, []string{nh}, esi, false)            // same ES as the AC
	// The AC on lo carries the ESI too.
	src, _ := ParseIPv6("fc00::1")
	segs, n, _ := ParseSegments([]string{"fc00::200"})
	if err := c.h.mapOps.CreateHeadendL2(1, 100, &HeadendEntry{
		Mode: uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2), NumSegments: n,
		SrcAddr: src, Segments: segs, BdId: bumTestBD,
	}, esi); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		slot  uint32
		srcIf uint32
		stat  string
	}{
		{"flood_exclude peer", 0, 1, "BUM_EGRESS_DROP"},
		{"split horizon (same ES)", 1, 1, "SPLIT_HORIZON_TX"},
		{"empty slot", 5, 1, "BUM_EGRESS_DROP"},
		{"source is not an AC", 1, 4242, "BUM_EGRESS_DROP"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := statCount(t, c.h.mapOps, tc.stat)
			ret, out := c.run(t, tc.slot, tc.srcIf, c.uplink, l2)
			if ret != XDP_DROP {
				t.Fatalf("action = %d, want XDP_DROP", ret)
			}
			if !bytes.Equal(out[:len(l2)], l2) {
				t.Error("a dropped copy must not have been rewritten")
			}
			if n := statCount(t, c.h.mapOps, tc.stat); n != before+1 {
				t.Errorf("%s = %d, want %d", tc.stat, n, before+1)
			}
		})
	}
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
