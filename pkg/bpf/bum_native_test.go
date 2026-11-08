package bpf

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"github.com/cilium/ebpf"
	vinberov1 "github.com/takehaya/vinbero/api/vinbero/v1"
)

// xdpBumNativeConstants: xdp BUM mode in native XDP (device_mode: driver).
var xdpBumNativeConstants = map[string]any{
	"enable_stats":     uint8(1),
	"bum_xdp_enabled":  uint8(1),
	"bum_mode_default": BumModeXDP,
	"bum_xdp_native":   uint8(1),
}

const bumXDPMetaMarker = uint32(0x564E4258)

// bumMeta builds struct bum_xdp_meta.
func bumMeta(srcIf uint32, seq uint64) []byte {
	m := make([]byte, 16)
	binary.NativeEndian.PutUint32(m[0:4], bumXDPMetaMarker)
	binary.NativeEndian.PutUint32(m[4:8], srcIf)
	binary.NativeEndian.PutUint64(m[8:16], seq)
	return m
}

// runWithMeta runs prog on meta+pkt, the metadata in front of the frame.
func runWithMeta(t *testing.T, prog *ebpf.Program, meta, pkt []byte) (uint32, []byte) {
	t.Helper()
	in := append(append([]byte{}, meta...), pkt...)
	opts := ebpf.RunOptions{
		Data:    in,
		DataOut: make([]byte, 1600),
		Context: xdpMdCtx{Data: uint32(len(meta)), DataEnd: uint32(len(in)), IngressIfindex: 1},
		Repeat:  1,
	}
	ret, err := prog.Run(&opts)
	if err != nil {
		t.Fatalf("test run: %v", err)
	}
	return ret, opts.DataOut
}

// In native XDP the ingress program hands each copy its seq in the
// metadata, and the egress program takes the seq from there (not from the
// CPU's latest plan, which a later frame may have replaced by the time the
// bulk queue is flushed), strips it and encapsulates for the next slot.
func TestBumNativeMetaCarriesSeq(t *testing.T) {
	c := newEgressCaseWithConstants(t, xdpBumNativeConstants)
	c.sync.SetNativeXDP(true)
	nh := c.nexthop.String()
	l2 := bumFrame(t)
	for i := range uint16(2) {
		c.peer(t, i, vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2, []string{nh, lastSegment(i).String()}, [ESILen]byte{}, false)
	}
	if err := c.sync.SyncBD(bumTestBD); err != nil {
		t.Fatal(err)
	}
	var tx devmapVal
	if err := c.h.objs.UplinkTxMap.Lookup(c.uplink, &tx); err != nil || tx.Ifindex != c.uplink || tx.ProgFD == 0 {
		t.Fatalf("uplink_tx_map[%d] = %+v, %v; want the uplink with the egress program", c.uplink, tx, err)
	}

	ret, out := c.h.run(l2)
	if ret != XDP_REDIRECT {
		t.Fatalf("ingress: action = %d, want XDP_REDIRECT", ret)
	}
	seq, _ := c.latestPlan(t)
	if len(out) != 16+len(l2) || !bytes.Equal(out[:16], bumMeta(1, seq)) {
		t.Fatalf("ingress output %x..., want the metadata {marker, lo, seq %d} in front of the frame", out[:min(len(out), 16)], seq)
	}
	meta := out[:16]

	// The test entry takes the egress device from bum_test_params_map; in
	// native mode the source AC comes from the metadata.
	if err := c.h.objs.BumTestParamsMap.Put(uint32(0), &BpfBumTestParams{EgressIfindex: c.uplink}); err != nil {
		t.Fatal(err)
	}

	// A later frame replaces the CPU's latest plan; the first frame's
	// copies still find theirs through the metadata.
	if ret, _ := c.h.run(l2); ret != XDP_REDIRECT {
		t.Fatalf("second ingress: action = %d", ret)
	}
	for i := range uint16(2) {
		ret, out := runWithMeta(t, c.h.objs.BumRemoteEgressTest, meta, l2)
		if ret != XDP_PASS {
			t.Fatalf("copy %d: action = %d, want XDP_PASS", i, ret)
		}
		const hdr = ethHeaderLen + ipv6HeaderLen + srhBaseLen + 2*ipv6AddrLen
		if len(out) != hdr+len(l2) {
			t.Fatalf("copy %d: len %d, want %d (metadata stripped, headers added)", i, len(out), hdr+len(l2))
		}
		srh := out[ethHeaderLen+ipv6HeaderLen:]
		if got := net.IP(srh[8:24]); !got.Equal(lastSegment(i)) {
			t.Errorf("copy %d: SRH[0] = %v, want slot %d's peer", i, got, i)
		}
	}
	if ret, _ := runWithMeta(t, c.h.objs.BumRemoteEgressTest, meta, l2); ret != XDP_DROP {
		t.Errorf("third copy: action = %d, want XDP_DROP (surplus)", ret)
	}

	// Metadata from somewhere else: the source AC does not match the plan.
	if ret, _ := runWithMeta(t, c.h.objs.BumRemoteEgressTest, bumMeta(7, seq+1), l2); ret != XDP_DROP {
		t.Errorf("foreign metadata: action = %d, want XDP_DROP", ret)
	}
	if n := statCount(t, c.h.mapOps, "BUM_PLAN_STALE"); n != 1 {
		t.Errorf("BUM_PLAN_STALE = %d, want 1", n)
	}
}

// A frame without the metadata is a unicast frame redirected through
// uplink_tx_map: the egress program leaves it alone.
func TestBumNativeEgressPassesUnicast(t *testing.T) {
	c := newEgressCaseWithConstants(t, xdpBumNativeConstants)
	pkt := bumFrame(t)
	p := BpfBumTestParams{EgressIfindex: c.uplink}
	if err := c.h.objs.BumTestParamsMap.Put(uint32(0), &p); err != nil {
		t.Fatal(err)
	}
	opts := ebpf.RunOptions{Data: pkt, DataOut: make([]byte, 1600), Repeat: 1}
	ret, err := c.h.objs.BumRemoteEgressTest.Run(&opts)
	if err != nil {
		t.Fatal(err)
	}
	if ret != XDP_PASS || !bytes.Equal(opts.DataOut, pkt) {
		t.Fatalf("action = %d, frame changed = %v; want XDP_PASS and the frame untouched", ret, !bytes.Equal(opts.DataOut, pkt))
	}
}

// vinbero_main drops the metadata a frame arrives with, so none of it can
// reach the egress program as if it were this host's.
func TestBumNativeIngressClearsMeta(t *testing.T) {
	h := newXDPTestHelperWithConstants(t, xdpBumNativeConstants)
	// Not IP, not VLAN-tagged: XDP_PASS to the stack.
	pkt := append(append(append([]byte{}, bcast...), 0x02, 0, 0, 0, 0, 0x01, 0x88, 0xb5), make([]byte, 46)...)
	ret, out := runWithMeta(t, h.objs.VinberoMain, bumMeta(1, 0), pkt)
	if ret != XDP_PASS {
		t.Fatalf("action = %d, want XDP_PASS", ret)
	}
	if !bytes.Equal(out, pkt) {
		t.Fatalf("output %d bytes, want the %d-byte frame without metadata", len(out), len(pkt))
	}
}

// In native XDP a device cannot be both an uplink and a local AC of an
// xdp-mode BD. Making an uplink an AC of another BD rebuilds every BD: the
// slot through it leaves its devmap and the device leaves uplink_tx_map.
func TestBumNativeUplinkBecomesAC(t *testing.T) {
	h := newXDPTestHelperWithConstants(t, xdpBumNativeConstants)
	up := dummyIfindex(t, "bumnat-up")
	s := NewBumDevmapSync(h.objs, func(uint16) uint8 { return BumModeXDP },
		func([IPv6AddrLen]byte) (BumUplink, error) { return BumUplink{Ifindex: up}, nil }, nil)
	s.SetNativeXDP(true)
	h.mapOps.SetBumDevmapSync(s)
	t.Cleanup(func() { h.mapOps.SetBumDevmapSync(nil) })

	h.bumAC(1)
	src, _ := ParseIPv6("fc00::1")
	segs, n, _ := ParseSegments([]string{"fc00::200"})
	if err := h.mapOps.CreateBdPeer(bumTestBD, 0, &HeadendEntry{
		Mode: uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2), NumSegments: n,
		SrcAddr: src, Segments: segs,
	}, [ESILen]byte{}, [IPv6AddrLen]byte{}, false); err != nil {
		t.Fatal(err)
	}
	if _, ok := devmapEntries(t, h.objs.BumFloodMap, bumTestBD)[BumSlotKeyBase]; !ok {
		t.Fatal("slot 0 missing from the flood devmap")
	}
	var v devmapVal
	if err := h.objs.UplinkTxMap.Lookup(up, &v); err != nil {
		t.Fatalf("uplink not in uplink_tx_map: %v", err)
	}

	// The uplink becomes an AC of another xdp-mode BD.
	if err := h.mapOps.CreateHeadendL2(up, 0, &HeadendEntry{
		Mode: uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2), NumSegments: n,
		SrcAddr: src, Segments: segs, BdId: 999,
	}, [ESILen]byte{}); err != nil {
		t.Fatal(err)
	}
	if _, ok := devmapEntries(t, h.objs.BumFloodMap, bumTestBD)[BumSlotKeyBase]; ok {
		t.Error("slot 0 still sends through a device that is now an AC")
	}
	if err := h.objs.UplinkTxMap.Lookup(up, &v); err == nil {
		t.Error("the AC's device is still in uplink_tx_map")
	}

	// Once it is no AC any more, the slot comes back.
	if err := h.mapOps.DeleteHeadendL2(up, 0); err != nil {
		t.Fatal(err)
	}
	if _, ok := devmapEntries(t, h.objs.BumFloodMap, bumTestBD)[BumSlotKeyBase]; !ok {
		t.Error("slot 0 did not come back")
	}
	if err := h.objs.UplinkTxMap.Lookup(up, &v); err != nil {
		t.Errorf("uplink not back in uplink_tx_map: %v", err)
	}
}
