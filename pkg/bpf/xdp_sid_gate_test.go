package bpf

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"github.com/cilium/ebpf"
	vinberov1 "github.com/takehaya/vinbero/api/vinbero/v1"
)

// TestXDPProgSIDGateTenantIngress checks that only a packet from the global
// VRF (vrf_id 0) reaches a local SID. The same SID-destined packet is run
// from an ingress the front door leaves in vrf 0 and from an AC classified
// to a tenant VRF; the tenant copy must not run the SID's behaviour (its
// endpoint slot counter stays put and the packet is not rewritten) and
// goes on to the headend lookup instead.
func TestXDPProgSIDGateTenantIngress(t *testing.T) {
	h := newXDPTestHelperWithStats(t)
	const ifidx = 1 // loopback; BPF_PROG_TEST_RUN backs the buffer with it
	const tenantVlan = 100

	const endSID = "fd00:5a1::1"
	const dt4SID = "fd00:5a1::4"
	h.createSidFunction(endSID+"/128", actionEnd)
	h.createSidFunctionWithVRF(dt4SID+"/128", actionEndDT4, 0)

	// End with an SRH (the localsid stage): processing moves the DA to the
	// next segment.
	const nextSeg = "fd00:5a1::99"
	endPkt, err := buildSRv6Packet(net.ParseIP("fd00:1::1"), net.ParseIP(endSID),
		[]net.IP{net.ParseIP(nextSeg), net.ParseIP(endSID)}, 1)
	if err != nil {
		t.Fatalf("build End packet: %v", err)
	}
	// End.DT4 without an SRH (the reduced-encap stage).
	dt4Pkt, err := buildEncapsulatedPacketNoSRH(net.ParseIP("fd00:1::1"), net.ParseIP(dt4SID),
		net.ParseIP("10.0.0.1").To4(), net.ParseIP("192.0.2.100").To4(), innerTypeIPv4)
	if err != nil {
		t.Fatalf("build End.DT4 packet: %v", err)
	}

	if err := h.mapOps.SetIngressPolicy(true, false, 0); err != nil {
		t.Fatalf("SetIngressPolicy: %v", err)
	}
	setAC := func(t *testing.T, vlan uint16, vrfID uint32) {
		t.Helper()
		if err := h.mapOps.SetIngressVrf(map[IngressACKey]uint32{{Ifindex: ifidx, VlanId: vlan}: vrfID}); err != nil {
			t.Fatalf("SetIngressVrf: %v", err)
		}
	}

	runSlot := func(t *testing.T, pkt []byte, slot uint8) (uint32, []byte, uint64) {
		t.Helper()
		return h.runCountingSlot(t, pkt, ifidx, slot)
	}

	for _, tc := range []struct {
		name string
		vlan uint16
		vrf  uint32
	}{
		{"untagged AC in vrf 0", 0, 0},
		{"tagged AC in vrf 0", tenantVlan, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setAC(t, tc.vlan, tc.vrf)
			l3 := ethHeaderLen
			end, dt4 := endPkt, dt4Pkt
			if tc.vlan != 0 {
				l3 += 4
				end, dt4 = withVlanTag(endPkt, tc.vlan), withVlanTag(dt4Pkt, tc.vlan)
			}

			ret, out, runs := runSlot(t, end, actionEnd)
			if runs != 1 {
				t.Errorf("End: slot ran %d times, want 1", runs)
			}
			if ret != XDP_PASS {
				t.Errorf("End: ret = %d, want XDP_PASS", ret)
			}
			if got := outerDA(out, l3); !got.Equal(net.ParseIP(nextSeg)) {
				t.Errorf("End: DA = %s, want %s", got, nextSeg)
			}

			if _, _, runs := runSlot(t, dt4, actionEndDT4); runs != 1 {
				t.Errorf("End.DT4: slot ran %d times, want 1", runs)
			}
		})
	}

	for _, tc := range []struct {
		name string
		vlan uint16
	}{
		{"untagged AC in a tenant VRF", 0},
		{"tagged AC in a tenant VRF", tenantVlan},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setAC(t, tc.vlan, 1)
			l3 := ethHeaderLen
			end, dt4 := endPkt, dt4Pkt
			if tc.vlan != 0 {
				l3 += 4
				end, dt4 = withVlanTag(endPkt, tc.vlan), withVlanTag(dt4Pkt, tc.vlan)
			}

			ret, out, runs := runSlot(t, end, actionEnd)
			if runs != 0 {
				t.Errorf("End: slot ran %d times, want 0", runs)
			}
			if ret != XDP_PASS {
				t.Errorf("End: ret = %d, want XDP_PASS", ret)
			}
			if got := outerDA(out, l3); !got.Equal(net.ParseIP(endSID)) {
				t.Errorf("End: DA = %s, want it unchanged (%s)", got, endSID)
			}

			ret, out, runs = runSlot(t, dt4, actionEndDT4)
			if runs != 0 {
				t.Errorf("End.DT4: slot ran %d times, want 0", runs)
			}
			if ret != XDP_PASS {
				t.Errorf("End.DT4: ret = %d, want XDP_PASS", ret)
			}
			if len(out) != len(dt4) {
				t.Errorf("End.DT4: output is %d bytes, want the %d-byte input untouched", len(out), len(dt4))
			}
		})
	}

	// The tenant packet continues to the headend lookup as if its
	// destination were not a local SID.
	t.Run("tenant packet to a SID goes to the headend", func(t *testing.T) {
		srcAddr, _ := ParseIPv6("fc00::1")
		dstAddr, _ := ParseIPv6("fc00::100")
		segments, numSegments, _ := ParseSegments([]string{"fc00::200"})
		// In the tenant's VRF, where its packet is looked up, and in vrf 0.
		h.headendVRFs = []uint32{0, 1}
		h.createHeadendEntry("fd00:5a1::/64", srcAddr, dstAddr, segments, numSegments, false)
		h.headendVRFs = nil

		setAC(t, 0, 1)
		ret, out, runs := runSlot(t, dt4Pkt, actionEndDT4)
		if runs != 0 {
			t.Errorf("tenant: End.DT4 slot ran %d times, want 0", runs)
		}
		if ret != XDP_PASS {
			t.Errorf("tenant: ret = %d, want XDP_PASS", ret)
		}
		if got := outerDA(out, ethHeaderLen); !got.Equal(net.IP(segments[0][:])) {
			t.Errorf("tenant: outer DA = %s, want the headend segment %s", got, net.IP(segments[0][:]))
		}

		// From vrf 0 the SID still wins over the covering headend prefix.
		setAC(t, 0, 0)
		if _, _, runs := runSlot(t, dt4Pkt, actionEndDT4); runs != 1 {
			t.Errorf("vrf 0: End.DT4 slot ran %d times, want 1", runs)
		}
	})
}

// TestXDPProgIngressVrfUnknownTag checks how the front door classifies a
// tagged frame whose {ifindex, vlan} has no AC. On a port whose untagged
// side is a tenant AC the frame is never vrf 0: only a service-return or
// L2 headend circuit configured for that {ifindex, vlan} may take it, and
// without one it is dropped before L3. Otherwise a host on that AC could
// add an unused tag, land in vrf 0 and reach a local SID. A trunk whose
// untagged side is underlay keeps the plain miss behaviour (vrf 0). In
// every case where the frame is not vrf 0 the SID must not run.
func TestXDPProgIngressVrfUnknownTag(t *testing.T) {
	h := newXDPTestHelperWithStats(t)
	const ifidx = 1
	const vlan = 5 // no AC for VLAN 5 in any case below
	const endSID = "fd00:5a2::1"
	const nextSeg = "fd00:5a2::99"
	h.createSidFunction(endSID+"/128", actionEnd)
	pkt, err := buildSRv6Packet(net.ParseIP("fd00:1::1"), net.ParseIP(endSID),
		[]net.IP{net.ParseIP(nextSeg), net.ParseIP(endSID)}, 1)
	if err != nil {
		t.Fatalf("build End packet: %v", err)
	}
	tagged := withVlanTag(pkt, vlan)

	if err := h.mapOps.SetIngressPolicy(true, false, 0); err != nil {
		t.Fatalf("SetIngressPolicy: %v", err)
	}

	srcAddr, _ := ParseIPv6("fc00::1")
	segments, numSegments, _ := ParseSegments([]string{"fc00::200"})
	l2Mode := uint32(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2)
	addL2 := func(t *testing.T) {
		h.createHeadendL2Entry(ifidx, vlan, srcAddr, segments, numSegments, 0)
		t.Cleanup(func() { _ = h.mapOps.DeleteHeadendL2(ifidx, vlan) })
	}
	addSvc := func(t *testing.T) {
		if _, err := h.mapOps.CreateServiceIngress(ifidx, vlan, &ServiceIngressEntry{
			Behavior: SvcRetAS, InnerTypeMask: SvcInnerIPv6,
			Encap: HeadendEntry{Mode: modeHEncaps, NumSegments: numSegments, SrcAddr: srcAddr, Segments: segments},
		}); err != nil {
			t.Fatalf("create service ingress: %v", err)
		}
		t.Cleanup(func() { _ = h.mapOps.DeleteServiceIngress(ifidx, vlan) })
	}
	tenantPort := map[IngressACKey]uint32{{Ifindex: ifidx, VlanId: 0}: 1}

	for _, tc := range []struct {
		name    string
		acs     map[IngressACKey]uint32
		circuit func(*testing.T)
		wantRet uint32 // checked when the frame is not taken by a circuit
		wantRun uint64
		wantL2  uint64
		wantSvc uint64
	}{
		{name: "tenant port, no circuit: dropped", acs: tenantPort, wantRet: XDP_DROP},
		{name: "tenant port, L2 headend circuit: taken by L2", acs: tenantPort, circuit: addL2, wantL2: 1},
		{name: "tenant port, service-return circuit: taken by service return", acs: tenantPort, circuit: addSvc, wantSvc: 1},
		{name: "untagged side is explicitly global", acs: map[IngressACKey]uint32{{Ifindex: ifidx, VlanId: 0}: 0, {Ifindex: ifidx, VlanId: 100}: 1}, wantRet: XDP_PASS, wantRun: 1},
		{name: "untagged side has no AC", acs: map[IngressACKey]uint32{{Ifindex: ifidx, VlanId: 100}: 1}, wantRet: XDP_PASS, wantRun: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := h.mapOps.SetIngressVrf(tc.acs); err != nil {
				t.Fatalf("SetIngressVrf: %v", err)
			}
			if tc.circuit != nil {
				tc.circuit(t)
			}
			l2Before := slotStatPackets(t, h.mapOps, MapTypeHeadendL2, l2Mode)
			svcBefore := slotStatPackets(t, h.mapOps, MapTypeServiceReturn, SvcRetAS)
			ret, out, runs := h.runCountingSlot(t, tagged, ifidx, actionEnd)
			l2 := slotStatPackets(t, h.mapOps, MapTypeHeadendL2, l2Mode) - l2Before
			svc := slotStatPackets(t, h.mapOps, MapTypeServiceReturn, SvcRetAS) - svcBefore

			if runs != tc.wantRun {
				t.Errorf("End slot ran %d times, want %d", runs, tc.wantRun)
			}
			if l2 != tc.wantL2 {
				t.Errorf("L2 headend slot ran %d times, want %d", l2, tc.wantL2)
			}
			if svc != tc.wantSvc {
				t.Errorf("service-return slot ran %d times, want %d", svc, tc.wantSvc)
			}
			if tc.circuit == nil && ret != tc.wantRet {
				t.Errorf("ret = %d, want %d", ret, tc.wantRet)
			}
			if tc.wantRun == 1 {
				if got := outerDA(out, ethHeaderLen+4); !got.Equal(net.ParseIP(nextSeg)) {
					t.Errorf("DA = %s, want %s", got, nextSeg)
				}
			}
		})
	}
}

// TestXDPProgEndpointRefusesTenantContext runs the built-in End program
// directly, the way a plugin's bpf_tail_call into sid_endpoint_progs would
// reach it, with the per-CPU context carrying a tenant vrf_id. End must not
// run (it would rewrite the DA); with vrf 0 it does. Every built-in endpoint
// reads its context through the same helper.
func TestXDPProgEndpointRefusesTenantContext(t *testing.T) {
	h := newXDPTestHelper(t)
	const sid = "fd00:5a3::1"
	const nextSeg = "fd00:5a3::99"
	pkt, err := buildSRv6PacketWithInnerIPv4(net.ParseIP("fd00:1::1"), net.ParseIP(sid),
		[]net.IP{net.ParseIP(nextSeg), net.ParseIP(sid)}, 1,
		net.ParseIP("10.0.0.1").To4(), net.ParseIP("192.0.2.100").To4())
	if err != nil {
		t.Fatalf("build packet: %v", err)
	}

	setCtx := func(t *testing.T, vrfID uint32, action uint8) {
		t.Helper()
		cpus, err := ebpf.PossibleCPU()
		if err != nil {
			t.Fatal(err)
		}
		contexts := make([]BpfTailcallCtx, cpus)
		for i := range contexts {
			contexts[i] = BpfTailcallCtx{
				L3Offset: ethHeaderLen, Slot: action, VrfId: vrfID,
				SidEntry: SidFunctionEntry{Action: action},
			}
		}
		if err := h.objs.TailcallCtxMap.Update(uint32(0), contexts, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("End from a tenant context", func(t *testing.T) {
		setCtx(t, 1, actionEnd)
		ret, out, err := h.objs.TailcallEndpointEnd.Test(pkt)
		if err != nil {
			t.Fatal(err)
		}
		if ret != XDP_DROP {
			t.Errorf("ret = %d, want XDP_DROP", ret)
		}
		if !bytes.Equal(out, pkt) {
			t.Errorf("packet was modified (DA %s)", outerDA(out, ethHeaderLen))
		}
	})

	t.Run("End from the global VRF", func(t *testing.T) {
		setCtx(t, 0, actionEnd)
		_, out, err := h.objs.TailcallEndpointEnd.Test(pkt)
		if err != nil {
			t.Fatal(err)
		}
		if got := outerDA(out, ethHeaderLen); !got.Equal(net.ParseIP(nextSeg)) {
			t.Errorf("DA = %s, want %s", got, nextSeg)
		}
	})
}

// runCountingSlot runs pkt on ifindex and returns the action, the output
// and how many times endpoint slot slot ran.
func (h *xdpTestHelper) runCountingSlot(t *testing.T, pkt []byte, ifindex uint32, slot uint8) (uint32, []byte, uint64) {
	t.Helper()
	before := slotStatPackets(t, h.mapOps, MapTypeEndpoint, uint32(slot))
	ret, out := h.runOnIfindex(pkt, ifindex)
	return ret, out, slotStatPackets(t, h.mapOps, MapTypeEndpoint, uint32(slot)) - before
}

// outerDA is the IPv6 destination of the frame whose IPv6 header starts at l3.
func outerDA(pkt []byte, l3 int) net.IP {
	return net.IP(pkt[l3+24 : l3+40])
}

// withVlanTag returns a copy of an untagged Ethernet frame with an 802.1Q
// tag for vlan inserted after the MAC addresses.
func withVlanTag(pkt []byte, vlan uint16) []byte {
	out := make([]byte, 0, len(pkt)+4)
	out = append(out, pkt[:12]...)
	out = binary.BigEndian.AppendUint16(out, 0x8100)
	out = binary.BigEndian.AppendUint16(out, vlan)
	return append(out, pkt[12:]...)
}
