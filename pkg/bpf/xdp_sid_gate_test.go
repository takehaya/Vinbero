package bpf

import (
	"encoding/binary"
	"net"
	"testing"
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

	// runSlot runs pkt and returns the action, the output and how many
	// times the endpoint slot of action ran.
	runSlot := func(t *testing.T, pkt []byte, slot uint8) (uint32, []byte, uint64) {
		t.Helper()
		before, err := h.mapOps.ReadSlotStats(MapTypeEndpoint)
		if err != nil {
			t.Fatalf("ReadSlotStats: %v", err)
		}
		ret, out := h.runOnIfindex(pkt, ifidx)
		after, err := h.mapOps.ReadSlotStats(MapTypeEndpoint)
		if err != nil {
			t.Fatalf("ReadSlotStats: %v", err)
		}
		return ret, out, after[slot].Packets - before[slot].Packets
	}

	outerDA := func(pkt []byte, l3 int) net.IP {
		return net.IP(pkt[l3+24 : l3+40])
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
		h.createHeadendEntry("fd00:5a1::/64", srcAddr, dstAddr, segments, numSegments, false)

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

// withVlanTag returns a copy of an untagged Ethernet frame with an 802.1Q
// tag for vlan inserted after the MAC addresses.
func withVlanTag(pkt []byte, vlan uint16) []byte {
	out := make([]byte, 0, len(pkt)+4)
	out = append(out, pkt[:12]...)
	out = binary.BigEndian.AppendUint16(out, 0x8100)
	out = binary.BigEndian.AppendUint16(out, vlan)
	return append(out, pkt[12:]...)
}
