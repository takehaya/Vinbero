package bpf

import (
	"net"
	"net/netip"
	"testing"

	vinberov1 "github.com/takehaya/vinbero/api/vinbero/v1"
)

// TestXDPProgSRPolicyCompose exercises color-based SR Policy steering in the
// headend data plane: a headend entry carrying policy_id != 0 must encap the
// route's service SID composed onto the policy's transport SID list
// (transport ++ service), and fall back to the bare service SID when the
// sr_policy_map lookup misses (policy absent/withdrawn).
func TestXDPProgSRPolicyCompose(t *testing.T) {
	const hEncaps = uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS)

	srcAddr, _ := ParseIPv6("fc00::1")
	serviceSID, _ := ParseIPv6("fd00:5fc::1")
	transport := []netip.Addr{
		netip.MustParseAddr("fd00:7::1"),
		netip.MustParseAddr("fd00:7::2"),
	}

	// headend entry: one service SID, steered via policy_id.
	newEntry := func(policyID uint16) *HeadendEntry {
		var segs [MaxSegments][IPv6AddrLen]uint8
		segs[0] = serviceSID
		return &HeadendEntry{
			Mode:        hEncaps,
			NumSegments: 1,
			PolicyId:    policyID,
			SrcAddr:     srcAddr,
			Segments:    segs,
		}
	}

	pktSrc := net.ParseIP("10.0.0.1").To4()
	pktDst := net.ParseIP("192.0.2.100").To4()

	t.Run("hit composes transport++service", func(t *testing.T) {
		h := newXDPTestHelper(t)
		const policyID = 5
		if err := h.mapOps.CreateHeadendV4("192.0.2.0/24", newEntry(policyID), OwnerRPC); err != nil {
			t.Fatalf("CreateHeadendV4: %v", err)
		}
		if err := h.mapOps.UpsertSRPolicy(policyID, transport); err != nil {
			t.Fatalf("UpsertSRPolicy: %v", err)
		}

		pkt, err := buildSimpleIPv4Packet(pktSrc, pktDst)
		if err != nil {
			t.Fatalf("build packet: %v", err)
		}
		ret, out := h.run(pkt)
		if ret != XDP_PASS {
			t.Fatalf("expected XDP_PASS, got %d", ret)
		}

		// Effective logical segment list: [T1, T2, service]; outer DA = T1.
		var composed [MaxSegments][IPv6AddrLen]uint8
		composed[0] = transport[0].As16()
		composed[1] = transport[1].As16()
		composed[2] = serviceSID
		const n = 3

		if !verifyEtherType(t, out, 0x86DD) {
			return
		}
		if !verifyOuterIPv6Header(t, out, srcAddr, composed[0]) {
			return
		}
		if !verifySRHStructure(t, out, n, convertSegmentsToBytes(composed, n)) {
			return
		}
		if !verifyInnerPacket(t, out, n, pktSrc, pktDst, true) {
			return
		}
	})

	t.Run("miss falls back to bare service SID", func(t *testing.T) {
		h := newXDPTestHelper(t)
		const policyID = 7 // no sr_policy_map entry installed
		if err := h.mapOps.CreateHeadendV4("192.0.2.0/24", newEntry(policyID), OwnerRPC); err != nil {
			t.Fatalf("CreateHeadendV4: %v", err)
		}

		pkt, err := buildSimpleIPv4Packet(pktSrc, pktDst)
		if err != nil {
			t.Fatalf("build packet: %v", err)
		}
		ret, out := h.run(pkt)
		if ret != XDP_PASS {
			t.Fatalf("expected XDP_PASS, got %d", ret)
		}

		// Fallback: single service SID, DA = service SID.
		var single [MaxSegments][IPv6AddrLen]uint8
		single[0] = serviceSID
		if !verifyOuterIPv6Header(t, out, srcAddr, serviceSID) {
			return
		}
		if !verifySRHStructure(t, out, 1, convertSegmentsToBytes(single, 1)) {
			return
		}
		if !verifyInnerPacket(t, out, 1, pktSrc, pktDst, true) {
			return
		}
	})

	t.Run("GetSRPolicy round-trips", func(t *testing.T) {
		h := newXDPTestHelper(t)
		if err := h.mapOps.UpsertSRPolicy(9, transport); err != nil {
			t.Fatalf("UpsertSRPolicy: %v", err)
		}
		got, err := h.mapOps.GetSRPolicy(9)
		if err != nil {
			t.Fatalf("GetSRPolicy: %v", err)
		}
		if len(got) != len(transport) {
			t.Fatalf("GetSRPolicy len = %d, want %d", len(got), len(transport))
		}
		for i := range transport {
			if !got[i].Equal(net.IP(transport[i].AsSlice())) {
				t.Errorf("transport[%d] = %s, want %s", i, got[i], transport[i])
			}
		}
		// Delete -> miss.
		if err := h.mapOps.DeleteSRPolicy(9); err != nil {
			t.Fatalf("DeleteSRPolicy: %v", err)
		}
		if got, _ := h.mapOps.GetSRPolicy(9); got != nil {
			t.Errorf("after delete GetSRPolicy = %v, want nil", got)
		}
	})
}
