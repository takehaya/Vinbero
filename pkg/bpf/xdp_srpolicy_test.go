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
	newEntry := func(policyID uint32) *HeadendEntry {
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

// policy_id 0 is the headend "no steering" sentinel, so the XDP program never
// looks it up; UpsertSRPolicy must reject it rather than create a dead
// sr_policy_map[0] entry.
func TestUpsertSRPolicyRejectsZeroID(t *testing.T) {
	h := newXDPTestHelper(t)
	if err := h.mapOps.UpsertSRPolicy(0, []netip.Addr{netip.MustParseAddr("fd00:200:0:1::")}); err == nil {
		t.Fatal("UpsertSRPolicy(0, ...) must be rejected (policy_id 0 = no steering)")
	}
}

// TestHighestSRPolicyIDInUse covers the value the id allocator seeds itself
// from after a restart. Both sources must count: sr_policy_map holds the
// installed transports, and the headend maps hold the references, which are
// what make a reassignment mis-steer live traffic.
func TestHighestSRPolicyIDInUse(t *testing.T) {
	const hEncaps = uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS)
	srcAddr, _ := ParseIPv6("fc00::1")
	serviceSID, _ := ParseIPv6("fd00:5fc::1")
	entryWith := func(policyID uint32) *HeadendEntry {
		var segs [MaxSegments][IPv6AddrLen]uint8
		segs[0] = serviceSID
		return &HeadendEntry{
			Mode: hEncaps, NumSegments: 1, PolicyId: policyID,
			SrcAddr: srcAddr, Segments: segs,
		}
	}
	transport := []netip.Addr{netip.MustParseAddr("fd00:7::1")}

	t.Run("empty maps report zero", func(t *testing.T) {
		h := newXDPTestHelper(t)
		got, err := h.mapOps.HighestSRPolicyIDInUse()
		if err != nil {
			t.Fatalf("HighestSRPolicyIDInUse: %v", err)
		}
		if got != 0 {
			t.Errorf("got %d, want 0 on a clean data plane", got)
		}
	})

	t.Run("installed policies count", func(t *testing.T) {
		h := newXDPTestHelper(t)
		for _, id := range []uint32{2, 9, 4} {
			if err := h.mapOps.UpsertSRPolicy(id, transport); err != nil {
				t.Fatalf("UpsertSRPolicy(%d): %v", id, err)
			}
		}
		got, err := h.mapOps.HighestSRPolicyIDInUse()
		if err != nil {
			t.Fatalf("HighestSRPolicyIDInUse: %v", err)
		}
		if got != 9 {
			t.Errorf("got %d, want 9", got)
		}
	})

	t.Run("a reference with no installed policy still counts", func(t *testing.T) {
		// The dangerous case: the policy was withdrawn before the restart but
		// a headend entry still points at its id. Reassigning that id would
		// steer this prefix onto whatever policy takes it next.
		h := newXDPTestHelper(t)
		if err := h.mapOps.CreateHeadendV4("192.0.2.0/24", entryWith(21), OwnerRPC); err != nil {
			t.Fatalf("CreateHeadendV4: %v", err)
		}
		got, err := h.mapOps.HighestSRPolicyIDInUse()
		if err != nil {
			t.Fatalf("HighestSRPolicyIDInUse: %v", err)
		}
		if got != 21 {
			t.Errorf("got %d, want 21 (an unreferenced-but-installed id is not the only hazard)", got)
		}
	})

	t.Run("v6 references count and the maximum wins", func(t *testing.T) {
		h := newXDPTestHelper(t)
		if err := h.mapOps.UpsertSRPolicy(3, transport); err != nil {
			t.Fatalf("UpsertSRPolicy: %v", err)
		}
		if err := h.mapOps.CreateHeadendV4("192.0.2.0/24", entryWith(11), OwnerRPC); err != nil {
			t.Fatalf("CreateHeadendV4: %v", err)
		}
		if err := h.mapOps.CreateHeadendV6("2001:db8::/32", entryWith(37), OwnerRPC); err != nil {
			t.Fatalf("CreateHeadendV6: %v", err)
		}
		got, err := h.mapOps.HighestSRPolicyIDInUse()
		if err != nil {
			t.Fatalf("HighestSRPolicyIDInUse: %v", err)
		}
		if got != 37 {
			t.Errorf("got %d, want 37", got)
		}
	})

	t.Run("unsteered entries do not raise the floor", func(t *testing.T) {
		// policy_id 0 means "not steered"; it must not be mistaken for a
		// reference, or every plain VPN route would inflate the id space.
		h := newXDPTestHelper(t)
		if err := h.mapOps.CreateHeadendV4("192.0.2.0/24", entryWith(0), OwnerRPC); err != nil {
			t.Fatalf("CreateHeadendV4: %v", err)
		}
		got, err := h.mapOps.HighestSRPolicyIDInUse()
		if err != nil {
			t.Fatalf("HighestSRPolicyIDInUse: %v", err)
		}
		if got != 0 {
			t.Errorf("got %d, want 0", got)
		}
	})
}
