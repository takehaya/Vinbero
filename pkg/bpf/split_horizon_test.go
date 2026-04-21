package bpf

import (
	"net"
	"testing"

	vinberov1 "github.com/takehaya/vinbero/api/vinbero/v1"
)

// TestXDPProgEndDT2MSplitHorizonRX verifies that End.DT2M drops a BUM frame
// whose outer source IPv6 belongs to a peer sharing a local ESI.
// Control: same packet with a peer in ESI_B (not local-attached) is forwarded.
func TestXDPProgEndDT2MSplitHorizonRX(t *testing.T) {
	esiA, _ := ParseESI("aa:aa:aa:aa:aa:aa:aa:aa:aa:01") // local ES
	esiB, _ := ParseESI("bb:bb:bb:bb:bb:bb:bb:bb:bb:01") // remote-only ES

	tests := []struct {
		name         string
		peerEsi      [ESILen]byte
		expectAction uint32
	}{
		{"same ES as local → drop", esiA, XDP_DROP},
		{"different ES → forward (PASS: no bridge)", esiB, XDP_PASS},
		{"peer single-homing (zero ESI) → forward", [ESILen]byte{}, XDP_PASS},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newXDPTestHelper(t)
			triggerSID := "fd00:1:100::10/128"
			bdID := uint16(100)

			h.createSidFunctionWithBD(triggerSID, actionEndDT2M, bdID)

			// Register local ES
			if err := h.mapOps.CreateEsi(esiA, NewEsiEntry(EsiConfig{LocalAttached: true})); err != nil {
				t.Fatalf("CreateEsi: %v", err)
			}

			// Register the peer (fd00:1:1::1) with the case's ESI
			peerSrc, _ := ParseIPv6("fd00:1:1::1")
			peerEntry := &HeadendEntry{
		Mode:        uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2),
		NumSegments: 1,
		SrcAddr:     peerSrc,
	}
			if err := h.mapOps.CreateBdPeer(bdID, 0, peerEntry, tc.peerEsi); err != nil {
				t.Fatalf("CreateBdPeer: %v", err)
			}

			pkt, err := buildL2EncapsulatedPacket(
				net.ParseIP("fd00:1:1::1"), net.ParseIP("fd00:1:100::10"),
				[]net.IP{net.ParseIP("fd00:1:100::10")}, 0,
				100, net.ParseIP("10.0.0.1"), net.ParseIP("192.0.2.100"), true,
			)
			if err != nil {
				t.Fatalf("buildL2EncapsulatedPacket: %v", err)
			}

			ret, _ := h.run(pkt)
			if ret != tc.expectAction {
				t.Errorf("expected action %d, got %d", tc.expectAction, ret)
			}
		})
	}
}

// TestXDPProgEndDT2MNonDFDrop verifies that BUM arriving from a remote PE on
// a different ES is accepted only when this PE is the Designated Forwarder
// for the BD's local ES.
func TestXDPProgEndDT2MNonDFDrop(t *testing.T) {
	localESI, _ := ParseESI("aa:aa:aa:aa:aa:aa:aa:aa:aa:01")
	senderESI, _ := ParseESI("cc:cc:cc:cc:cc:cc:cc:cc:cc:01")
	localPE, err := ParseIPv6("fd00:a::1")
	if err != nil {
		t.Fatalf("ParseIPv6 localPE: %v", err)
	}
	otherPE, err := ParseIPv6("fd00:b::1")
	if err != nil {
		t.Fatalf("ParseIPv6 otherPE: %v", err)
	}

	tests := []struct {
		name         string
		dfPE         [16]byte // all-zero = unset
		expectAction uint32
	}{
		{"DF unset → forward (fail-open)", [16]byte{}, XDP_PASS},
		{"this PE is DF → forward", localPE, XDP_PASS},
		{"this PE is non-DF → drop", otherPE, XDP_DROP},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newXDPTestHelperWithStats(t)

			h.createSidFunctionWithBD("fd00:1:100::10/128", actionEndDT2M, 100)
			if err := h.mapOps.CreateEsi(localESI, NewEsiEntry(EsiConfig{
				LocalAttached:  true,
				LocalPeSrcAddr: localPE,
				DfPeSrcAddr:    tc.dfPE,
			})); err != nil {
				t.Fatalf("CreateEsi local: %v", err)
			}
			// A local HeadendL2 (with ESI + bd_id) populates bd_local_esi_map
			// for the DF lookup.
			hl2 := &HeadendEntry{
				Mode:        uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2),
				NumSegments: 1,
				SrcAddr:     localPE,
				BdId:        100,
			}
			if err := h.mapOps.CreateHeadendL2(1, 100, hl2, localESI); err != nil {
				t.Fatalf("CreateHeadendL2: %v", err)
			}

			// Sender is on a DIFFERENT ES to isolate the DF check from split-horizon.
			peerSrc, _ := ParseIPv6("fd00:1:1::1")
			peerEntry := &HeadendEntry{
				Mode:        uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2),
				NumSegments: 1,
				SrcAddr:     peerSrc,
			}
			if err := h.mapOps.CreateBdPeer(100, 0, peerEntry, senderESI); err != nil {
				t.Fatalf("CreateBdPeer: %v", err)
			}

			pkt, err := buildL2EncapsulatedPacket(
				net.ParseIP("fd00:1:1::1"), net.ParseIP("fd00:1:100::10"),
				[]net.IP{net.ParseIP("fd00:1:100::10")}, 0,
				100, net.ParseIP("10.0.0.1"), net.ParseIP("192.0.2.100"), true,
			)
			if err != nil {
				t.Fatalf("buildL2EncapsulatedPacket: %v", err)
			}

			ret, _ := h.run(pkt)
			if ret != tc.expectAction {
				t.Errorf("expected action %d, got %d", tc.expectAction, ret)
			}
		})
	}
}

// TestXDPProgEndDT2SplitHorizonUnaffected verifies End.DT2 (DT2U) is NOT
// affected by split-horizon: same ESI peer still reaches FDB forwarding.
// DT2U is explicit unicast lookup; split-horizon only applies to DT2M.
func TestXDPProgEndDT2SplitHorizonUnaffected(t *testing.T) {
	h := newXDPTestHelper(t)
	esi, _ := ParseESI("aa:aa:aa:aa:aa:aa:aa:aa:aa:01")

	h.createSidFunctionWithBD("fd00:1:100::10/128", actionEndDT2, 100)
	if err := h.mapOps.CreateEsi(esi, NewEsiEntry(EsiConfig{LocalAttached: true})); err != nil {
		t.Fatalf("CreateEsi: %v", err)
	}
	peerSrc, _ := ParseIPv6("fd00:1:1::1")
	peerEntry := &HeadendEntry{
		Mode:        uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2),
		NumSegments: 1,
		SrcAddr:     peerSrc,
	}
	if err := h.mapOps.CreateBdPeer(100, 0, peerEntry, esi); err != nil {
		t.Fatalf("CreateBdPeer: %v", err)
	}
	// Prime FDB so DT2U hits
	h.createFdbEntry(100, net.HardwareAddr{0, 0, 0, 0, 0, 2}, 1)

	pkt, err := buildL2EncapsulatedPacket(
		net.ParseIP("fd00:1:1::1"), net.ParseIP("fd00:1:100::10"),
		[]net.IP{net.ParseIP("fd00:1:100::10")}, 0,
		100, net.ParseIP("10.0.0.1"), net.ParseIP("192.0.2.100"), true,
	)
	if err != nil {
		t.Fatalf("buildL2EncapsulatedPacket: %v", err)
	}

	ret, _ := h.run(pkt)
	if ret != XDP_REDIRECT {
		t.Errorf("expected DT2 to redirect (split-horizon must not apply to DT2U), got %d", ret)
	}
}
