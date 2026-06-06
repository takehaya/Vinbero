package apply

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"go.uber.org/zap"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

func newMUPApplier(t *testing.T, fh *fakeHeadend) *Applier {
	t.Helper()
	return NewApplier(fh, testLocatorManager(t), vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop())
}

// T1ST installs a downlink H.Encaps headend on the UE prefix whose destination
// SID carries Args.Mob.Session(gNB endpoint, TEID, QFI) at offset 7.
func TestApplyMUP_T1ST_Downlink(t *testing.T) {
	fh := newFakeHeadend()
	a := newMUPApplier(t, fh)

	const (
		uePrefix = "10.0.0.1/32"
		gnb      = "203.0.113.5"
		base     = "fd00:2:2:b::" // remote interwork segment locator:function
		teid     = uint32(0x12345678)
		qfi      = uint8(9)
	)
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyMUPIPv4, MUP: &bgp.MUPRoute{
		Type: bgp.MUPRouteTypeT1ST, RD: "65000:100",
		Prefix: uePrefix, Endpoint: gnb, TEID: teid, TEIDLen: 32, QFI: qfi,
		SRv6SID: base,
	}})

	entry, ok := fh.v4created[uePrefix]
	if !ok {
		t.Fatalf("CreateHeadendV4 not called for UE prefix; v4created=%v", fh.v4created)
	}
	if entry.Mode != uint8(v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS) {
		t.Errorf("mode = %d, want H_ENCAPS", entry.Mode)
	}
	// Args.Mob.Session at offset 7 in the destination SID.
	da := entry.DstAddr
	const off = mupDefaultArgsOffset
	if got := netip.AddrFrom4([4]byte(da[off : off+4])); got != netip.MustParseAddr(gnb) {
		t.Errorf("gNB in SID = %s, want %s", got, gnb)
	}
	if got := binary.BigEndian.Uint32(da[off+4 : off+8]); got != teid {
		t.Errorf("TEID in SID = 0x%08X, want 0x%08X", got, teid)
	}
	if got := da[off+8] & 0x3F; got != qfi {
		t.Errorf("QFI in SID = %d, want %d", got, qfi)
	}
	// Locator:function (bytes before the args window) preserved from base.
	wantBase := netip.MustParseAddr(base).As16()
	for i := 0; i < off; i++ {
		if da[i] != wantBase[i] {
			t.Errorf("SID byte %d = 0x%02X, want base 0x%02X", i, da[i], wantBase[i])
		}
	}

	// Withdraw removes the headend.
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyMUPIPv4, IsWithdraw: true, MUP: &bgp.MUPRoute{
		Type: bgp.MUPRouteTypeT1ST, RD: "65000:100", Prefix: uePrefix, Endpoint: gnb, TEID: teid, TEIDLen: 32, SRv6SID: base,
	}})
	if len(fh.v4deleted) != 1 || fh.v4deleted[0] != uePrefix {
		t.Errorf("withdraw deleted = %v, want [%s]", fh.v4deleted, uePrefix)
	}
}

// T1ST over GTP6 (IPv6 gNB endpoint + IPv6 UE prefix) installs an H.Encaps entry
// in the v6 headend map whose SID carries a 5-byte GTP6 Args.Mob.Session
// (TEID+QFI only; the gNB IPv6 is not in the SID).
func TestApplyMUP_T1ST_Downlink_GTP6(t *testing.T) {
	fh := newFakeHeadend()
	a := newMUPApplier(t, fh)

	const (
		uePrefix = "2001:db8:a::1/128"
		gnb      = "2001:db8:b::1" // IPv6 endpoint => GTP6
		base     = "fd00:6:6:b::"
		teid     = uint32(0x12345678)
		qfi      = uint8(5)
	)
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyMUPIPv6, MUP: &bgp.MUPRoute{
		Type: bgp.MUPRouteTypeT1ST, RD: "65000:100",
		Prefix: uePrefix, Endpoint: gnb, TEID: teid, TEIDLen: 32, QFI: qfi, SRv6SID: base,
	}})

	// IPv6 UE prefix => v6 headend map.
	entry, ok := fh.v6created[uePrefix]
	if !ok {
		t.Fatalf("CreateHeadendV6 not called for v6 UE prefix; v6created=%v", fh.v6created)
	}
	da := entry.DstAddr
	const off = mupDefaultArgsOffset
	if got := binary.BigEndian.Uint32(da[off : off+4]); got != teid {
		t.Errorf("TEID in SID = 0x%08X, want 0x%08X", got, teid)
	}
	if got := da[off+4] & 0x3F; got != qfi {
		t.Errorf("QFI in SID = %d, want %d", got, qfi)
	}
}

// T2ST over GTP6 (IPv6 endpoint) installs an uplink F-TEID entry plus an
// H.M.GTP6.D_TEID gate on the endpoint /128 in the v6 headend map.
func TestApplyMUP_T2ST_Uplink_GTP6(t *testing.T) {
	fh := newFakeHeadend()
	a := newMUPApplier(t, fh)

	const (
		endpoint = "2001:db8::1"
		teid     = uint32(0xAB000000)
		teidLen  = uint8(8)
	)
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyMUPIPv6, MUP: &bgp.MUPRoute{
		Type: bgp.MUPRouteTypeT2ST, RD: "65000:100",
		Endpoint: endpoint, TEID: teid, TEIDLen: teidLen, SRv6SID: "fd00:6:6:c::",
	}})

	ue, ok := fh.mupUplink[mupUplinkKey{endpoint, teid, teidLen}]
	if !ok {
		t.Fatalf("CreateMupUplinkV6 not called; mupUplink=%v", fh.mupUplink)
	}
	if ue.ArgsOffset != bpf.MupArgsOffsetNone {
		t.Errorf("uplink ArgsOffset = %d, want MupArgsOffsetNone", ue.ArgsOffset)
	}
	gate, ok := fh.v6created[endpoint+"/128"]
	if !ok {
		t.Fatalf("v6 gate not installed; v6created=%v", fh.v6created)
	}
	if gate.Mode != uint8(v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_M_GTP6_D_TEID) {
		t.Errorf("gate mode = %d, want H_M_GTP6_D_TEID", gate.Mode)
	}
}

// T2ST installs an uplink F-TEID entry (no Args.Mob.Session patch) plus a gate.
func TestApplyMUP_T2ST_Uplink(t *testing.T) {
	fh := newFakeHeadend()
	a := newMUPApplier(t, fh)

	const (
		endpoint = "192.0.2.100"
		direct   = "fd00:3:3:c::" // remote direct segment (End.DT4)
		teid     = uint32(0xAB000000)
		teidLen  = uint8(8) // /8 TEID prefix
	)
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyMUPIPv4, MUP: &bgp.MUPRoute{
		Type: bgp.MUPRouteTypeT2ST, RD: "65000:100",
		Endpoint: endpoint, TEID: teid, TEIDLen: teidLen, SRv6SID: direct,
	}})

	// F-TEID uplink entry.
	ue, ok := fh.mupUplink[mupUplinkKey{endpoint, teid, teidLen}]
	if !ok {
		t.Fatalf("CreateMupUplinkV4 not called; mupUplink=%v", fh.mupUplink)
	}
	if ue.ArgsOffset != bpf.MupArgsOffsetNone {
		t.Errorf("uplink ArgsOffset = %d, want MupArgsOffsetNone (no patch)", ue.ArgsOffset)
	}
	if got := netip.AddrFrom16(ue.DstAddr); got != netip.MustParseAddr(direct) {
		t.Errorf("uplink direct SID = %s, want %s", got, direct)
	}
	// Gate on the endpoint /32 with the F-TEID behavior.
	gate, ok := fh.v4created[endpoint+"/32"]
	if !ok {
		t.Fatalf("gate not installed; v4created=%v", fh.v4created)
	}
	if gate.Mode != uint8(v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_M_GTP4_D_TEID) {
		t.Errorf("gate mode = %d, want H_M_GTP4_D_TEID", gate.Mode)
	}
}

// Two T2ST routes from DIFFERENT RDs on the same endpoint (different TEIDs)
// share one gate: the gate is created once and removed only when the last
// session withdraws. The gate owner is RD-independent (OwnerBGPMUPGate), so a
// withdraw from the second RD releases it cleanly (the regression the OCR review
// flagged: an RD-scoped gate owner would fail the cross-owner delete and leak).
func TestApplyMUP_T2ST_MultiRD_SharedGate(t *testing.T) {
	fh := newFakeHeadend()
	a := newMUPApplier(t, fh)

	const endpoint = "192.0.2.100"
	mk := func(rd string, teid uint32, withdraw bool) bgp.RouteEvent {
		return bgp.RouteEvent{Family: bgp.FamilyMUPIPv4, IsWithdraw: withdraw, MUP: &bgp.MUPRoute{
			Type: bgp.MUPRouteTypeT2ST, RD: rd, Endpoint: endpoint, TEID: teid, TEIDLen: 32, SRv6SID: "fd00:3:3:c::",
		}}
	}

	a.Apply(mk("65000:1", 0x100, false)) // RD-A
	a.Apply(mk("65000:2", 0x200, false)) // RD-B, same endpoint, different TEID

	if _, ok := fh.v4created[endpoint+"/32"]; !ok {
		t.Fatal("gate not installed")
	}
	if len(fh.mupUplink) != 2 {
		t.Errorf("want 2 F-TEID entries (one per RD/TEID), got %d", len(fh.mupUplink))
	}

	a.Apply(mk("65000:1", 0x100, true)) // RD-A withdraws
	if len(fh.v4deleted) != 0 {
		t.Errorf("gate removed too early after RD-A withdraw: %v", fh.v4deleted)
	}
	a.Apply(mk("65000:2", 0x200, true)) // RD-B withdraws (last)
	if len(fh.v4deleted) != 1 || fh.v4deleted[0] != endpoint+"/32" {
		t.Errorf("gate not removed once after last withdraw; deleted=%v", fh.v4deleted)
	}
}

// A re-advertise of the SAME T2ST (BGP refresh / replay) must not inflate the
// gate ref-count: one logical session holds exactly one reference, so a single
// withdraw removes the gate. (Regression for the round-2 finding.)
func TestApplyMUP_T2ST_IdempotentReadvertise(t *testing.T) {
	fh := newFakeHeadend()
	a := newMUPApplier(t, fh)

	ev := bgp.RouteEvent{Family: bgp.FamilyMUPIPv4, MUP: &bgp.MUPRoute{
		Type: bgp.MUPRouteTypeT2ST, RD: "65000:1", Endpoint: "192.0.2.100",
		TEID: 0x100, TEIDLen: 32, SRv6SID: "fd00:3:3:c::",
	}}
	a.Apply(ev) // advertise
	a.Apply(ev) // identical re-advertise (must NOT bump the gate ref-count)

	wd := ev
	wd.IsWithdraw = true
	a.Apply(wd) // single withdraw must release the gate

	if len(fh.v4deleted) != 1 || fh.v4deleted[0] != "192.0.2.100/32" {
		t.Errorf("re-advertise inflated the gate ref-count; single withdraw left it stranded: deleted=%v", fh.v4deleted)
	}
	if len(fh.mupUplink) != 0 {
		t.Errorf("uplink entry not removed after withdraw: %v", fh.mupUplink)
	}
}

// Two sessions on one endpoint share a single gate; the gate is removed only
// when the last session withdraws.
func TestApplyMUP_T2ST_GateRefCount(t *testing.T) {
	fh := newFakeHeadend()
	a := newMUPApplier(t, fh)

	const endpoint = "192.0.2.100"
	mk := func(teid uint32) bgp.RouteEvent {
		return bgp.RouteEvent{Family: bgp.FamilyMUPIPv4, MUP: &bgp.MUPRoute{
			Type: bgp.MUPRouteTypeT2ST, RD: "65000:100",
			Endpoint: endpoint, TEID: teid, TEIDLen: 32, SRv6SID: "fd00:3:3:c::",
		}}
	}
	wd := func(teid uint32) bgp.RouteEvent {
		ev := mk(teid)
		ev.IsWithdraw = true
		return ev
	}

	a.Apply(mk(0x100))
	a.Apply(mk(0x200))
	if _, ok := fh.v4created[endpoint+"/32"]; !ok {
		t.Fatal("gate missing after two installs")
	}

	// First withdraw: gate must remain (one session still references it).
	a.Apply(wd(0x100))
	if len(fh.v4deleted) != 0 {
		t.Errorf("gate deleted too early after first withdraw: %v", fh.v4deleted)
	}
	// Second withdraw: gate goes away.
	a.Apply(wd(0x200))
	if len(fh.v4deleted) != 1 || fh.v4deleted[0] != endpoint+"/32" {
		t.Errorf("gate not removed after last withdraw; deleted=%v", fh.v4deleted)
	}
	if len(fh.mupUplink) != 0 {
		t.Errorf("uplink entries remain after withdraw: %v", fh.mupUplink)
	}
}

// Resolution helpers: a T1ST/T2ST that carries no SID of its own resolves its
// interwork/direct SID from the gateways' ISD/DSD segment-discovery routes
// (RFC 9433 §3) -- the draft-faithful model where a controller advertises only
// session state and the gateways advertise their segments.

// Route-targets shared by the resolution-test helpers so a discovery route and
// the session it resolves land in the same VPN (resolution is RT-scoped). The
// interwork pair (ISD <-> T1ST) and the direct pair (DSD <-> T2ST) use distinct
// RTs; the RDs may differ, mirroring an interworking gateway that advertises
// under its own RD.
const (
	testRTInterwork = "100:2000"
	testRTDirect    = "100:6000"
)

func mupT1ST(rd, uePrefix, gnb string, teid uint32, qfi uint8, ownSID string) bgp.RouteEvent {
	return bgp.RouteEvent{Family: bgp.FamilyMUPIPv4, MUP: &bgp.MUPRoute{
		Type: bgp.MUPRouteTypeT1ST, RD: rd, Prefix: uePrefix, RTs: []string{testRTInterwork},
		Endpoint: gnb, TEID: teid, TEIDLen: 32, QFI: qfi, SRv6SID: ownSID,
	}}
}

func mupISD(rd, prefix, sid string) bgp.RouteEvent {
	return bgp.RouteEvent{Family: bgp.FamilyMUPIPv4, MUP: &bgp.MUPRoute{
		Type: bgp.MUPRouteTypeISD, RD: rd, Prefix: prefix, RTs: []string{testRTInterwork}, SRv6SID: sid,
	}}
}

func mupT2ST(rd, endpoint string, teid uint32, teidLen uint8, segID2 uint16, segID4 uint32, ownSID string) bgp.RouteEvent {
	return bgp.RouteEvent{Family: bgp.FamilyMUPIPv4, MUP: &bgp.MUPRoute{
		Type: bgp.MUPRouteTypeT2ST, RD: rd, Endpoint: endpoint, TEID: teid, TEIDLen: teidLen,
		RTs: []string{testRTDirect}, SegmentID2: segID2, SegmentID4: segID4, SRv6SID: ownSID,
	}}
}

func mupDSD(rd, address string, segID2 uint16, segID4 uint32, sid string) bgp.RouteEvent {
	return bgp.RouteEvent{Family: bgp.FamilyMUPIPv4, MUP: &bgp.MUPRoute{
		Type: bgp.MUPRouteTypeDSD, RD: rd, Address: address,
		RTs: []string{testRTDirect}, SegmentID2: segID2, SegmentID4: segID4, SRv6SID: sid,
	}}
}

// assertT1STBase checks the downlink headend's destination SID was composed onto
// `base` (the locator:function bytes before the offset-7 args window).
func assertT1STBase(t *testing.T, fh *fakeHeadend, uePrefix, base string) {
	t.Helper()
	entry, ok := fh.v4created[uePrefix]
	if !ok {
		t.Fatalf("downlink headend not installed for %s; v4created=%v", uePrefix, fh.v4created)
	}
	want := netip.MustParseAddr(base).As16()
	for i := 0; i < mupDefaultArgsOffset; i++ {
		if entry.DstAddr[i] != want[i] {
			t.Fatalf("SID base byte %d = 0x%02X, want 0x%02X (resolution used the wrong SID)", i, entry.DstAddr[i], want[i])
		}
	}
}

// A T1ST carrying no SID of its own resolves its interwork SID from the ISD
// whose prefix contains the gNB endpoint -- regardless of arrival order, and
// withdrawing the ISD tears the deferred-again session back down.
func TestApplyMUP_T1ST_ResolvesViaISD(t *testing.T) {
	const (
		rd   = "65100:1"
		ue   = "10.1.0.1/32"
		gnb  = "172.16.0.1"
		isdP = "172.16.0.0/24"
		isid = "fd00:a:0:1::" // interwork SID advertised by the access gateway
	)

	t.Run("ISD before T1ST", func(t *testing.T) {
		fh := newFakeHeadend()
		a := newMUPApplier(t, fh)
		a.Apply(mupISD(rd, isdP, isid))
		a.Apply(mupT1ST(rd, ue, gnb, 256, 9, "")) // no own SID
		assertT1STBase(t, fh, ue, isid)
	})

	t.Run("T1ST before ISD (deferred)", func(t *testing.T) {
		fh := newFakeHeadend()
		a := newMUPApplier(t, fh)
		a.Apply(mupT1ST(rd, ue, gnb, 256, 9, "")) // no ISD yet -> deferred
		if _, ok := fh.v4created[ue]; ok {
			t.Fatal("downlink installed before its ISD arrived; should be deferred")
		}
		a.Apply(mupISD(rd, isdP, isid)) // ISD arrives -> reconcile installs it
		assertT1STBase(t, fh, ue, isid)
	})

	t.Run("ISD withdraw tears down", func(t *testing.T) {
		fh := newFakeHeadend()
		a := newMUPApplier(t, fh)
		a.Apply(mupISD(rd, isdP, isid))
		a.Apply(mupT1ST(rd, ue, gnb, 256, 9, ""))
		wd := mupISD(rd, isdP, isid)
		wd.IsWithdraw = true
		a.Apply(wd)
		if len(fh.v4deleted) != 1 || fh.v4deleted[0] != ue {
			t.Errorf("withdrawing the ISD did not tear down the deferred T1ST; deleted=%v", fh.v4deleted)
		}
	})
}

// A T2ST carrying no SID of its own resolves its direct SID from the DSD that
// carries the same MUP segment id, and the gate appears only once the session
// resolves (a deferred T2ST installs no gate).
func TestApplyMUP_T2ST_ResolvesViaDSD(t *testing.T) {
	const (
		rd       = "65100:1"
		endpoint = "192.0.2.100"
		dsdAddr  = "10.0.0.1"
		seg2     = uint16(1)
		seg4     = uint32(2)
		direct   = "fd00:d:0:1::" // direct SID advertised by the data gateway
	)

	t.Run("DSD before T2ST", func(t *testing.T) {
		fh := newFakeHeadend()
		a := newMUPApplier(t, fh)
		a.Apply(mupDSD(rd, dsdAddr, seg2, seg4, direct))
		a.Apply(mupT2ST(rd, endpoint, 0x100, 32, seg2, seg4, "")) // no own SID
		ue, ok := fh.mupUplink[mupUplinkKey{endpoint, 0x100, 32}]
		if !ok {
			t.Fatalf("uplink entry not installed; mupUplink=%v", fh.mupUplink)
		}
		if got := netip.AddrFrom16(ue.DstAddr); got != netip.MustParseAddr(direct) {
			t.Errorf("uplink direct SID = %s, want %s (DSD resolution)", got, direct)
		}
	})

	t.Run("T2ST before DSD (deferred, no gate)", func(t *testing.T) {
		fh := newFakeHeadend()
		a := newMUPApplier(t, fh)
		a.Apply(mupT2ST(rd, endpoint, 0x100, 32, seg2, seg4, "")) // no DSD yet
		if len(fh.mupUplink) != 0 {
			t.Errorf("uplink installed before its DSD; should be deferred: %v", fh.mupUplink)
		}
		if _, ok := fh.v4created[endpoint+"/32"]; ok {
			t.Error("gate installed for a deferred T2ST; gate must wait for resolution")
		}
		a.Apply(mupDSD(rd, dsdAddr, seg2, seg4, direct)) // DSD arrives -> install
		if _, ok := fh.mupUplink[mupUplinkKey{endpoint, 0x100, 32}]; !ok {
			t.Errorf("uplink not installed after its DSD arrived; mupUplink=%v", fh.mupUplink)
		}
		if _, ok := fh.v4created[endpoint+"/32"]; !ok {
			t.Error("gate not installed after the T2ST resolved")
		}
	})

	t.Run("DSD withdraw releases gate", func(t *testing.T) {
		fh := newFakeHeadend()
		a := newMUPApplier(t, fh)
		a.Apply(mupDSD(rd, dsdAddr, seg2, seg4, direct))
		a.Apply(mupT2ST(rd, endpoint, 0x100, 32, seg2, seg4, ""))
		wd := mupDSD(rd, dsdAddr, seg2, seg4, direct)
		wd.IsWithdraw = true
		a.Apply(wd)
		if len(fh.mupUplink) != 0 {
			t.Errorf("uplink survived its DSD withdraw: %v", fh.mupUplink)
		}
		if len(fh.v4deleted) != 1 || fh.v4deleted[0] != endpoint+"/32" {
			t.Errorf("gate not released when the DSD withdrew; deleted=%v", fh.v4deleted)
		}
	})
}

// When a discovery route is updated in place (same table key, new SID), the
// dependent session must re-resolve and re-Put the data-plane entry with the new
// SID -- and for T2ST the gate must NOT be churned (its ref-count is unchanged).
// This exercises reconcile's "installedSID != ” && != sid" branch, the headline
// transition of the resolution feature.
func TestApplyMUP_SIDChangeReResolution(t *testing.T) {
	t.Run("T2ST re-Puts F-TEID, gate untouched", func(t *testing.T) {
		const (
			rd       = "65100:1"
			endpoint = "192.0.2.100"
			dsdAddr  = "10.0.0.1"
			seg2     = uint16(1)
			seg4     = uint32(2)
			sidA     = "fd00:d:0:1::"
			sidB     = "fd00:d:0:2::"
		)
		fh := newFakeHeadend()
		a := newMUPApplier(t, fh)
		a.Apply(mupDSD(rd, dsdAddr, seg2, seg4, sidA))
		a.Apply(mupT2ST(rd, endpoint, 0x100, 32, seg2, seg4, "")) // installs via sidA
		if got := netip.AddrFrom16(fh.mupUplink[mupUplinkKey{endpoint, 0x100, 32}].DstAddr); got != netip.MustParseAddr(sidA) {
			t.Fatalf("initial uplink SID = %s, want %s", got, sidA)
		}
		// Same DSD key, new SID -> re-resolution.
		a.Apply(mupDSD(rd, dsdAddr, seg2, seg4, sidB))
		if got := netip.AddrFrom16(fh.mupUplink[mupUplinkKey{endpoint, 0x100, 32}].DstAddr); got != netip.MustParseAddr(sidB) {
			t.Errorf("uplink SID after re-resolution = %s, want %s (re-Put branch)", got, sidB)
		}
		if len(fh.v4deleted) != 0 {
			t.Errorf("gate was churned on a SID change; deleted=%v (must be untouched)", fh.v4deleted)
		}
	})

	t.Run("T1ST re-composes headend onto the new interwork SID", func(t *testing.T) {
		const (
			rd   = "65100:1"
			ue   = "10.1.0.1/32"
			gnb  = "172.16.0.1"
			isdP = "172.16.0.0/24"
			sidA = "fd00:a:0:1::"
			sidB = "fd00:a:0:2::"
		)
		fh := newFakeHeadend()
		a := newMUPApplier(t, fh)
		a.Apply(mupISD(rd, isdP, sidA))
		a.Apply(mupT1ST(rd, ue, gnb, 256, 9, "")) // installs via sidA
		assertT1STBase(t, fh, ue, sidA)
		a.Apply(mupISD(rd, isdP, sidB)) // same ISD key, new SID -> re-resolution
		assertT1STBase(t, fh, ue, sidB)
	})
}

// Resolution is scoped to the session's VPN by route-target: a discovery route
// whose RTs do not intersect the session's must NOT resolve it, even if it would
// otherwise match (covering prefix / same segment id). This is the cross-VPN-
// hijack guard, and it is RT-scoped rather than RD-scoped because an interworking
// gateway (e.g. a third-party MUP gateway) advertises its ISD under its own RD, distinct from the
// controller's T1ST RD -- an RD-scoped match would never resolve across vendors.
func TestApplyMUP_ResolutionIsRTScoped(t *testing.T) {
	const (
		ue   = "10.1.0.1/32"
		gnb  = "172.16.0.1"
		isdP = "172.16.0.0/24"
		isid = "fd00:a:0:1::"
	)
	fh := newFakeHeadend()
	a := newMUPApplier(t, fh)

	// ISD with a non-intersecting RT (and a different RD): must not resolve.
	isdOtherVPN := mupISD("65100:999", isdP, isid)
	isdOtherVPN.MUP.RTs = []string{"100:9999"}
	a.Apply(isdOtherVPN)
	a.Apply(mupT1ST("65100:1", ue, gnb, 256, 9, "")) // RT testRTInterwork
	if _, ok := fh.v4created[ue]; ok {
		t.Fatal("T1ST resolved against an ISD in a different VPN (cross-VPN hijack not prevented)")
	}

	// ISD under yet another RD but an intersecting RT (the interworking-gateway
	// case): resolves despite the RD mismatch -- the cross-vendor interop path.
	a.Apply(mupISD("65100:50002", isdP, isid)) // RT testRTInterwork, RD != T1ST RD
	assertT1STBase(t, fh, ue, isid)
}

// Two same-RD DSDs advertising the same segment id for different SIDs make the
// direct SID ambiguous; resolution must pick deterministically (the lowest SID),
// not flap with Go map iteration order.
func TestApplyMUP_DSD_SegmentIDCollisionDeterministic(t *testing.T) {
	const (
		rd       = "65100:1"
		endpoint = "192.0.2.100"
		seg2     = uint16(1)
		seg4     = uint32(2)
		sidLo    = "fd00:d:0:1::"
		sidHi    = "fd00:d:0:2::"
	)
	fh := newFakeHeadend()
	a := newMUPApplier(t, fh)
	// Insert the higher SID first; the lower one must still win deterministically.
	a.Apply(mupDSD(rd, "10.0.0.9", seg2, seg4, sidHi))
	a.Apply(mupDSD(rd, "10.0.0.1", seg2, seg4, sidLo))
	a.Apply(mupT2ST(rd, endpoint, 0x100, 32, seg2, seg4, ""))
	if got := netip.AddrFrom16(fh.mupUplink[mupUplinkKey{endpoint, 0x100, 32}].DstAddr); got != netip.MustParseAddr(sidLo) {
		t.Errorf("colliding-segment-id resolution = %s, want the deterministic lowest %s", got, sidLo)
	}
}

// A withdraw whose TEID does not match the currently-installed T1ST is for a
// superseded session (a newer T1ST on the same UE prefix replaced it) and must
// NOT tear down the active downlink. (The {RD,prefix}-only key would otherwise
// let a stale withdraw remove a live install.)
func TestApplyMUP_T1ST_SupersededWithdrawIgnored(t *testing.T) {
	const (
		rd   = "65100:1"
		ue   = "10.1.0.1/32"
		gnb  = "172.16.0.1"
		isdP = "172.16.0.0/24"
		isid = "fd00:a:0:1::"
	)
	fh := newFakeHeadend()
	a := newMUPApplier(t, fh)
	a.Apply(mupISD(rd, isdP, isid))
	a.Apply(mupT1ST(rd, ue, gnb, 0x100, 9, "")) // TEID 0x100
	a.Apply(mupT1ST(rd, ue, gnb, 0x200, 9, "")) // TEID 0x200 supersedes (same UE prefix)

	wdOld := mupT1ST(rd, ue, gnb, 0x100, 9, "") // withdraw the superseded TEID
	wdOld.IsWithdraw = true
	a.Apply(wdOld)
	if len(fh.v4deleted) != 0 {
		t.Errorf("a superseded-TEID withdraw tore down the live downlink; deleted=%v", fh.v4deleted)
	}
	if _, ok := fh.v4created[ue]; !ok {
		t.Error("downlink headend missing after a superseded-TEID withdraw")
	}

	wdCur := mupT1ST(rd, ue, gnb, 0x200, 9, "") // withdraw the current TEID
	wdCur.IsWithdraw = true
	a.Apply(wdCur)
	if len(fh.v4deleted) != 1 || fh.v4deleted[0] != ue {
		t.Errorf("withdrawing the current TEID did not tear down the downlink; deleted=%v", fh.v4deleted)
	}
}

// Two uplink sessions on one endpoint that both resolve via the same DSD share a
// single gate, acquired once when the DSD arrives (both deferred until then) and
// released once when it withdraws -- exercising the shared-gate ref-count through
// the resolution path, not just inline SIDs.
func TestApplyMUP_T2ST_SharedGateViaDSD(t *testing.T) {
	const (
		rd       = "65100:1"
		endpoint = "192.0.2.100"
		dsdAddr  = "10.0.0.1"
		seg2     = uint16(1)
		seg4     = uint32(2)
		direct   = "fd00:d:0:1::"
	)
	fh := newFakeHeadend()
	a := newMUPApplier(t, fh)
	a.Apply(mupT2ST(rd, endpoint, 0x100, 32, seg2, seg4, "")) // both deferred (no DSD)
	a.Apply(mupT2ST(rd, endpoint, 0x200, 32, seg2, seg4, ""))
	if _, ok := fh.v4created[endpoint+"/32"]; ok {
		t.Fatal("gate installed while both T2STs were deferred")
	}
	a.Apply(mupDSD(rd, dsdAddr, seg2, seg4, direct)) // resolves both
	if len(fh.mupUplink) != 2 {
		t.Errorf("want 2 F-TEID entries after DSD, got %d", len(fh.mupUplink))
	}
	if _, ok := fh.v4created[endpoint+"/32"]; !ok {
		t.Fatal("shared gate not installed after resolution")
	}
	wd := mupDSD(rd, dsdAddr, seg2, seg4, direct)
	wd.IsWithdraw = true
	a.Apply(wd) // tears both down
	if len(fh.mupUplink) != 0 {
		t.Errorf("uplink entries survived DSD withdraw: %v", fh.mupUplink)
	}
	if len(fh.v4deleted) != 1 || fh.v4deleted[0] != endpoint+"/32" {
		t.Errorf("shared gate not released exactly once after DSD withdraw; deleted=%v", fh.v4deleted)
	}
}
