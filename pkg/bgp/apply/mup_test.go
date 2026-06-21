package apply

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"go.uber.org/zap"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/vrf"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

func newMUPApplier(t *testing.T, fh *fakeHeadend) *Applier {
	t.Helper()
	return NewApplier(fh, testLocatorManager(t), vrfbgp.NewManager(), &fakeFib{}, "LOC1", 65000, zap.NewNop())
}

// bindMUPGTP4Src registers a binding carrying rd and the RFC 9433 §6.6 GTP4
// downlink source prefix on vm. The binding declares no families, so the
// MUP import filter stays default-allow and only the source embed is bound.
func bindMUPGTP4Src(t *testing.T, vm *vrfbgp.Manager, vrf, rd, prefix string) {
	t.Helper()
	pfx, err := vrfbgp.ParseMUPGTP4SourcePrefix(prefix, rd)
	if err != nil {
		t.Fatalf("ParseMUPGTP4SourcePrefix(%q): %v", prefix, err)
	}
	if err := vm.Bind(vrfbgp.Binding{VRFName: vrf, RD: rd, MupGTP4SourcePrefix: pfx}); err != nil {
		t.Fatalf("Bind: %v", err)
	}
}

// newMUPApplierWithGTP4Src is newMUPApplier plus a binding that turns on the
// GTP4 downlink source embed for rd.
func newMUPApplierWithGTP4Src(t *testing.T, fh *fakeHeadend, rd, prefix string) *Applier {
	t.Helper()
	vm := vrfbgp.NewManager()
	bindMUPGTP4Src(t, vm, "vrf-mup", rd, prefix)
	return NewApplier(fh, testLocatorManager(t), vm, &fakeFib{}, "LOC1", 65000, zap.NewNop())
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
	// Args.Mob.Session at offset 7 in the destination SID (RFC 9433 §6.1:
	// [gNB(4)][QFI<<2|RQI<<1(1)][TEID(4)]).
	da := entry.DstAddr
	const off = mupDefaultArgsOffset
	if got := netip.AddrFrom4([4]byte(da[off : off+4])); got != netip.MustParseAddr(gnb) {
		t.Errorf("gNB in SID = %s, want %s", got, gnb)
	}
	if got := (da[off+4] >> 2) & 0x3F; got != qfi {
		t.Errorf("QFI in SID = %d, want %d", got, qfi)
	}
	if got := binary.BigEndian.Uint32(da[off+5 : off+9]); got != teid {
		t.Errorf("TEID in SID = 0x%08X, want 0x%08X", got, teid)
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
	// GTP6 Args.Mob.Session (RFC 9433 §6.1): [QFI<<2|RQI<<1(1)][TEID(4)].
	if got := (da[off] >> 2) & 0x3F; got != qfi {
		t.Errorf("QFI in SID = %d, want %d", got, qfi)
	}
	if got := binary.BigEndian.Uint32(da[off+1 : off+5]); got != teid {
		t.Errorf("TEID in SID = 0x%08X, want 0x%08X", got, teid)
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

	ue, ok := fh.mupUplink[mupUplinkKey{0, endpoint, teid, teidLen}]
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
	ue, ok := fh.mupUplink[mupUplinkKey{0, endpoint, teid, teidLen}]
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
		ue, ok := fh.mupUplink[mupUplinkKey{0, endpoint, 0x100, 32}]
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
		if _, ok := fh.mupUplink[mupUplinkKey{0, endpoint, 0x100, 32}]; !ok {
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
		if got := netip.AddrFrom16(fh.mupUplink[mupUplinkKey{0, endpoint, 0x100, 32}].DstAddr); got != netip.MustParseAddr(sidA) {
			t.Fatalf("initial uplink SID = %s, want %s", got, sidA)
		}
		// Same DSD key, new SID -> re-resolution.
		a.Apply(mupDSD(rd, dsdAddr, seg2, seg4, sidB))
		if got := netip.AddrFrom16(fh.mupUplink[mupUplinkKey{0, endpoint, 0x100, 32}].DstAddr); got != netip.MustParseAddr(sidB) {
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
	if got := netip.AddrFrom16(fh.mupUplink[mupUplinkKey{0, endpoint, 0x100, 32}].DstAddr); got != netip.MustParseAddr(sidLo) {
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

// TestApplyMUP_ImportRTFilterDefaultAllow pins MUP keeps its historical
// default-allow when no binding under mup_ipv4 / mup_ipv6 exists.
func TestApplyMUP_ImportRTFilterDefaultAllow(t *testing.T) {
	fh := newFakeHeadend()
	vm := vrfbgp.NewManager()
	// Bind only a vpnv4 family: the MUP family stays "empty" so default-allow holds.
	if err := vm.Bind(vrfbgp.Binding{
		VRFName: "vrf-v4",
		Families: map[bgp.Family]vrfbgp.FamilyPolicy{
			bgp.FamilyVPNv4: {RouteTargets: []vrfbgp.RouteTarget{
				{RT: "65000:1", Direction: vrfbgp.DirectionImport},
			}},
		},
	}); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	a := NewApplier(fh, testLocatorManager(t), vm, &fakeFib{}, "LOC1", 65000, zap.NewNop())
	a.Apply(mupISD("65000:200", "10.0.0.0/24", "fd00:2:2:b::"))
	if len(a.mupISD) != 1 {
		t.Errorf("MUP must stay default-allow when no MUP-family binding exists, got %d ISD entries", len(a.mupISD))
	}
}

// TestApplyMUP_ImportRTFilterDropsUnmatched pins that once a MUP-family
// binding exists, a SESSION route (T1ST/T2ST) whose RT is not imported is
// dropped before it reaches the resolution tables. ISD/DSD discovery routes
// bypass the filter because they carry the controller/gateway's own RTs and
// feed cross-VRF resolution. A re-advertise of the same route under a
// matched RT is then accepted (the filter does not leave a poison cache).
func TestApplyMUP_ImportRTFilterDropsUnmatched(t *testing.T) {
	fh := newFakeHeadend()
	vm := vrfbgp.NewManager()
	if err := vm.Bind(vrfbgp.Binding{
		VRFName: "vrf-mup",
		Families: map[bgp.Family]vrfbgp.FamilyPolicy{
			bgp.FamilyMUPIPv4: {RouteTargets: []vrfbgp.RouteTarget{
				{RT: testRTInterwork, Direction: vrfbgp.DirectionImport},
			}},
		},
	}); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	a := NewApplier(fh, testLocatorManager(t), vm, &fakeFib{}, "LOC1", 65000, zap.NewNop())

	// ISD with an unmatched RT must STILL be accepted (discovery bypasses the
	// session-RT filter). This guards against the regression where a narrow
	// session-RT binding silently dropped the discovery feed that T1ST/T2ST
	// resolution depends on.
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyMUPIPv4, MUP: &bgp.MUPRoute{
		Type: bgp.MUPRouteTypeISD, RD: "65000:200", Prefix: "10.0.0.0/24",
		RTs: []string{testRTDirect}, SRv6SID: "fd00:2:2:b::",
	}})
	if len(a.mupISD) != 1 {
		t.Errorf("ISD must bypass the session-RT filter; got %d entries", len(a.mupISD))
	}

	// T1ST is a SESSION route, so the filter applies: an unmatched RT must
	// not install a session entry.
	notImported := mupT1ST("65000:200", "10.1.0.1/32", "192.0.2.1", 256, 9, "")
	notImported.MUP.RTs = []string{testRTDirect}
	a.Apply(notImported)
	if len(a.mupT1ST) != 0 {
		t.Errorf("T1ST with unmatched RT must not enter mupT1ST; got %v", a.mupT1ST)
	}

	// Same T1ST re-advertised with the imported RT is accepted.
	a.Apply(mupT1ST("65000:200", "10.1.0.1/32", "192.0.2.1", 256, 9, ""))
	if len(a.mupT1ST) != 1 {
		t.Errorf("T1ST with matched RT must be accepted; got %d entries", len(a.mupT1ST))
	}

	// Withdraw bypasses the filter even when the RTs no longer match a
	// binding's import set: a route accepted earlier must still be torn down.
	wd := mupT1ST("65000:200", "10.1.0.1/32", "192.0.2.1", 256, 9, "")
	wd.IsWithdraw = true
	wd.MUP.RTs = []string{testRTDirect} // withdraw NLRI may lose the RT path attr
	a.Apply(wd)
	if len(a.mupT1ST) != 0 {
		t.Errorf("withdraw must bypass the filter and remove the entry; got %v", a.mupT1ST)
	}
}

// SetMUPDefaultAllow=true is the escape hatch for the asymmetric-expansion
// edge case: one binding declares mup_ipv* via the new form, but legacy
// bindings (whose ImportRTs do not auto-expand into MUP) must keep receiving
// their MUP traffic. With the knob on, the filter is bypassed even when a
// MUP-family binding exists.
func TestApplyMUP_DefaultAllowKnobBypassesFilter(t *testing.T) {
	fh := newFakeHeadend()
	vm := vrfbgp.NewManager()
	if err := vm.Bind(vrfbgp.Binding{
		VRFName: "vrf-mup",
		Families: map[bgp.Family]vrfbgp.FamilyPolicy{
			bgp.FamilyMUPIPv4: {RouteTargets: []vrfbgp.RouteTarget{
				{RT: testRTInterwork, Direction: vrfbgp.DirectionImport},
			}},
		},
	}); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	a := NewApplier(fh, testLocatorManager(t), vm, &fakeFib{}, "LOC1", 65000, zap.NewNop())
	a.SetMUPDefaultAllow(true)

	// T1ST with an RT the binding does NOT import must still install (the
	// knob force-allows even though the family-bound filter would drop).
	notImported := mupT1ST("65000:200", "10.1.0.1/32", "192.0.2.1", 256, 9, "")
	notImported.MUP.RTs = []string{testRTDirect}
	a.Apply(notImported)
	if len(a.mupT1ST) != 1 {
		t.Errorf("default-allow knob must bypass the filter; got %d T1ST entries", len(a.mupT1ST))
	}
}

// With a binding carrying mup_gtp4_source_prefix for the session's RD, the
// downlink outer source embeds the session's UPF IPv4 anchor (the same-RD
// T2ST endpoint) right after the configured prefix bits (RFC 9433 §6.6),
// and follows the T2ST through arrive-after-install and withdraw.
func TestApplyMUP_T1ST_GTP4SourceEmbed(t *testing.T) {
	fh := newFakeHeadend()
	const (
		rd       = "65000:100"
		uePrefix = "10.1.0.1/32"
		gnb      = "172.16.0.1"
		upf      = "172.16.0.254"
		teid     = uint32(0x100)
	)
	t1st := bgp.RouteEvent{Family: bgp.FamilyMUPIPv4, MUP: &bgp.MUPRoute{
		Type: bgp.MUPRouteTypeT1ST, RD: rd,
		Prefix: uePrefix, Endpoint: gnb, TEID: teid, TEIDLen: 32, QFI: 9,
		SRv6SID: "fd00:2:2:b::",
	}}
	t2st := bgp.RouteEvent{Family: bgp.FamilyMUPIPv4, MUP: &bgp.MUPRoute{
		Type: bgp.MUPRouteTypeT2ST, RD: rd,
		Endpoint: upf, TEID: teid, TEIDLen: 32,
	}}
	a := newMUPApplierWithGTP4Src(t, fh, rd, "::/0")

	// T1ST before any T2ST: no anchor known yet, plain encap source (LOC1).
	a.Apply(t1st)
	entry := fh.v4created[uePrefix]
	if entry == nil {
		t.Fatalf("CreateHeadendV4 not called for UE prefix")
	}
	plainSrc := netip.MustParsePrefix("fd00:1:1::/48").Masked().Addr().As16()
	if entry.SrcAddr != plainSrc {
		t.Fatalf("src before T2ST = %v, want plain encap source %v",
			netip.AddrFrom16(entry.SrcAddr), netip.AddrFrom16(plainSrc))
	}

	// The T2ST arriving re-reconciles the downlink with the embedded source:
	// prefix ::/0 puts the anchor in the first 32 bits (ac10:fe::).
	a.Apply(t2st)
	entry = fh.v4created[uePrefix]
	embedded := netip.MustParseAddr("ac10:fe::").As16()
	if entry.SrcAddr != embedded {
		t.Fatalf("src after T2ST = %v, want embedded %v",
			netip.AddrFrom16(entry.SrcAddr), netip.AddrFrom16(embedded))
	}

	// Withdrawing the T2ST reverts the downlink to the plain encap source.
	w := *t2st.MUP
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyMUPIPv4, IsWithdraw: true, MUP: &w})
	entry = fh.v4created[uePrefix]
	if entry.SrcAddr != plainSrc {
		t.Errorf("src after T2ST withdraw = %v, want plain encap source %v",
			netip.AddrFrom16(entry.SrcAddr), netip.AddrFrom16(plainSrc))
	}
}

// The embed honors a non-zero source-prefix: with a /64 prefix the anchor
// occupies bits 64..95 (v4src_position 64 on the peer GW).
func TestApplyMUP_T1ST_GTP4SourceEmbed_Position64(t *testing.T) {
	fh := newFakeHeadend()
	const rd = "65000:100"
	a := newMUPApplierWithGTP4Src(t, fh, rd, "2001:cafe:0:1::/64")
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyMUPIPv4, MUP: &bgp.MUPRoute{
		Type: bgp.MUPRouteTypeT2ST, RD: rd, Endpoint: "172.16.0.254",
		TEID: 0x100, TEIDLen: 32,
	}})
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyMUPIPv4, MUP: &bgp.MUPRoute{
		Type: bgp.MUPRouteTypeT1ST, RD: rd,
		Prefix: "10.1.0.1/32", Endpoint: "172.16.0.1", TEID: 0x100, TEIDLen: 32, QFI: 9,
		SRv6SID: "fd00:2:2:b::",
	}})

	entry := fh.v4created["10.1.0.1/32"]
	if entry == nil {
		t.Fatalf("CreateHeadendV4 not called")
	}
	want := netip.MustParseAddr("2001:cafe:0:1:ac10:fe::").As16()
	if entry.SrcAddr != want {
		t.Errorf("src = %v, want %v",
			netip.AddrFrom16(entry.SrcAddr), netip.AddrFrom16(want))
	}
}

// A GTP6 downlink (IPv6 endpoint) is exempt from the GTP4 source embed even
// when the RD's binding carries a prefix and an anchor exists.
func TestApplyMUP_T1ST_GTP4SourceEmbed_GTP6Exempt(t *testing.T) {
	fh := newFakeHeadend()
	const rd = "65000:100"
	a := newMUPApplierWithGTP4Src(t, fh, rd, "::/0")
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyMUPIPv4, MUP: &bgp.MUPRoute{
		Type: bgp.MUPRouteTypeT2ST, RD: rd, Endpoint: "172.16.0.254",
		TEID: 0x100, TEIDLen: 32,
	}})
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyMUPIPv6, MUP: &bgp.MUPRoute{
		Type: bgp.MUPRouteTypeT1ST, RD: rd,
		Prefix: "2001:db8:a::1/128", Endpoint: "2001:db8:b::1",
		TEID: 0x100, TEIDLen: 32, QFI: 5, SRv6SID: "fd00:6:6:b::",
	}})

	entry := fh.v6created["2001:db8:a::1/128"]
	if entry == nil {
		t.Fatalf("CreateHeadendV6 not called")
	}
	plainSrc := netip.MustParsePrefix("fd00:1:1::/48").Masked().Addr().As16()
	if entry.SrcAddr != plainSrc {
		t.Errorf("GTP6 src = %v, want plain encap source %v",
			netip.AddrFrom16(entry.SrcAddr), netip.AddrFrom16(plainSrc))
	}
}

// The embed is scoped to the RD whose binding carries the prefix: a session
// under a different RD keeps the plain encap source even when its own T2ST
// anchor exists. This pins the per-VRF semantics of mup_gtp4_source_prefix.
func TestApplyMUP_T1ST_GTP4SourceEmbed_RDScoped(t *testing.T) {
	fh := newFakeHeadend()
	a := newMUPApplierWithGTP4Src(t, fh, "65000:100", "::/0")

	const otherRD = "65000:200"
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyMUPIPv4, MUP: &bgp.MUPRoute{
		Type: bgp.MUPRouteTypeT2ST, RD: otherRD, Endpoint: "172.16.0.254",
		TEID: 0x100, TEIDLen: 32,
	}})
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyMUPIPv4, MUP: &bgp.MUPRoute{
		Type: bgp.MUPRouteTypeT1ST, RD: otherRD,
		Prefix: "10.1.0.1/32", Endpoint: "172.16.0.1", TEID: 0x100, TEIDLen: 32, QFI: 9,
		SRv6SID: "fd00:2:2:b::",
	}})

	entry := fh.v4created["10.1.0.1/32"]
	if entry == nil {
		t.Fatalf("CreateHeadendV4 not called")
	}
	plainSrc := netip.MustParsePrefix("fd00:1:1::/48").Masked().Addr().As16()
	if entry.SrcAddr != plainSrc {
		t.Errorf("other-RD src = %v, want plain encap source %v",
			netip.AddrFrom16(entry.SrcAddr), netip.AddrFrom16(plainSrc))
	}
}

// A runtime binding mutation (VrfBgpService) drives ReconcileMUPGTP4SrcForRD:
// a changed prefix re-embeds the installed downlink's outer source, and a
// removed prefix reverts it to the plain encap source — the hook does not
// gate on a prefix being present, unlike the T2ST-driven internal path.
func TestApplyMUP_GTP4SourceEmbed_RuntimeReconcile(t *testing.T) {
	fh := newFakeHeadend()
	const rd = "65000:100"
	vm := vrfbgp.NewManager()
	bindMUPGTP4Src(t, vm, "vrf-mup", rd, "::/0")
	a := NewApplier(fh, testLocatorManager(t), vm, &fakeFib{}, "LOC1", 65000, zap.NewNop())

	a.Apply(bgp.RouteEvent{Family: bgp.FamilyMUPIPv4, MUP: &bgp.MUPRoute{
		Type: bgp.MUPRouteTypeT2ST, RD: rd, Endpoint: "172.16.0.254",
		TEID: 0x100, TEIDLen: 32,
	}})
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyMUPIPv4, MUP: &bgp.MUPRoute{
		Type: bgp.MUPRouteTypeT1ST, RD: rd,
		Prefix: "10.1.0.1/32", Endpoint: "172.16.0.1", TEID: 0x100, TEIDLen: 32, QFI: 9,
		SRv6SID: "fd00:2:2:b::",
	}})
	if got, want := fh.v4created["10.1.0.1/32"].SrcAddr, netip.MustParseAddr("ac10:fe::").As16(); got != want {
		t.Fatalf("src = %v, want embedded %v", netip.AddrFrom16(got), netip.AddrFrom16(want))
	}

	// Re-bind with a different prefix and drive the hook: the install follows.
	bindMUPGTP4Src(t, vm, "vrf-mup", rd, "2001:cafe:0:1::/64")
	a.ReconcileMUPGTP4SrcForRD(rd)
	if got, want := fh.v4created["10.1.0.1/32"].SrcAddr, netip.MustParseAddr("2001:cafe:0:1:ac10:fe::").As16(); got != want {
		t.Fatalf("src after prefix change = %v, want %v", netip.AddrFrom16(got), netip.AddrFrom16(want))
	}

	// Re-bind without a prefix and drive the hook: the install reverts.
	if err := vm.Bind(vrfbgp.Binding{VRFName: "vrf-mup", RD: rd}); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	a.ReconcileMUPGTP4SrcForRD(rd)
	plainSrc := netip.MustParsePrefix("fd00:1:1::/48").Masked().Addr().As16()
	if got := fh.v4created["10.1.0.1/32"].SrcAddr; got != plainSrc {
		t.Errorf("src after prefix removal = %v, want plain encap source %v",
			netip.AddrFrom16(got), netip.AddrFrom16(plainSrc))
	}
}

// A T2ST whose RTs match a VRF binding installs its F-TEID entry under that
// VRF's vrf_id, and the binding-mutation reconcile re-keys it when the
// resolved VRF changes (here: unbind drops the match, so the session falls
// back to the global VRF, id 0). The route carries its own SID so resolution
// does not depend on a DSD.
func TestApplyMUP_T2ST_UplinkInstanceScoping(t *testing.T) {
	fh := newFakeHeadend()
	vm := vrfbgp.NewManager()
	if err := vm.Bind(vrfbgp.Binding{
		VRFName: "vrf-a",
		Families: map[bgp.Family]vrfbgp.FamilyPolicy{
			bgp.FamilyMUPIPv4: {RouteTargets: []vrfbgp.RouteTarget{{RT: "100:1", Direction: vrfbgp.DirectionImport}}},
		},
	}); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	// Bind Ensures the VRF object, which allocates a non-zero vrf_id (0 is the
	// global VRF). The T2ST's F-TEID entry keys under that id.
	inst, ok := vm.VRF().IDForName("vrf-a")
	if !ok || inst == vrf.GlobalVRFID {
		t.Fatalf("VRF vrf-a got id %d (ok=%v), want a non-global id", inst, ok)
	}
	a := NewApplier(fh, testLocatorManager(t), vm, &fakeFib{}, "LOC1", 65000, zap.NewNop())

	const (
		endpoint = "192.0.2.100"
		direct   = "fd00:3:3:c::"
		teid     = uint32(0x100)
	)
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyMUPIPv4, MUP: &bgp.MUPRoute{
		Type: bgp.MUPRouteTypeT2ST, RD: "65000:100", RTs: []string{"100:1"},
		Endpoint: endpoint, TEID: teid, TEIDLen: 32, SRv6SID: direct,
	}})

	if _, ok := fh.mupUplink[mupUplinkKey{inst, endpoint, teid, 32}]; !ok {
		t.Fatalf("uplink entry not keyed under vrf_id %d; mupUplink=%v", inst, fh.mupUplink)
	}

	// Unbind drops the RT match; the reconcile re-keys the session back to the
	// global VRF (id 0), since no binding now claims the route.
	if err := vm.Unbind("vrf-a"); err != nil {
		t.Fatalf("Unbind: %v", err)
	}
	a.ReconcileMUPUplinkInstances()
	if _, ok := fh.mupUplink[mupUplinkKey{inst, endpoint, teid, 32}]; ok {
		t.Errorf("old vrf_id key still installed after re-key; mupUplink=%v", fh.mupUplink)
	}
	if _, ok := fh.mupUplink[mupUplinkKey{vrf.GlobalVRFID, endpoint, teid, 32}]; !ok {
		t.Errorf("session not re-keyed to the global VRF; mupUplink=%v", fh.mupUplink)
	}
	// The re-key must move only the F-TEID entry: deleting the shared gate —
	// even transiently — would let GTP-U pass unprocessed.
	for _, p := range fh.v4deleted {
		if p == endpoint+"/32" {
			t.Errorf("re-key deleted the endpoint gate; v4deleted=%v", fh.v4deleted)
		}
	}
}
