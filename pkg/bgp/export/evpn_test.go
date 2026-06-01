package export

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/locator"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

// fakeEVPNAdv records RT2 (MAC/IP) and RT3 (Inclusive Multicast) advertise /
// withdraw calls.
type fakeEVPNAdv struct {
	pushed         []bgp.EVPNRoute
	withdrawn      []bgp.EVPNMACKey
	pushedMcast    []bgp.EVPNRoute
	withdrawnMcast []bgp.EVPNMcastKey
	pushedES       []bgp.EVPNRoute
	withdrawnES    []bgp.EVPNESKey
	pushErr        error
}

func (f *fakeEVPNAdv) PushEVPNMac(_ context.Context, r bgp.EVPNRoute) error {
	if f.pushErr != nil {
		return f.pushErr
	}
	f.pushed = append(f.pushed, r)
	return nil
}

func (f *fakeEVPNAdv) WithdrawEVPNMac(_ context.Context, key bgp.EVPNMACKey) error {
	f.withdrawn = append(f.withdrawn, key)
	return nil
}

func (f *fakeEVPNAdv) PushEVPNInclusiveMulticast(_ context.Context, r bgp.EVPNRoute) error {
	if f.pushErr != nil {
		return f.pushErr
	}
	f.pushedMcast = append(f.pushedMcast, r)
	return nil
}

func (f *fakeEVPNAdv) WithdrawEVPNInclusiveMulticast(_ context.Context, key bgp.EVPNMcastKey) error {
	f.withdrawnMcast = append(f.withdrawnMcast, key)
	return nil
}

func (f *fakeEVPNAdv) PushEVPNEthernetSegment(_ context.Context, r bgp.EVPNRoute) error {
	if f.pushErr != nil {
		return f.pushErr
	}
	f.pushedES = append(f.pushedES, r)
	return nil
}

func (f *fakeEVPNAdv) WithdrawEVPNEthernetSegment(_ context.Context, key bgp.EVPNESKey) error {
	f.withdrawnES = append(f.withdrawnES, key)
	return nil
}

func newTestEVPNExporter(t *testing.T) (*EVPNExporter, *fakeEVPNAdv, *fakeSidOps) {
	t.Helper()
	locs := locator.NewManager()
	if err := locs.Add(&locator.Locator{
		Name:              "LOC1",
		Prefix:            netip.MustParsePrefix("fd00:1:1::/48"),
		BlockLen:          32,
		NodeLen:           16,
		FunctionLen:       16,
		ArgumentLen:       64,
		Behavior:          locator.BehaviorClassic,
		FunctionAutoStart: 0x10,
		FunctionAutoEnd:   0xfffe,
	}); err != nil {
		t.Fatalf("add locator: %v", err)
	}
	adv := &fakeEVPNAdv{}
	sid := &fakeSidOps{}
	e := NewEVPNExporter(adv, sid, locs, "2001:db8:ff::1", zap.NewNop())
	return e, adv, sid
}

func evpnTestBinding() vrfbgp.Binding {
	return vrfbgp.Binding{
		VRFName:        "evi100",
		RD:             "65000:100",
		ExportRTs:      []string{"65000:100"},
		DefaultLocator: "LOC1",
		BDID:           100,
	}
}

func TestEnableBDInstallsBothL2SIDs(t *testing.T) {
	e, adv, sid := newTestEVPNExporter(t)
	if err := e.EnableBD(evpnTestBinding(), 10); err != nil {
		t.Fatalf("EnableBD: %v", err)
	}
	if len(sid.created) != 2 {
		t.Fatalf("want 2 L2 SIDs installed (DT2U + DT2M), got %d: %+v", len(sid.created), sid.created)
	}
	if _, ok := sidForAction(sid.created, endpointActionDT2U); !ok {
		t.Errorf("no End.DT2U SID installed: %+v", sid.created)
	}
	if _, ok := sidForAction(sid.created, endpointActionDT2M); !ok {
		t.Errorf("no End.DT2M SID installed: %+v", sid.created)
	}
	// RT3 (Inclusive Multicast) is advertised once at enable, carrying the DT2M SID.
	if len(adv.pushedMcast) != 1 {
		t.Fatalf("want 1 RT3 advertised at enable, got %d", len(adv.pushedMcast))
	}
	r3 := adv.pushedMcast[0]
	if r3.Type != bgp.EVPNRouteTypeInclusiveMulticast {
		t.Errorf("type = %d, want RT3 inclusive multicast", r3.Type)
	}
	dt2m, _ := sidForAction(sid.created, endpointActionDT2M)
	if r3.SRv6SID+"/128" != dt2m {
		t.Errorf("RT3 SID = %q, want the installed End.DT2M %q", r3.SRv6SID, dt2m)
	}
	if r3.RD != "65000:100" || r3.NextHop != "2001:db8:ff::1" || r3.RemoteSrc != "fd00:1:1::" {
		t.Errorf("RT3 fields wrong: %+v", r3)
	}
}

func TestEnableBDRollsBackDT2UWhenDT2MFails(t *testing.T) {
	e, _, sid := newTestEVPNExporter(t)
	// DT2U installs (call 1), DT2M (call 2) fails -> the DT2U rollback path runs.
	sid.failOnCall = 2
	if err := e.EnableBD(evpnTestBinding(), 10); err == nil {
		t.Fatal("EnableBD should fail when the End.DT2M SID install fails")
	}
	if len(sid.created) != 1 {
		t.Fatalf("want only the DT2U SID created before the failure, got %d", len(sid.created))
	}
	if len(sid.deleted) != 1 {
		t.Fatalf("want the DT2U SID rolled back, got %d deletes", len(sid.deleted))
	}
	if sid.created[0].prefix != sid.deleted[0] {
		t.Errorf("rolled-back SID %q != installed DT2U %q", sid.deleted[0], sid.created[0].prefix)
	}
	// Re-enable must work (the DT2U function was returned to the pool).
	sid.failOnCall = 0
	if err := e.EnableBD(evpnTestBinding(), 10); err != nil {
		t.Fatalf("re-enable after rollback: %v", err)
	}
}

func TestEnableBDRollbackFailureSurfacesStrandedSID(t *testing.T) {
	e, _, sid := newTestEVPNExporter(t)
	sid.failOnCall = 2                       // DT2M install fails
	sid.deleteErr = errors.New("map locked") // the DT2U rollback delete also fails
	err := e.EnableBD(evpnTestBinding(), 10)
	if err == nil {
		t.Fatal("EnableBD should fail when both the DT2M install and the DT2U rollback fail")
	}
	if !strings.Contains(err.Error(), "stranded") {
		t.Errorf("error should surface the stranded DT2U SID, got: %v", err)
	}
}

func TestEnableBDRejectsInvalidNextHop(t *testing.T) {
	locs := locator.NewManager()
	if err := locs.Add(&locator.Locator{
		Name: "LOC1", Prefix: netip.MustParsePrefix("fd00:1:1::/48"),
		BlockLen: 32, NodeLen: 16, FunctionLen: 16, ArgumentLen: 64,
		Behavior: locator.BehaviorClassic, FunctionAutoStart: 0x10, FunctionAutoEnd: 0xfffe,
	}); err != nil {
		t.Fatalf("add locator: %v", err)
	}
	for _, nh := range []string{"", "10.0.0.1", "not-an-ip"} {
		e := NewEVPNExporter(&fakeEVPNAdv{}, &fakeSidOps{}, locs, nh, zap.NewNop())
		if err := e.EnableBD(evpnTestBinding(), 10); err == nil {
			t.Errorf("EnableBD with next_hop %q should fail (must be a valid IPv6)", nh)
		}
	}
}

func TestEnableBDRejectsMissingFields(t *testing.T) {
	e, _, _ := newTestEVPNExporter(t)
	noBD := evpnTestBinding()
	noBD.BDID = 0
	if err := e.EnableBD(noBD, 10); err == nil {
		t.Error("EnableBD without bd_id should fail")
	}
	noRD := evpnTestBinding()
	noRD.RD = ""
	if err := e.EnableBD(noRD, 10); err == nil {
		t.Error("EnableBD without RD should fail")
	}
	badLoc := evpnTestBinding()
	badLoc.DefaultLocator = "NOPE"
	if err := e.EnableBD(badLoc, 10); err == nil {
		t.Error("EnableBD with an unknown locator should fail")
	}
}

func TestSIDsForBD(t *testing.T) {
	e, _, _ := newTestEVPNExporter(t)
	if got := e.SIDsForBD(100); got != nil {
		t.Errorf("SIDsForBD must be nil before the BD is enabled, got %v", got)
	}
	if err := e.EnableBD(evpnTestBinding(), 10); err != nil {
		t.Fatalf("EnableBD: %v", err)
	}
	got := e.SIDsForBD(100)
	if len(got) != 2 {
		t.Fatalf("SIDsForBD(100) should return both the DT2U and DT2M keys, got %v", got)
	}
	// Both must be valid "<addr>/128" sid_function_map keys and distinct.
	if got[0] == got[1] {
		t.Errorf("the DT2U and DT2M keys must differ, got %v", got)
	}
	for _, k := range got {
		if _, _, err := net.ParseCIDR(k); err != nil {
			t.Errorf("SID key %q is not a valid prefix: %v", k, err)
		}
	}
	e.DisableBD(100)
	if got := e.SIDsForBD(100); got != nil {
		t.Errorf("SIDsForBD must be nil after the BD is disabled, got %v", got)
	}
}

func TestOnLocalMACAdvertisesRT2(t *testing.T) {
	e, adv, sid := newTestEVPNExporter(t)
	if err := e.EnableBD(evpnTestBinding(), 10); err != nil {
		t.Fatalf("EnableBD: %v", err)
	}
	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}
	e.OnLocalMAC(100, mac, true)

	if len(adv.pushed) != 1 {
		t.Fatalf("want 1 RT2 advertised, got %d", len(adv.pushed))
	}
	r := adv.pushed[0]
	if r.Type != bgp.EVPNRouteTypeMACIP {
		t.Errorf("type = %d, want RT2", r.Type)
	}
	if r.RD != "65000:100" {
		t.Errorf("rd = %q", r.RD)
	}
	if len(r.RTs) != 1 || r.RTs[0] != "65000:100" {
		t.Errorf("rts = %v", r.RTs)
	}
	if r.MAC != mac.String() {
		t.Errorf("mac = %q, want %q", r.MAC, mac.String())
	}
	if r.NextHop != "2001:db8:ff::1" {
		t.Errorf("nexthop = %q, want the configured loopback", r.NextHop)
	}
	if r.RemoteSrc != "fd00:1:1::" {
		t.Errorf("remote_src = %q, want the locator base fd00:1:1::", r.RemoteSrc)
	}
	dt2u, _ := sidForAction(sid.created, endpointActionDT2U)
	if r.SRv6SID+"/128" != dt2u {
		t.Errorf("SID = %q, want the installed End.DT2U %q", r.SRv6SID, dt2u)
	}
}

func TestOnLocalMACWithdrawMirrorsAdvertise(t *testing.T) {
	e, adv, _ := newTestEVPNExporter(t)
	if err := e.EnableBD(evpnTestBinding(), 10); err != nil {
		t.Fatalf("EnableBD: %v", err)
	}
	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}
	e.OnLocalMAC(100, mac, true)
	e.OnLocalMAC(100, mac, false)
	if len(adv.withdrawn) != 1 {
		t.Fatalf("want 1 withdraw, got %d", len(adv.withdrawn))
	}
	k := adv.withdrawn[0]
	if k.RD != "65000:100" || k.MAC != mac.String() || k.EthernetTag != 0 {
		t.Errorf("withdraw key = %+v", k)
	}
}

func TestOnLocalMACAddIsIdempotent(t *testing.T) {
	e, adv, _ := newTestEVPNExporter(t)
	if err := e.EnableBD(evpnTestBinding(), 10); err != nil {
		t.Fatalf("EnableBD: %v", err)
	}
	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}
	e.OnLocalMAC(100, mac, true)
	e.OnLocalMAC(100, mac, true) // duplicate learn
	if len(adv.pushed) != 1 {
		t.Errorf("a duplicate MAC learn should advertise once, got %d", len(adv.pushed))
	}
}

func TestOnLocalMACIgnoresUnboundBD(t *testing.T) {
	e, adv, _ := newTestEVPNExporter(t)
	e.OnLocalMAC(999, net.HardwareAddr{0xaa, 0, 0, 0, 0, 1}, true)
	if len(adv.pushed) != 0 {
		t.Errorf("a MAC in an unbound BD must not be advertised, got %d", len(adv.pushed))
	}
}

func TestOnLocalMACWithdrawUnadvertisedIsNoop(t *testing.T) {
	e, adv, _ := newTestEVPNExporter(t)
	if err := e.EnableBD(evpnTestBinding(), 10); err != nil {
		t.Fatalf("EnableBD: %v", err)
	}
	// Delete a MAC we never advertised: must not issue a withdraw.
	e.OnLocalMAC(100, net.HardwareAddr{0xaa, 0, 0, 0, 0, 9}, false)
	if len(adv.withdrawn) != 0 {
		t.Errorf("withdraw of an unadvertised MAC must be a no-op, got %d", len(adv.withdrawn))
	}
}

func TestDisableBDWithdrawsAllAndReleases(t *testing.T) {
	e, adv, sid := newTestEVPNExporter(t)
	if err := e.EnableBD(evpnTestBinding(), 10); err != nil {
		t.Fatalf("EnableBD: %v", err)
	}
	e.OnLocalMAC(100, net.HardwareAddr{0xaa, 0, 0, 0, 0, 1}, true)
	e.OnLocalMAC(100, net.HardwareAddr{0xaa, 0, 0, 0, 0, 2}, true)

	e.DisableBD(100)

	if len(adv.withdrawn) != 2 {
		t.Errorf("want 2 RT2 withdrawn on disable, got %d", len(adv.withdrawn))
	}
	if len(adv.withdrawnMcast) != 1 {
		t.Errorf("want the RT3 withdrawn on disable, got %d", len(adv.withdrawnMcast))
	}
	if len(sid.deleted) != 2 {
		t.Errorf("want both L2 SIDs (DT2U + DT2M) released on disable, got %d", len(sid.deleted))
	}
	// The BD is gone, so re-enabling must succeed.
	if err := e.EnableBD(evpnTestBinding(), 10); err != nil {
		t.Fatalf("re-enable after disable: %v", err)
	}
}

func TestOnLocalMACPushFailureNotRecorded(t *testing.T) {
	e, adv, _ := newTestEVPNExporter(t)
	if err := e.EnableBD(evpnTestBinding(), 10); err != nil {
		t.Fatalf("EnableBD: %v", err)
	}
	adv.pushErr = errors.New("push failed")
	e.OnLocalMAC(100, net.HardwareAddr{0xaa, 0, 0, 0, 0, 1}, true)
	// The push failed, so the MAC must not be recorded -- a later disable must
	// not withdraw a route that was never advertised.
	adv.pushErr = nil
	e.DisableBD(100)
	if len(adv.withdrawn) != 0 {
		t.Errorf("a failed push must not be recorded, but disable withdrew %d", len(adv.withdrawn))
	}
}

// A re-enable whose advertisement-affecting fields are unchanged is a no-op: no
// SID re-mint, no RT3 flap, and the already-advertised MACs stay tracked. A change
// to a receive-only field (import RTs) is likewise a no-op for origination.
func TestEnableBDIdempotentOnUnchangedReBind(t *testing.T) {
	e, adv, sid := newTestEVPNExporter(t)
	b := evpnTestBinding()
	if err := e.EnableBD(b, 10); err != nil {
		t.Fatalf("EnableBD: %v", err)
	}
	mac := net.HardwareAddr{0xaa, 0, 0, 0, 0, 1}
	e.OnLocalMAC(100, mac, true)
	createdBefore, mcastBefore := len(sid.created), len(adv.pushedMcast)

	// Re-bind with an identical binding + ifindex.
	if err := e.EnableBD(b, 10); err != nil {
		t.Fatalf("re-EnableBD: %v", err)
	}
	if len(sid.created) != createdBefore {
		t.Errorf("unchanged re-bind must not re-mint SIDs; created %d -> %d", createdBefore, len(sid.created))
	}
	if len(sid.deleted) != 0 {
		t.Errorf("unchanged re-bind must not release SIDs; deleted=%d", len(sid.deleted))
	}
	if len(adv.pushedMcast) != mcastBefore || len(adv.withdrawnMcast) != 0 {
		t.Errorf("unchanged re-bind must not flap RT3; pushedMcast=%d withdrawnMcast=%d", len(adv.pushedMcast), len(adv.withdrawnMcast))
	}

	// A change limited to a receive-only field (import RTs) does not affect what
	// this exporter originates, so it is still a no-op.
	b.ImportRTs = []string{"65000:999"}
	if err := e.EnableBD(b, 10); err != nil {
		t.Fatalf("import-rt-only re-EnableBD: %v", err)
	}
	if len(sid.deleted) != 0 || len(adv.withdrawnMcast) != 0 {
		t.Errorf("a receive-only import_rts change must not re-enable origination; deleted=%d withdrawnMcast=%d", len(sid.deleted), len(adv.withdrawnMcast))
	}

	// The MAC advertised before the re-binds is still tracked (state was preserved,
	// not rebuilt): withdrawing it fires exactly one withdraw.
	e.OnLocalMAC(100, mac, false)
	if len(adv.withdrawn) != 1 {
		t.Errorf("the pre-rebind MAC must still be tracked after a no-op re-bind; withdrawn=%d", len(adv.withdrawn))
	}
}

// A re-enable that changes an advertisement-affecting field (here the bridge
// ifindex) tears the BD down and re-enables cleanly: old SIDs released, new SIDs
// minted, RT3 withdrawn then re-advertised.
func TestEnableBDReEnablesOnChange(t *testing.T) {
	e, adv, sid := newTestEVPNExporter(t)
	b := evpnTestBinding()
	if err := e.EnableBD(b, 10); err != nil {
		t.Fatalf("EnableBD: %v", err)
	}
	if err := e.EnableBD(b, 20); err != nil { // bridge ifindex changed 10 -> 20
		t.Fatalf("changed re-EnableBD: %v", err)
	}
	if len(sid.deleted) != 2 {
		t.Errorf("a changed re-bind must release both old SIDs; deleted=%d want 2", len(sid.deleted))
	}
	if len(sid.created) != 4 {
		t.Errorf("a changed re-bind must re-mint both SIDs; created=%d want 4", len(sid.created))
	}
	if len(adv.withdrawnMcast) != 1 || len(adv.pushedMcast) != 2 {
		t.Errorf("a changed re-bind must flap RT3; pushedMcast=%d withdrawnMcast=%d", len(adv.pushedMcast), len(adv.withdrawnMcast))
	}
}

// testESI is a Type-0 ESI whose value's high-order 6 octets (bytes 1..6) encode
// the MAC aa:bb:cc:dd:ee:ff, which RFC 7432 Sec. 7.6 derives as the ES-Import RT.
var testESI = [bpf.ESILen]byte{0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02, 0x03}

func TestEnableESAdvertisesRT4(t *testing.T) {
	e, adv, sid := newTestEVPNExporter(t)
	if err := e.EnableES(testESI, "65000:200"); err != nil {
		t.Fatalf("EnableES: %v", err)
	}
	if len(adv.pushedES) != 1 {
		t.Fatalf("want 1 RT4 advertised, got %d", len(adv.pushedES))
	}
	r := adv.pushedES[0]
	if r.Type != bgp.EVPNRouteTypeEthernetSegment {
		t.Errorf("type = %d, want RT4", r.Type)
	}
	if r.RD != "65000:200" {
		t.Errorf("rd = %q", r.RD)
	}
	if r.ESI != testESI {
		t.Errorf("esi = %x, want %x", r.ESI, testESI)
	}
	if r.ESImportRT != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("es_import_rt = %q, want aa:bb:cc:dd:ee:ff (derived from the ESI)", r.ESImportRT)
	}
	if r.NextHop != "2001:db8:ff::1" {
		t.Errorf("nexthop = %q, want the configured loopback", r.NextHop)
	}
	if r.SRv6SID != "" {
		t.Errorf("RT4 carries no SRv6 SID, got %q", r.SRv6SID)
	}
	// RT4 mints no SID.
	if len(sid.created) != 0 {
		t.Errorf("RT4 must not mint any SID, got %d", len(sid.created))
	}
}

func TestEnableESRejectsEmptyRDAndBadNextHop(t *testing.T) {
	e, _, _ := newTestEVPNExporter(t)
	if err := e.EnableES(testESI, ""); err == nil {
		t.Error("EnableES without an RD should fail")
	}
	bad := NewEVPNExporter(&fakeEVPNAdv{}, &fakeSidOps{}, locator.NewManager(), "10.0.0.1", zap.NewNop())
	if err := bad.EnableES(testESI, "65000:200"); err == nil {
		t.Error("EnableES with a non-IPv6 next_hop should fail")
	}
}

func TestDisableESWithdrawsRT4(t *testing.T) {
	e, adv, _ := newTestEVPNExporter(t)
	if err := e.EnableES(testESI, "65000:200"); err != nil {
		t.Fatalf("EnableES: %v", err)
	}
	e.DisableES(testESI)
	if len(adv.withdrawnES) != 1 {
		t.Fatalf("want 1 RT4 withdrawn, got %d", len(adv.withdrawnES))
	}
	k := adv.withdrawnES[0]
	if k.RD != "65000:200" || k.ESI != testESI {
		t.Errorf("withdraw key = %+v", k)
	}
	// A second disable is a no-op.
	e.DisableES(testESI)
	if len(adv.withdrawnES) != 1 {
		t.Errorf("disable of an unadvertised ES must be a no-op, got %d", len(adv.withdrawnES))
	}
}

func TestEnableESReplaces(t *testing.T) {
	e, adv, _ := newTestEVPNExporter(t)
	if err := e.EnableES(testESI, "65000:200"); err != nil {
		t.Fatalf("EnableES: %v", err)
	}
	// Re-enable with a different RD: the new RT4 is pushed (push-first) and the old
	// one, a different NLRI key, is withdrawn.
	if err := e.EnableES(testESI, "65000:201"); err != nil {
		t.Fatalf("re-EnableES: %v", err)
	}
	if len(adv.withdrawnES) != 1 || adv.withdrawnES[0].RD != "65000:200" {
		t.Errorf("re-enable must withdraw the prior RT4 (RD 65000:200), got %+v", adv.withdrawnES)
	}
	if len(adv.pushedES) != 2 || adv.pushedES[1].RD != "65000:201" {
		t.Errorf("re-enable must push the new RT4 (RD 65000:201), got %+v", adv.pushedES)
	}
}

// Re-enabling an ES with the SAME RD relies on gobgp AddPath superseding the
// same-NLRI path, so no explicit withdraw is issued (an explicit withdraw would
// race the re-push and could blackhole the ES).
func TestEnableESSameRDDoesNotWithdraw(t *testing.T) {
	e, adv, _ := newTestEVPNExporter(t)
	if err := e.EnableES(testESI, "65000:200"); err != nil {
		t.Fatalf("EnableES: %v", err)
	}
	if err := e.EnableES(testESI, "65000:200"); err != nil {
		t.Fatalf("re-EnableES same RD: %v", err)
	}
	if len(adv.withdrawnES) != 0 {
		t.Errorf("same-RD re-enable must not withdraw (AddPath supersedes), got %d", len(adv.withdrawnES))
	}
	if len(adv.pushedES) != 2 {
		t.Errorf("each EnableES re-pushes the RT4, got %d", len(adv.pushedES))
	}
}

// A failed re-EnableES push must leave the prior RT4 intact (push-first): the
// withdraw of the old advertisement only runs after the new push lands.
func TestEnableESPushFailureKeepsPrior(t *testing.T) {
	e, adv, _ := newTestEVPNExporter(t)
	if err := e.EnableES(testESI, "65000:200"); err != nil {
		t.Fatalf("EnableES: %v", err)
	}
	adv.pushErr = errors.New("push failed")
	if err := e.EnableES(testESI, "65000:201"); err == nil {
		t.Fatal("EnableES should return the push error")
	}
	if len(adv.withdrawnES) != 0 {
		t.Errorf("a failed re-EnableES must not withdraw the prior RT4, got %d", len(adv.withdrawnES))
	}
	if rd, ok := e.RDForESI(testESI); !ok || rd != "65000:200" {
		t.Errorf("the prior RD must remain advertised after a failed re-enable; RDForESI=%q,%v", rd, ok)
	}
}

func TestRDForESI(t *testing.T) {
	e, _, _ := newTestEVPNExporter(t)
	if _, ok := e.RDForESI(testESI); ok {
		t.Error("RDForESI must report not-advertised before EnableES")
	}
	if err := e.EnableES(testESI, "65000:200"); err != nil {
		t.Fatalf("EnableES: %v", err)
	}
	if rd, ok := e.RDForESI(testESI); !ok || rd != "65000:200" {
		t.Errorf("RDForESI = %q,%v want 65000:200,true", rd, ok)
	}
	e.DisableES(testESI)
	if _, ok := e.RDForESI(testESI); ok {
		t.Error("RDForESI must report not-advertised after DisableES")
	}
}

// MaxPrefixes bounds how many local MACs a bridge domain originates as RT2; a
// withdraw frees headroom for a later MAC.
func TestOnLocalMACMaxPrefixesCap(t *testing.T) {
	e, adv, _ := newTestEVPNExporter(t)
	b := evpnTestBinding()
	b.MaxPrefixes = 2
	if err := e.EnableBD(b, 10); err != nil {
		t.Fatalf("EnableBD: %v", err)
	}
	macs := []net.HardwareAddr{
		{0xaa, 0, 0, 0, 0, 1}, {0xaa, 0, 0, 0, 0, 2}, {0xaa, 0, 0, 0, 0, 3},
	}
	for _, m := range macs {
		e.OnLocalMAC(100, m, true)
	}
	if len(adv.pushed) != 2 {
		t.Fatalf("MaxPrefixes=2 must cap RT2 at 2, got %d", len(adv.pushed))
	}
	// Withdraw one (frees headroom), then a new MAC advertises again.
	e.OnLocalMAC(100, macs[0], false)
	e.OnLocalMAC(100, net.HardwareAddr{0xaa, 0, 0, 0, 0, 4}, true)
	if len(adv.pushed) != 3 {
		t.Errorf("freeing headroom must let a new MAC advertise; total pushed=%d, want 3", len(adv.pushed))
	}
}
