package export

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"golang.org/x/sys/unix"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/locator"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

// fakeAdvertiser records advertise / withdraw calls so a test can assert what
// the exporter pushed without a live BGP session.
type fakeAdvertiser struct {
	advertised []bgp.VPNRoute
	unicast    []bgp.UnicastRoute
	withdrawn  []bgp.RouteKey
	advErr     error
}

func (f *fakeAdvertiser) Advertise(_ context.Context, r bgp.VPNRoute) error {
	if f.advErr != nil {
		return f.advErr
	}
	f.advertised = append(f.advertised, r)
	return nil
}

func (f *fakeAdvertiser) AdvertiseUnicast(_ context.Context, r bgp.UnicastRoute) error {
	f.unicast = append(f.unicast, r)
	return nil
}

func (f *fakeAdvertiser) Withdraw(_ context.Context, key bgp.RouteKey) error {
	f.withdrawn = append(f.withdrawn, key)
	return nil
}

// sidCreate captures one CreateSidFunction call's identity (the trigger
// prefix and the endpoint behavior).
type sidCreate struct {
	prefix string
	action uint8
}

type fakeSidOps struct {
	created    []sidCreate
	deleted    []string
	failOnCall int // 0 = never; N = fail the Nth CreateSidFunction call
	calls      int
}

func (f *fakeSidOps) CreateSidFunction(triggerPrefix string, entry *bpf.SidFunctionEntry, _ *bpf.SidAuxEntry, _ bpf.OwnerTag) error {
	f.calls++
	if f.failOnCall != 0 && f.calls == f.failOnCall {
		return errors.New("create failed")
	}
	f.created = append(f.created, sidCreate{prefix: triggerPrefix, action: entry.Action})
	return nil
}

func (f *fakeSidOps) DeleteSidFunction(triggerPrefix string, _ bpf.OwnerTag) error {
	f.deleted = append(f.deleted, triggerPrefix)
	return nil
}

type fakeResolver struct {
	ifindex uint32
	table   uint32
	err     error
}

func (f fakeResolver) Resolve(_ string) (uint32, uint32, error) {
	return f.ifindex, f.table, f.err
}

const testTable = 100

func newTestExporter(t *testing.T) (*Exporter, *fakeAdvertiser, *fakeSidOps) {
	t.Helper()
	return newTestExporterLogger(t, zap.NewNop())
}

func newTestExporterLogger(t *testing.T, logger *zap.Logger) (*Exporter, *fakeAdvertiser, *fakeSidOps) {
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
	adv := &fakeAdvertiser{}
	sid := &fakeSidOps{}
	e := New(adv, sid, locs, vrfbgp.NewManager(), fakeResolver{ifindex: 10, table: testTable}, "2001:db8:ff::1", UnderlayConfig{}, logger)
	return e, adv, sid
}

func testBinding() vrfbgp.Binding {
	return vrfbgp.Binding{
		VRFName:        "vrf1",
		RD:             "65000:100",
		ExportRTs:      []string{"65000:100"},
		DefaultLocator: "LOC1",
	}
}

// sidForAction returns the trigger prefix the exporter installed for the given
// endpoint behavior, so a test can correlate an advertised SID back to its
// sid_function_map entry.
func sidForAction(created []sidCreate, action uint8) (string, bool) {
	for _, c := range created {
		if c.action == action {
			return c.prefix, true
		}
	}
	return "", false
}

func TestEnableVRFInstallsBothEndpointSIDs(t *testing.T) {
	e, _, sid := newTestExporter(t)
	if _, err := e.EnableVRF(testBinding()); err != nil {
		t.Fatalf("EnableVRF: %v", err)
	}
	if len(sid.created) != 2 {
		t.Fatalf("want 2 endpoint SIDs installed, got %d: %+v", len(sid.created), sid.created)
	}
	if _, ok := sidForAction(sid.created, endpointActionDT4); !ok {
		t.Errorf("no End.DT4 SID installed: %+v", sid.created)
	}
	if _, ok := sidForAction(sid.created, endpointActionDT6); !ok {
		t.Errorf("no End.DT6 SID installed: %+v", sid.created)
	}
}

func TestEnableVRFRejectsMissingRDOrLocator(t *testing.T) {
	e, _, _ := newTestExporter(t)
	noRD := testBinding()
	noRD.RD = ""
	if _, err := e.EnableVRF(noRD); err == nil {
		t.Error("EnableVRF without RD should fail")
	}
	noLoc := testBinding()
	noLoc.DefaultLocator = ""
	if _, err := e.EnableVRF(noLoc); err == nil {
		t.Error("EnableVRF without default_locator should fail")
	}
}

func TestEnableVRFRejectsDuplicate(t *testing.T) {
	e, _, _ := newTestExporter(t)
	if _, err := e.EnableVRF(testBinding()); err != nil {
		t.Fatalf("first EnableVRF: %v", err)
	}
	if _, err := e.EnableVRF(testBinding()); err == nil {
		t.Error("second EnableVRF for the same VRF should fail")
	}
}

func TestEnableVRFRollsBackDT4WhenDT6Fails(t *testing.T) {
	e, _, sid := newTestExporter(t)
	// DT4 installs (call 1), DT6 (call 2) fails -> the DT4 rollback path runs.
	sid.failOnCall = 2
	if _, err := e.EnableVRF(testBinding()); err == nil {
		t.Fatal("EnableVRF should fail when the DT6 SID install fails")
	}
	if len(sid.created) != 1 {
		t.Fatalf("want 1 SID installed (DT4) before the failure, got %d", len(sid.created))
	}
	if len(sid.deleted) != 1 {
		t.Fatalf("want the DT4 SID rolled back, got %d deletes", len(sid.deleted))
	}
	if sid.created[0].prefix != sid.deleted[0] {
		t.Errorf("rolled-back SID %q != installed DT4 SID %q", sid.deleted[0], sid.created[0].prefix)
	}
	// Re-enable must work (the DT4 function was returned to the pool).
	sid.failOnCall = 0
	if _, err := e.EnableVRF(testBinding()); err != nil {
		t.Fatalf("re-enable after rollback: %v", err)
	}
}

func TestOnRouteAdvertisesV4(t *testing.T) {
	e, adv, sid := newTestExporter(t)
	if _, err := e.EnableVRF(testBinding()); err != nil {
		t.Fatalf("EnableVRF: %v", err)
	}
	e.OnRoute(testTable, netip.MustParsePrefix("10.0.0.0/24"), true)

	if len(adv.advertised) != 1 {
		t.Fatalf("want 1 advertised route, got %d", len(adv.advertised))
	}
	r := adv.advertised[0]
	if r.Family != bgp.FamilyVPNv4 {
		t.Errorf("family = %q, want vpnv4", r.Family)
	}
	if r.Prefix != "10.0.0.0/24" {
		t.Errorf("prefix = %q", r.Prefix)
	}
	if r.RD != "65000:100" {
		t.Errorf("rd = %q", r.RD)
	}
	if len(r.RTs) != 1 || r.RTs[0] != "65000:100" {
		t.Errorf("rts = %v", r.RTs)
	}
	if r.NextHop != "2001:db8:ff::1" {
		t.Errorf("nexthop = %q, want 2001:db8:ff::1", r.NextHop)
	}
	wantSID, ok := sidForAction(sid.created, endpointActionDT4)
	if !ok || r.SRv6SID+"/128" != wantSID {
		t.Errorf("SID = %q, want the DT4 endpoint %q", r.SRv6SID, wantSID)
	}
}

func TestOnRouteAdvertisesV6(t *testing.T) {
	e, adv, sid := newTestExporter(t)
	if _, err := e.EnableVRF(testBinding()); err != nil {
		t.Fatalf("EnableVRF: %v", err)
	}
	e.OnRoute(testTable, netip.MustParsePrefix("2001:db8::/64"), true)

	if len(adv.advertised) != 1 {
		t.Fatalf("want 1 advertised route, got %d", len(adv.advertised))
	}
	r := adv.advertised[0]
	if r.Family != bgp.FamilyVPNv6 {
		t.Errorf("family = %q, want vpnv6", r.Family)
	}
	wantSID, ok := sidForAction(sid.created, endpointActionDT6)
	if !ok || r.SRv6SID+"/128" != wantSID {
		t.Errorf("SID = %q, want the DT6 endpoint %q", r.SRv6SID, wantSID)
	}
}

func TestOnRouteIgnoresUnknownTable(t *testing.T) {
	e, adv, _ := newTestExporter(t)
	if _, err := e.EnableVRF(testBinding()); err != nil {
		t.Fatalf("EnableVRF: %v", err)
	}
	e.OnRoute(testTable+1, netip.MustParsePrefix("10.0.0.0/24"), true)
	if len(adv.advertised) != 0 {
		t.Errorf("a route in an unowned table must not be advertised, got %d", len(adv.advertised))
	}
}

func TestOnRouteWithdrawMirrorsAdvertise(t *testing.T) {
	e, adv, _ := newTestExporter(t)
	if _, err := e.EnableVRF(testBinding()); err != nil {
		t.Fatalf("EnableVRF: %v", err)
	}
	prefix := netip.MustParsePrefix("10.0.0.0/24")
	e.OnRoute(testTable, prefix, true)
	e.OnRoute(testTable, prefix, false)

	if len(adv.withdrawn) != 1 {
		t.Fatalf("want 1 withdraw, got %d", len(adv.withdrawn))
	}
	k := adv.withdrawn[0]
	if k.Family != bgp.FamilyVPNv4 || k.Prefix != "10.0.0.0/24" || k.RD != "65000:100" {
		t.Errorf("withdraw key = %+v", k)
	}
}

func TestDisableVRFWithdrawsAllAndReleases(t *testing.T) {
	e, adv, sid := newTestExporter(t)
	if _, err := e.EnableVRF(testBinding()); err != nil {
		t.Fatalf("EnableVRF: %v", err)
	}
	e.OnRoute(testTable, netip.MustParsePrefix("10.0.0.0/24"), true)
	e.OnRoute(testTable, netip.MustParsePrefix("10.0.1.0/24"), true)

	e.DisableVRF("vrf1")

	if len(adv.withdrawn) != 2 {
		t.Errorf("want 2 prefixes withdrawn on disable, got %d", len(adv.withdrawn))
	}
	if len(sid.deleted) != 2 {
		t.Errorf("want 2 endpoint SIDs deleted on disable, got %d", len(sid.deleted))
	}
	// The VRF is gone, so re-enabling must succeed (and reusing the released
	// functions must not error).
	if _, err := e.EnableVRF(testBinding()); err != nil {
		t.Fatalf("re-enable after disable: %v", err)
	}
}

func TestOnRouteRespectsMaxPrefixes(t *testing.T) {
	e, adv, _ := newTestExporter(t)
	b := testBinding()
	b.MaxPrefixes = 1
	if _, err := e.EnableVRF(b); err != nil {
		t.Fatalf("EnableVRF: %v", err)
	}
	e.OnRoute(testTable, netip.MustParsePrefix("10.0.0.0/24"), true)
	e.OnRoute(testTable, netip.MustParsePrefix("10.0.1.0/24"), true)
	if len(adv.advertised) != 1 {
		t.Errorf("max_prefixes=1 should cap advertisements at 1, got %d", len(adv.advertised))
	}
}

// A flood of over-cap prefixes logs the cap-reached warning once, not once per
// dropped prefix, and a withdraw that frees headroom re-arms the warning.
func TestOnRouteMaxPrefixesLogsOncePerCrossing(t *testing.T) {
	core, logs := observer.New(zapcore.WarnLevel)
	e, _, _ := newTestExporterLogger(t, zap.New(core))
	b := testBinding()
	b.MaxPrefixes = 1
	if _, err := e.EnableVRF(b); err != nil {
		t.Fatalf("EnableVRF: %v", err)
	}
	const msg = "VRF prefix limit reached; capping auto-advertise"
	e.OnRoute(testTable, netip.MustParsePrefix("10.0.0.0/24"), true) // advertised (1/1)
	e.OnRoute(testTable, netip.MustParsePrefix("10.0.1.0/24"), true) // capped, logs once
	e.OnRoute(testTable, netip.MustParsePrefix("10.0.2.0/24"), true) // still capped, no new log
	if n := logs.FilterMessage(msg).Len(); n != 1 {
		t.Fatalf("a flood of over-cap prefixes must log once, got %d", n)
	}
	// Withdraw the advertised prefix to free headroom, then overflow again: the
	// warning re-arms, so a second crossing logs once more.
	e.OnRoute(testTable, netip.MustParsePrefix("10.0.0.0/24"), false)
	e.OnRoute(testTable, netip.MustParsePrefix("10.0.3.0/24"), true) // fills the freed slot
	e.OnRoute(testTable, netip.MustParsePrefix("10.0.4.0/24"), true) // capped again, logs once more
	if n := logs.FilterMessage(msg).Len(); n != 2 {
		t.Errorf("a fresh crossing after freeing headroom must log again, got %d total", n)
	}
}

func TestCloseDisablesEveryVRF(t *testing.T) {
	e, adv, _ := newTestExporter(t)
	if _, err := e.EnableVRF(testBinding()); err != nil {
		t.Fatalf("EnableVRF: %v", err)
	}
	e.OnRoute(testTable, netip.MustParsePrefix("10.0.0.0/24"), true)
	e.Close()
	if len(adv.withdrawn) != 1 {
		t.Errorf("Close should withdraw advertised routes, got %d", len(adv.withdrawn))
	}
}

func TestOnRouteUnderlayAdvertisesIPv6Unicast(t *testing.T) {
	e, adv, _ := newTestExporter(t)
	e.underlay = &underlayState{advertised: make(map[bgp.RouteKey]struct{})}
	e.OnRoute(unix.RT_TABLE_MAIN, netip.MustParsePrefix("2001:db8:ff::1/128"), true)
	if len(adv.unicast) != 1 {
		t.Fatalf("want 1 IPv6 unicast advertised, got %d", len(adv.unicast))
	}
	if adv.unicast[0].Prefix != "2001:db8:ff::1/128" || adv.unicast[0].NextHop != "2001:db8:ff::1" {
		t.Errorf("unicast route = %+v", adv.unicast[0])
	}
	// IPv4, link-local, and the default route are never SRv6 underlay
	// advertisements; they must be skipped.
	e.OnRoute(unix.RT_TABLE_MAIN, netip.MustParsePrefix("10.9.0.0/24"), true)
	e.OnRoute(unix.RT_TABLE_MAIN, netip.MustParsePrefix("fe80::/64"), true)
	e.OnRoute(unix.RT_TABLE_MAIN, netip.MustParsePrefix("::/0"), true)
	if len(adv.unicast) != 1 {
		t.Errorf("IPv4 / link-local / default underlay routes must be skipped, got %d", len(adv.unicast))
	}
	// Withdraw on delete.
	e.OnRoute(unix.RT_TABLE_MAIN, netip.MustParsePrefix("2001:db8:ff::1/128"), false)
	if len(adv.withdrawn) != 1 {
		t.Errorf("underlay delete should withdraw, got %d", len(adv.withdrawn))
	}
}

func TestOnRouteWithdrawUnadvertisedIsNoop(t *testing.T) {
	e, adv, _ := newTestExporter(t)
	if _, err := e.EnableVRF(testBinding()); err != nil {
		t.Fatalf("EnableVRF: %v", err)
	}
	// Delete a prefix we never advertised (capped, or its Advertise failed):
	// must NOT issue a Withdraw that could hit another owner's same-NLRI path.
	e.OnRoute(testTable, netip.MustParsePrefix("10.5.0.0/24"), false)
	if len(adv.withdrawn) != 0 {
		t.Errorf("withdraw of an unadvertised prefix must be a no-op, got %d", len(adv.withdrawn))
	}
}

func TestEnableVRFRejectsReservedTable(t *testing.T) {
	// A VRF resolving to the reserved main table (254) must be rejected before
	// any SID is minted, so it never mis-dispatches into the underlay path.
	e := New(&fakeAdvertiser{}, &fakeSidOps{}, locator.NewManager(), vrfbgp.NewManager(),
		fakeResolver{ifindex: 10, table: unix.RT_TABLE_MAIN}, "2001:db8:ff::1", UnderlayConfig{}, zap.NewNop())
	if _, err := e.EnableVRF(testBinding()); err == nil {
		t.Error("EnableVRF must reject a VRF resolving to the reserved main table")
	}
}

func TestOnRouteUnderlayRespectsMaxPrefixes(t *testing.T) {
	adv := &fakeAdvertiser{}
	e := New(adv, &fakeSidOps{}, locator.NewManager(), vrfbgp.NewManager(),
		fakeResolver{ifindex: 10, table: testTable}, "2001:db8:ff::1",
		UnderlayConfig{Redistribute: []string{"connected"}, MaxPrefixes: 1}, zap.NewNop())
	e.underlay = &underlayState{advertised: make(map[bgp.RouteKey]struct{})}
	e.OnRoute(unix.RT_TABLE_MAIN, netip.MustParsePrefix("2001:db8:1::/64"), true)
	e.OnRoute(unix.RT_TABLE_MAIN, netip.MustParsePrefix("2001:db8:2::/64"), true)
	if len(adv.unicast) != 1 {
		t.Errorf("underlay max_prefixes=1 should cap at 1, got %d", len(adv.unicast))
	}
}

func TestEnableVRFRejectsDuplicateTable(t *testing.T) {
	e, _, _ := newTestExporter(t)
	if _, err := e.EnableVRF(testBinding()); err != nil {
		t.Fatalf("first EnableVRF: %v", err)
	}
	// Different VRF name, same table id (the fake resolver always returns
	// testTable), which would otherwise overwrite byTable and mis-attribute
	// prefixes.
	other := testBinding()
	other.VRFName = "vrf2"
	if _, err := e.EnableVRF(other); err == nil {
		t.Error("EnableVRF should reject a second VRF mapping to an already-exported table")
	}
}

func TestOnRouteAdvertiseFailureNotRecorded(t *testing.T) {
	e, adv, _ := newTestExporter(t)
	if _, err := e.EnableVRF(testBinding()); err != nil {
		t.Fatalf("EnableVRF: %v", err)
	}
	adv.advErr = errors.New("advertise failed")
	e.OnRoute(testTable, netip.MustParsePrefix("10.0.0.0/24"), true)
	// The advertise failed, so the route must NOT be recorded -- otherwise a
	// later disable/Close would withdraw a route that was never advertised.
	e.DisableVRF("vrf1")
	if len(adv.withdrawn) != 0 {
		t.Errorf("a failed advertise must not be recorded, but disable withdrew %d", len(adv.withdrawn))
	}
}

func TestOnRouteAddIsIdempotent(t *testing.T) {
	e, adv, _ := newTestExporter(t)
	if _, err := e.EnableVRF(testBinding()); err != nil {
		t.Fatalf("EnableVRF: %v", err)
	}
	p := netip.MustParsePrefix("10.0.0.0/24")
	e.OnRoute(testTable, p, true)
	e.OnRoute(testTable, p, true) // duplicate NEWROUTE / ListExisting refresh
	if len(adv.advertised) != 1 {
		t.Errorf("a duplicate add should advertise once, got %d", len(adv.advertised))
	}
}

// A runtime AddVRF for a binding with no redistribute set enables nothing: it is
// receive-only, so no Endpoint SID is minted and no table is watched.
func TestAddVRFEmptyRedistributeIsNoop(t *testing.T) {
	e, _, sid := newTestExporter(t)
	if err := e.AddVRF(testBinding()); err != nil { // testBinding has no Redistribute
		t.Fatalf("AddVRF with empty redistribute: %v", err)
	}
	if len(e.vrfs) != 0 {
		t.Errorf("a binding with no redistribute set must enable nothing; vrfs=%v", e.vrfs)
	}
	if len(sid.created) != 0 {
		t.Errorf("a no-op AddVRF must mint no Endpoint SID, got %d", len(sid.created))
	}
}

// When RegisterTable rejects the redistribute set, enableAndWatch self-disables
// the VRF so AddVRF leaves no SID installed -- the invariant Start's unwind now
// relies on. An unknown protocol keyword makes RegisterTable fail without
// touching netlink, so this stays a pure unit test.
func TestAddVRFRollsBackOnRegisterTableFailure(t *testing.T) {
	e, _, sid := newTestExporter(t)
	b := testBinding()
	b.Redistribute = []string{"bogus"}
	if err := e.AddVRF(b); err == nil {
		t.Fatal("AddVRF should fail when RegisterTable rejects the redistribute set")
	}
	if len(e.vrfs) != 0 {
		t.Errorf("a RegisterTable failure must self-disable the VRF; vrfs=%v", e.vrfs)
	}
	if len(sid.created) != 2 || len(sid.deleted) != 2 {
		t.Errorf("both Endpoint SIDs must be minted then rolled back; created=%d deleted=%d",
			len(sid.created), len(sid.deleted))
	}
}

// RemoveVRF of an unknown VRF is a no-op: nothing to withdraw, no SID to release.
func TestRemoveVRFUnknownIsNoop(t *testing.T) {
	e, adv, sid := newTestExporter(t)
	e.RemoveVRF("nope")
	if len(adv.withdrawn) != 0 || len(sid.deleted) != 0 {
		t.Errorf("RemoveVRF of an unknown VRF must be a no-op; withdrawn=%d deleted=%d",
			len(adv.withdrawn), len(sid.deleted))
	}
}

// RemoveVRF withdraws the VRF's advertised prefixes, releases both Endpoint
// SIDs, and unregisters its table from the watcher.
func TestRemoveVRFWithdrawsAndUnregisters(t *testing.T) {
	e, adv, sid := newTestExporter(t)
	if _, err := e.EnableVRF(testBinding()); err != nil {
		t.Fatalf("EnableVRF: %v", err)
	}
	if err := e.watcher.RegisterTable(testTable, []string{"connected"}); err != nil {
		t.Fatalf("RegisterTable: %v", err)
	}
	e.OnRoute(testTable, netip.MustParsePrefix("10.0.0.0/24"), true)

	e.RemoveVRF("vrf1")

	if len(adv.withdrawn) != 1 {
		t.Errorf("RemoveVRF must withdraw the advertised prefix, got %d", len(adv.withdrawn))
	}
	if len(sid.deleted) != 2 {
		t.Errorf("RemoveVRF must release both Endpoint SIDs, got %d", len(sid.deleted))
	}
	// The table must be unregistered: DumpTable now reports it as not registered,
	// a pure check that returns before touching netlink.
	if err := e.watcher.DumpTable(testTable); err == nil {
		t.Error("RemoveVRF must unregister the table from the watcher")
	}
}
