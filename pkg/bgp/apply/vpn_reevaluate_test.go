package apply_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/api/vinbero/v1/vinberov1connect"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bgp/apply"
	"github.com/takehaya/vinbero/pkg/config"
	"github.com/takehaya/vinbero/pkg/locator"
	"github.com/takehaya/vinbero/pkg/server"
	"github.com/takehaya/vinbero/pkg/vrf"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

// These tests run the applier behind the daemon's RPC server, with a fake
// loc-rib standing in for GoBGP: the server requests replays, the loc-rib
// re-delivers what it holds, and the assertions read the data plane. A
// binding change reaches the applier through a VPN loc-rib replay on the
// replayer's goroutine. A source locator registration writes the tracked
// routes within the LocatorCreate RPC and then requests an EVPN replay.

const sourceLocator = "LOC2"

// fakeRIB holds the routes a peer advertised and replays them the way
// demux.ReplayBuiltin does, excluding live delivery while it runs.
type fakeRIB struct {
	a      *apply.Applier
	mu     sync.Mutex
	routes map[string]bgp.RouteEvent
	done   chan struct{}
}

func (r *fakeRIB) deliver(ev bgp.RouteEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var key string
	switch {
	case ev.VPN != nil:
		key = ev.VPN.Prefix + "|" + ev.VPN.RD
	case ev.EVPN != nil:
		key = ev.EVPN.MAC + "|" + ev.EVPN.RD
	}
	if ev.IsWithdraw {
		delete(r.routes, key)
	} else {
		r.routes[key] = ev
	}
	r.a.Apply(ev)
}

// replay is what the daemon hands the server as its loc-rib replay.
func (r *fakeRIB) replay(families []bgp.Family) error {
	err := r.a.ReplayAndReconcile(func() error {
		r.mu.Lock()
		defer r.mu.Unlock()
		for _, ev := range r.routes {
			for _, fam := range families {
				if ev.Family == fam {
					r.a.Apply(ev)
				}
			}
		}
		return nil
	})
	r.done <- struct{}{}
	return err
}

// evpnReplay is what the daemon hands the server as its EVPN replay.
func (r *fakeRIB) evpnReplay() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, ev := range r.routes {
		if ev.Family == bgp.FamilyEVPN {
			r.a.Apply(ev)
		}
	}
}

type vpnLab struct {
	t        *testing.T
	dp       *apply.FakeDataPlane
	rib      *fakeRIB
	bindings *vrfbgp.Manager
	logs     *observer.ObservedLogs
	locator  vinberov1connect.LocatorServiceClient
	vrfBgp   vinberov1connect.VrfBgpServiceClient
}

func newVPNLab(t *testing.T) *vpnLab {
	t.Helper()
	dp := apply.NewFakeDataPlane()
	locs := locator.NewManager()
	bindings := vrfbgp.NewManager()
	core, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(core)
	a := apply.NewApplier(dp, locs, bindings, apply.NewFakeFib(), sourceLocator, 65100, logger)
	rib := &fakeRIB{a: a, routes: map[string]bgp.RouteEvent{}, done: make(chan struct{}, 16)}

	cfg := &config.Config{}
	cfg.BGP.Global.SourceLocator = sourceLocator
	srv := server.NewServer(cfg, nil, nil, nil, locs, bindings, nil, nil, nil, nil, a, nil, nil, nil, rib.evpnReplay, rib.replay, logger)
	srv.Setup()
	ts := httptest.NewServer(srv.Mux())
	t.Cleanup(ts.Close)
	return &vpnLab{
		t:        t,
		dp:       dp,
		rib:      rib,
		bindings: bindings,
		logs:     logs,
		locator:  vinberov1connect.NewLocatorServiceClient(http.DefaultClient, ts.URL),
		vrfBgp:   vinberov1connect.NewVrfBgpServiceClient(http.DefaultClient, ts.URL),
	}
}

func vpnRoute(prefix, rd, rt, sid string) bgp.RouteEvent {
	return bgp.RouteEvent{
		Family: bgp.FamilyVPNv4,
		VPN: &bgp.VPNRoute{
			Family: bgp.FamilyVPNv4, Prefix: prefix, RD: rd,
			SRv6SID: sid, RTs: []string{rt},
		},
	}
}

// The far PE's route: what pe-osaka receives in the cplane-plugin-2site lab.
var (
	importedRoute = vpnRoute("10.1.0.0/24", "65100:100", "65000:200", "fd00:100:0:1::")
	otherRoute    = vpnRoute("10.9.0.0/24", "65100:900", "65000:900", "fd00:100:0:9::")
)

// replayed waits for the replay an RPC requested to finish.
func (l *vpnLab) replayed() {
	l.t.Helper()
	select {
	case <-l.rib.done:
	case <-time.After(5 * time.Second):
		l.t.Fatal("no VPN replay ran")
	}
}

func (l *vpnLab) createLocator(prefix string) {
	l.t.Helper()
	resp, err := l.locator.LocatorCreate(context.Background(), connect.NewRequest(&v1.LocatorCreateRequest{
		Locators: []*v1.Locator{{
			Name: sourceLocator, Prefix: prefix,
			BlockLen: 32, NodeLen: 16, FunctionLen: 16, ArgumentLen: 64,
			Behavior: v1.LocatorBehaviorMode_LOCATOR_BEHAVIOR_MODE_CLASSIC,
		}},
	}))
	if err != nil || len(resp.Msg.GetErrors()) != 0 {
		l.t.Fatalf("LocatorCreate: %v %v", err, resp.Msg.GetErrors())
	}
	l.replayed() // the EVPN replay it requests
}

func (l *vpnLab) deleteLocator() {
	l.t.Helper()
	resp, err := l.locator.LocatorDelete(context.Background(), connect.NewRequest(&v1.LocatorDeleteRequest{
		Names: []string{sourceLocator},
	}))
	if err != nil || len(resp.Msg.GetErrors()) != 0 {
		l.t.Fatalf("LocatorDelete: %v %v", err, resp.Msg.GetErrors())
	}
}

func (l *vpnLab) bind(vrf string, importRTs ...string) {
	l.t.Helper()
	fam := &v1.VrfBgpFamily{}
	for _, rt := range importRTs {
		fam.RouteTargets = append(fam.RouteTargets, &v1.VrfBgpRouteTarget{Rt: rt, Direction: "both"})
	}
	resp, err := l.vrfBgp.VrfBgpBind(context.Background(), connect.NewRequest(&v1.VrfBgpBindRequest{
		Bindings: []*v1.VrfBgpBinding{{
			VrfName: vrf, Rd: "65100:200",
			Families: map[string]*v1.VrfBgpFamily{"vpnv4": fam},
		}},
	}))
	if err != nil || len(resp.Msg.GetErrors()) != 0 {
		l.t.Fatalf("VrfBgpBind: %v %v", err, resp.Msg.GetErrors())
	}
}

func (l *vpnLab) unbind(vrf string) {
	l.t.Helper()
	resp, err := l.vrfBgp.VrfBgpUnbind(context.Background(), connect.NewRequest(&v1.VrfBgpUnbindRequest{
		VrfNames: []string{vrf},
	}))
	if err != nil || len(resp.Msg.GetErrors()) != 0 {
		l.t.Fatalf("VrfBgpUnbind: %v %v", err, resp.Msg.GetErrors())
	}
}

func (l *vpnLab) removeRT(vrf, rt string) {
	l.t.Helper()
	if _, err := l.vrfBgp.RemoveRouteTarget(context.Background(), connect.NewRequest(&v1.RemoveRouteTargetRequest{
		VrfName: vrf, Family: "vpnv4", Rt: rt,
	})); err != nil {
		l.t.Fatalf("RemoveRouteTarget: %v", err)
	}
}

func (l *vpnLab) addRT(vrf, rt string) {
	l.t.Helper()
	if _, err := l.vrfBgp.AddRouteTarget(context.Background(), connect.NewRequest(&v1.AddRouteTargetRequest{
		VrfName: vrf, Family: "vpnv4",
		RouteTarget: &v1.VrfBgpRouteTarget{Rt: rt, Direction: "import"},
	})); err != nil {
		l.t.Fatalf("AddRouteTarget: %v", err)
	}
}

// programmed reports whether prefix is in the data plane, failing the test if
// it is there with an encapsulation source other than wantSrc.
func (l *vpnLab) programmed(prefix string, wantSrc netip.Addr) bool {
	l.t.Helper()
	trigger, ok := l.dp.HeadendV4(prefix)
	if !ok {
		return false
	}
	if got := netip.AddrFrom16(trigger.SrcAddr); got != wantSrc {
		l.t.Errorf("%s trigger source = %s, want %s", prefix, got, wantSrc)
	}
	members := l.dp.EcmpGroup(trigger.GroupId)
	if len(members) == 0 {
		l.t.Errorf("%s trigger points at group %d, which has no members", prefix, trigger.GroupId)
	}
	for _, m := range members {
		if got := netip.AddrFrom16(m.Entry.SrcAddr); got != wantSrc {
			l.t.Errorf("%s member source = %s, want %s", prefix, got, wantSrc)
		}
	}
	return true
}

var loc2Src = netip.MustParseAddr("fd00:200::")

// The route a peer sends before the source locator is registered cannot be
// programmed: every headend entry takes its encapsulation source from that
// locator. The binding here is already in place, so no binding RPC follows to
// replay the loc-rib. Registering the locator has to bring the route in.
// This is the order the cplane-plugin-2site lab hit when the BGP session came
// up before its start script ran `vbctl locator create`.
func TestVPNRouteBeforeSourceLocator(t *testing.T) {
	l := newVPNLab(t)
	l.bind("vrf-cust", "65000:200")
	l.replayed() // nothing in the loc-rib yet

	l.rib.deliver(importedRoute)
	if l.programmed("10.1.0.0/24", loc2Src) {
		t.Fatal("route programmed without a source locator")
	}

	l.createLocator("fd00:200::/48")
	if !l.programmed("10.1.0.0/24", loc2Src) {
		t.Fatal("route never programmed after the source locator was registered")
	}
}

// Every order of {route received, binding created, source locator registered}
// ends with the same data plane: the imported route programmed with the
// locator's source, and a route no VRF imports absent.
func TestVPNReevaluationEveryOrder(t *testing.T) {
	steps := map[string]func(l *vpnLab){
		"route": func(l *vpnLab) {
			l.rib.deliver(importedRoute)
			l.rib.deliver(otherRoute)
		},
		"bind": func(l *vpnLab) {
			l.bind("vrf-cust", "65000:200")
			l.replayed()
		},
		"locator": func(l *vpnLab) {
			l.createLocator("fd00:200::/48")
		},
	}
	orders := [][3]string{
		{"route", "bind", "locator"},
		{"route", "locator", "bind"},
		{"bind", "route", "locator"},
		{"bind", "locator", "route"},
		{"locator", "route", "bind"},
		{"locator", "bind", "route"},
	}
	for _, order := range orders {
		t.Run(fmt.Sprintf("%s-%s-%s", order[0], order[1], order[2]), func(t *testing.T) {
			l := newVPNLab(t)
			for _, step := range order {
				steps[step](l)
			}
			if !l.programmed("10.1.0.0/24", loc2Src) {
				t.Error("imported route is not programmed")
			}
			if l.programmed("10.9.0.0/24", loc2Src) {
				t.Error("route no VRF imports is programmed")
			}
		})
	}
}

// The same holds when an existing binding gains the RT instead of a binding
// being created.
func TestVPNReevaluationRTAdded(t *testing.T) {
	l := newVPNLab(t)
	l.createLocator("fd00:200::/48")
	l.bind("vrf-cust", "65000:100")
	l.replayed()
	l.rib.deliver(importedRoute)
	if l.programmed("10.1.0.0/24", loc2Src) {
		t.Fatal("route programmed before any VRF imports its RT")
	}
	l.addRT("vrf-cust", "65000:200")
	l.replayed()
	if !l.programmed("10.1.0.0/24", loc2Src) {
		t.Fatal("route not programmed after its RT was imported")
	}
}

// Removing an import RT, or deleting the binding that held it, takes out the
// routes no VRF imports any more and leaves the others. Removing the last
// binding of the family restores default-allow, the same result the routes
// get on a node that never had a binding.
func TestVPNReevaluationRetract(t *testing.T) {
	setup := func(t *testing.T) *vpnLab {
		l := newVPNLab(t)
		l.createLocator("fd00:200::/48")
		l.bind("vrf-a", "65000:200")
		l.replayed()
		l.bind("vrf-b", "65000:900")
		l.replayed()
		l.rib.deliver(importedRoute)
		l.rib.deliver(otherRoute)
		if !l.programmed("10.1.0.0/24", loc2Src) || !l.programmed("10.9.0.0/24", loc2Src) {
			t.Fatal("setup: routes not programmed")
		}
		return l
	}

	t.Run("RT removed", func(t *testing.T) {
		l := setup(t)
		l.logs.TakeAll()
		l.removeRT("vrf-b", "65000:900")
		l.replayed()
		if l.programmed("10.9.0.0/24", loc2Src) {
			t.Error("route stayed after its only import RT was removed")
		}
		if !l.programmed("10.1.0.0/24", loc2Src) {
			t.Error("route still imported by vrf-a was removed")
		}
		if n := l.logs.FilterMessageSnippet("default-allow again").Len(); n != 0 {
			t.Errorf("a removal that leaves the family gated warned about default-allow %d times", n)
		}
	})

	t.Run("binding deleted", func(t *testing.T) {
		l := setup(t)
		l.unbind("vrf-b")
		l.replayed()
		if l.programmed("10.9.0.0/24", loc2Src) {
			t.Error("route stayed after the binding importing it was deleted")
		}
		if !l.programmed("10.1.0.0/24", loc2Src) {
			t.Error("route still imported by vrf-a was removed")
		}

		l.logs.TakeAll()
		l.unbind("vrf-a")
		l.replayed()
		if !l.programmed("10.1.0.0/24", loc2Src) || !l.programmed("10.9.0.0/24", loc2Src) {
			t.Error("removing the last binding did not restore default-allow")
		}
		if n := l.logs.FilterMessageSnippet("default-allow again").Len(); n != 1 {
			t.Errorf("default-allow warnings = %d, want 1", n)
		}
	})
}

// A source locator registered again under another prefix rewrites the
// installed routes with the new source.
func TestVPNReevaluationSourceLocatorMoved(t *testing.T) {
	l := newVPNLab(t)
	l.createLocator("fd00:200::/48")
	l.rib.deliver(importedRoute)
	if !l.programmed("10.1.0.0/24", loc2Src) {
		t.Fatal("route not programmed")
	}
	l.deleteLocator()
	l.createLocator("fd00:300::/48")
	if !l.programmed("10.1.0.0/24", netip.MustParseAddr("fd00:300::")) {
		t.Fatal("route gone after the locator moved")
	}
}

// Deleting the source locator leaves installed routes forwarding with the
// source they have and logs one warning. A replay meanwhile neither rewrites
// them nor logs per prefix, a route received meanwhile waits with one
// warning, and registering the locator again under another prefix writes
// them all with the new source.
func TestVPNSourceLocatorDeleted(t *testing.T) {
	l := newVPNLab(t)
	l.createLocator("fd00:200::/48")
	l.bind("vrf-a", "65000:200", "65000:900")
	l.replayed()
	l.rib.deliver(importedRoute)
	if !l.programmed("10.1.0.0/24", loc2Src) {
		t.Fatal("route not programmed")
	}

	l.logs.TakeAll()
	l.deleteLocator()
	l.removeRT("vrf-a", "65000:900") // a replay while the locator is gone
	l.replayed()
	l.rib.deliver(otherRoute) // no VRF imports it now
	l.addRT("vrf-a", "65000:900")
	l.replayed()
	if !l.programmed("10.1.0.0/24", loc2Src) {
		t.Error("deleting the source locator removed an installed route")
	}
	if l.programmed("10.9.0.0/24", loc2Src) {
		t.Error("route programmed without a source locator")
	}
	if errs := l.logs.FilterLevelExact(zapcore.ErrorLevel).All(); len(errs) != 0 {
		t.Errorf("logged %d errors while the source locator was gone: %+v", len(errs), errs)
	}
	warns := l.logs.FilterLevelExact(zapcore.WarnLevel)
	if n := warns.FilterMessageSnippet("source locator deleted").Len(); n != 1 {
		t.Errorf("deletion warnings = %d, want 1", n)
	}
	if n := warns.FilterMessageSnippet("not installed until the source locator").Len(); n != 1 {
		t.Errorf("waiting-prefix warnings = %d, want 1 (for 10.9.0.0/24)", n)
	}

	l.createLocator("fd00:300::/48")
	moved := netip.MustParseAddr("fd00:300::")
	if !l.programmed("10.1.0.0/24", moved) || !l.programmed("10.9.0.0/24", moved) {
		t.Error("routes not written after the source locator was registered again")
	}
}

// An EVPN RT2 received before the source locator cannot be written either.
// Registering the locator replays the EVPN loc-rib, which writes it.
func TestEVPNRouteBeforeSourceLocator(t *testing.T) {
	l := newVPNLab(t)
	if _, err := l.bindings.VRF().SetBridge("evi-100", vrf.Bridge{Name: "br100", BdID: 100, Ifindex: 5}); err != nil {
		t.Fatalf("SetBridge: %v", err)
	}
	if err := l.bindings.Bind(vrfbgp.Binding{VRFName: "evi-100", Families: map[bgp.Family]vrfbgp.FamilyPolicy{
		bgp.FamilyEVPN: {RouteTargets: []vrfbgp.RouteTarget{{RT: "65000:100", Direction: vrfbgp.DirectionImport}}},
	}}); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	l.rib.deliver(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: &bgp.EVPNRoute{
		Type: bgp.EVPNRouteTypeMACIP, RD: "65000:100", RTs: []string{"65000:100"},
		MAC: "aa:bb:cc:00:00:01", SRv6SID: "fd00:100:0:d2::",
	}})
	if l.dp.HasFdb(100, "aa:bb:cc:00:00:01") {
		t.Fatal("RT2 written without a source locator")
	}
	l.createLocator("fd00:200::/48")
	if !l.dp.HasFdb(100, "aa:bb:cc:00:00:01") {
		t.Fatal("RT2 not written after the source locator was registered")
	}
}

// A route write that fails when the source locator is registered is logged,
// the RPC still succeeds, and the replay the registration requests retries
// until the route is written.
func TestVPNSourceLocatorWriteFailureConverges(t *testing.T) {
	l := newVPNLab(t)
	l.rib.deliver(importedRoute)
	// The synchronous pass in the RPC and the first replay attempt fail.
	l.dp.FailEcmpWrites(2)
	l.createLocator("fd00:200::/48")
	if n := l.logs.FilterMessageSnippet("after the source locator was registered failed").Len(); n != 1 {
		t.Errorf("failed write warnings = %d, want 1", n)
	}
	l.replayed() // the retry, after the replayer's backoff
	if !l.programmed("10.1.0.0/24", loc2Src) {
		t.Fatal("route not written after the retry")
	}
}

// An EVPN route is not tracked until it is written, so a write that fails
// during the replay the locator registration requests is seen only by that
// replay. The replay must report it, so the replayer retries.
func TestEVPNSourceLocatorWriteFailureConverges(t *testing.T) {
	l := newVPNLab(t)
	if _, err := l.bindings.VRF().SetBridge("evi-100", vrf.Bridge{Name: "br100", BdID: 100, Ifindex: 5}); err != nil {
		t.Fatalf("SetBridge: %v", err)
	}
	if err := l.bindings.Bind(vrfbgp.Binding{VRFName: "evi-100", Families: map[bgp.Family]vrfbgp.FamilyPolicy{
		bgp.FamilyEVPN: {RouteTargets: []vrfbgp.RouteTarget{{RT: "65000:100", Direction: vrfbgp.DirectionImport}}},
	}}); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	l.rib.deliver(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: &bgp.EVPNRoute{
		Type: bgp.EVPNRouteTypeMACIP, RD: "65000:100", RTs: []string{"65000:100"},
		MAC: "aa:bb:cc:00:00:01", SRv6SID: "fd00:100:0:d2::",
	}})
	// The replay's bd_peer write fails once.
	l.dp.FailBdPeerWrites(1)
	l.createLocator("fd00:200::/48")
	// Without a retry no further replay runs, and this times out.
	l.replayed()
	if !l.dp.HasFdb(100, "aa:bb:cc:00:00:01") {
		t.Fatal("RT2 not written after the retry")
	}
}
