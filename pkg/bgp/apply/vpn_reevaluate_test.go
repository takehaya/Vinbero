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

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/api/vinbero/v1/vinberov1connect"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bgp/apply"
	"github.com/takehaya/vinbero/pkg/config"
	"github.com/takehaya/vinbero/pkg/locator"
	"github.com/takehaya/vinbero/pkg/server"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

// These tests run the applier behind the daemon's RPC server, with a fake
// loc-rib standing in for GoBGP: the server requests replays, the loc-rib
// re-delivers what it holds, and the assertions read the data plane.

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
	key := ev.VPN.Prefix + "|" + ev.VPN.RD
	if ev.IsWithdraw {
		delete(r.routes, key)
	} else {
		r.routes[key] = ev
	}
	r.a.Apply(ev)
}

// replay is what the daemon hands the server as its VPN replay.
func (r *fakeRIB) replay(families []bgp.Family) error {
	err := r.a.QuietVPNDenials(func() error {
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

type vpnLab struct {
	t       *testing.T
	dp      *apply.FakeDataPlane
	rib     *fakeRIB
	locator vinberov1connect.LocatorServiceClient
	vrfBgp  vinberov1connect.VrfBgpServiceClient
}

func newVPNLab(t *testing.T) *vpnLab {
	t.Helper()
	dp := apply.NewFakeDataPlane()
	locs := locator.NewManager()
	bindings := vrfbgp.NewManager()
	a := apply.NewApplier(dp, locs, bindings, apply.NewFakeFib(), sourceLocator, 65100, zap.NewNop())
	rib := &fakeRIB{a: a, routes: map[string]bgp.RouteEvent{}, done: make(chan struct{}, 16)}

	cfg := &config.Config{}
	cfg.BGP.Global.SourceLocator = sourceLocator
	srv := server.NewServer(cfg, nil, nil, nil, locs, bindings, nil, nil, nil, nil, nil, nil, nil, nil, nil, rib.replay, zap.NewNop())
	srv.Setup()
	ts := httptest.NewServer(srv.Mux())
	t.Cleanup(ts.Close)
	return &vpnLab{
		t:       t,
		dp:      dp,
		rib:     rib,
		locator: vinberov1connect.NewLocatorServiceClient(http.DefaultClient, ts.URL),
		vrfBgp:  vinberov1connect.NewVrfBgpServiceClient(http.DefaultClient, ts.URL),
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
	l.replayed()
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
			l.replayed()
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
	l.replayed()
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
		l.replayed()
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
		l.removeRT("vrf-b", "65000:900")
		l.replayed()
		if l.programmed("10.9.0.0/24", loc2Src) {
			t.Error("route stayed after its only import RT was removed")
		}
		if !l.programmed("10.1.0.0/24", loc2Src) {
			t.Error("route still imported by vrf-a was removed")
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

		l.unbind("vrf-a")
		l.replayed()
		if !l.programmed("10.1.0.0/24", loc2Src) || !l.programmed("10.9.0.0/24", loc2Src) {
			t.Error("removing the last binding did not restore default-allow")
		}
	})
}

// A source locator registered again under another prefix rewrites the
// installed routes with the new source.
func TestVPNReevaluationSourceLocatorMoved(t *testing.T) {
	l := newVPNLab(t)
	l.createLocator("fd00:200::/48")
	l.replayed()
	l.rib.deliver(importedRoute)
	if !l.programmed("10.1.0.0/24", loc2Src) {
		t.Fatal("route not programmed")
	}
	l.deleteLocator()
	l.createLocator("fd00:300::/48")
	l.replayed()
	if !l.programmed("10.1.0.0/24", netip.MustParseAddr("fd00:300::")) {
		t.Fatal("route gone after the locator moved")
	}
}
