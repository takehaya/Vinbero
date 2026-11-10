package server

import (
	"context"
	"errors"
	"slices"
	"testing"

	"connectrpc.com/connect"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/config"
	"github.com/takehaya/vinbero/pkg/locator"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

// The hook requests a replay of the L3VPN families an import filter change
// touched, and warns when a family went back to default-allow.
func TestVPNImportFilterHook(t *testing.T) {
	core, logs := observer.New(zapcore.WarnLevel)
	var got [][]bgp.Family
	hook := vpnImportFilterHook(func(f []bgp.Family) { got = append(got, slices.Clone(f)) }, zap.New(core))

	hook([]vrfbgp.ImportFilterChange{
		{Family: bgp.FamilyEVPN, Before: "import:65000:1", After: "import:"},
		{Family: bgp.FamilyVPNv6, Before: vrfbgp.ImportFilterDefaultAllow, After: "import:65000:1"},
	})
	hook([]vrfbgp.ImportFilterChange{{Family: bgp.FamilyEVPN, Before: "import:", After: vrfbgp.ImportFilterDefaultAllow}})
	if want := [][]bgp.Family{{bgp.FamilyVPNv6}}; !slices.EqualFunc(got, want, slices.Equal[[]bgp.Family]) {
		t.Errorf("requests = %v, want %v", got, want)
	}
	if n := logs.Len(); n != 0 {
		t.Errorf("logged %d warnings for changes that do not restore VPN default-allow", n)
	}

	hook([]vrfbgp.ImportFilterChange{{Family: bgp.FamilyVPNv4, Before: "import:65000:1", After: vrfbgp.ImportFilterDefaultAllow}})
	warns := logs.All()
	if len(warns) != 1 || warns[0].ContextMap()["family"] != string(bgp.FamilyVPNv4) {
		t.Errorf("warnings = %+v, want one for vpnv4", warns)
	}
}

type fakeSourceReconciler struct{ calls int }

func (f *fakeSourceReconciler) ReconcileSourceLocator() { f.calls++ }

// Registering the BGP source locator rewrites what the applier tracks and
// replays the EVPN loc-rib, synchronously in the RPC. Other locators and
// failed registrations do neither. Deleting it logs one warning and leaves the
// installed entries alone.
func TestLocatorService_SourceLocatorHooks(t *testing.T) {
	core, logs := observer.New(zapcore.WarnLevel)
	mgr := locator.NewManager()
	rec := &fakeSourceReconciler{}
	evpnReplays := 0
	cfg := &config.Config{}
	cfg.BGP.Global.SourceLocator = "LOC2"
	s := &Server{cfg: cfg, srcLocator: rec, evpnReplay: func() { evpnReplays++ }, logger: zap.New(core)}
	add, del := s.sourceLocatorHooks(mgr.Add, mgr.Delete)
	srv := NewLocatorServer(mgr, add, del)

	create := func(name, prefix string) {
		t.Helper()
		if _, err := srv.LocatorCreate(context.Background(), connect.NewRequest(&v1.LocatorCreateRequest{
			Locators: []*v1.Locator{{
				Name: name, Prefix: prefix,
				BlockLen: 32, NodeLen: 16, FunctionLen: 16, ArgumentLen: 64,
				Behavior: v1.LocatorBehaviorMode_LOCATOR_BEHAVIOR_MODE_CLASSIC,
			}},
		})); err != nil {
			t.Fatalf("LocatorCreate: %v", err)
		}
	}
	remove := func(name string) {
		t.Helper()
		if _, err := srv.LocatorDelete(context.Background(), connect.NewRequest(&v1.LocatorDeleteRequest{Names: []string{name}})); err != nil {
			t.Fatalf("LocatorDelete: %v", err)
		}
	}
	want := func(what string, n int) {
		t.Helper()
		if rec.calls != n || evpnReplays != n {
			t.Errorf("%s: reconciles = %d, EVPN replays = %d, want %d each", what, rec.calls, evpnReplays, n)
		}
	}

	create("LOC1", "fd00:100::/48")
	want("another locator", 0)
	create("LOC2", "fd00:100::/48") // prefix taken: the add fails
	want("failed registration", 0)
	create("LOC2", "fd00:200::/48")
	want("source locator", 1)
	if _, ok := mgr.Get("LOC2"); !ok {
		t.Fatal("source locator was not registered")
	}

	remove("LOC1")
	if logs.Len() != 0 {
		t.Errorf("deleting another locator warned: %+v", logs.All())
	}
	remove("LOC2")
	if logs.Len() != 1 {
		t.Errorf("deleting the source locator logged %d warnings, want 1", logs.Len())
	}
	want("delete", 1)
	create("LOC2", "fd00:300::/48")
	want("registered again", 2)
}

// Without BGP or a configured source locator the locator calls are passed
// through as they are.
func TestSourceLocatorHooksPassThrough(t *testing.T) {
	boom := errors.New("add")
	add := func(*locator.Locator) error { return boom }
	del := func(string, bool) error { return nil }
	for _, s := range []*Server{
		{cfg: &config.Config{}, srcLocator: &fakeSourceReconciler{}},
		func() *Server {
			cfg := &config.Config{}
			cfg.BGP.Global.SourceLocator = "LOC2"
			return &Server{cfg: cfg}
		}(),
	} {
		gotAdd, gotDel := s.sourceLocatorHooks(add, del)
		if err := gotAdd(&locator.Locator{Name: "LOC2"}); !errors.Is(err, boom) {
			t.Errorf("add was wrapped: %v", err)
		}
		if gotDel == nil {
			t.Error("del lost")
		}
	}
}
