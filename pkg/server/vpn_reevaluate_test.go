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

type fakeTracked struct {
	calls int
	err   error
}

func (f *fakeTracked) ReconcileTracked() error { f.calls++; return f.err }

// Registering the BGP source locator writes what the applier tracks within
// the RPC and requests an EVPN replay, which runs the tracked pass again with
// the replayer's retry. Other locators and failed registrations do neither.
// A failed tracked pass is logged and the RPC still succeeds. Deleting the
// locator logs one warning and leaves the installed entries alone.
func TestLocatorService_SourceLocatorHooks(t *testing.T) {
	core, logs := observer.New(zapcore.WarnLevel)
	mgr := locator.NewManager()
	rec := &fakeTracked{}
	var requests [][]bgp.Family
	cfg := &config.Config{}
	cfg.BGP.Global.SourceLocator = "LOC2"
	s := &Server{cfg: cfg, tracked: rec, logger: zap.New(core)}
	add, del := s.sourceLocatorHooks(mgr.Add, mgr.Delete, func(f []bgp.Family) { requests = append(requests, slices.Clone(f)) })
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
		if rec.calls != n || len(requests) != n {
			t.Errorf("%s: tracked passes = %d, replay requests = %v, want %d each", what, rec.calls, requests, n)
		}
		for _, r := range requests {
			if !slices.Equal(r, []bgp.Family{bgp.FamilyEVPN}) {
				t.Errorf("%s: replay request %v, want [evpn]", what, r)
			}
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

	logs.TakeAll()
	rec.err = errors.New("map full")
	create("LOC2", "fd00:300::/48") // fails the test if the RPC reports an error
	want("registered again with a failing write", 2)
	if n := logs.FilterMessageSnippet("retrying").Len(); n != 1 {
		t.Errorf("failed tracked pass logged %d warnings, want 1", n)
	}
	if _, ok := mgr.Get("LOC2"); !ok {
		t.Error("source locator not registered after a failed tracked pass")
	}
}

// Without BGP or a configured source locator the locator calls are passed
// through as they are.
func TestSourceLocatorHooksPassThrough(t *testing.T) {
	boom := errors.New("add")
	add := func(*locator.Locator) error { return boom }
	del := func(string, bool) error { return nil }
	for _, s := range []*Server{
		{cfg: &config.Config{}, tracked: &fakeTracked{}},
		func() *Server {
			cfg := &config.Config{}
			cfg.BGP.Global.SourceLocator = "LOC2"
			return &Server{cfg: cfg}
		}(),
	} {
		gotAdd, gotDel := s.sourceLocatorHooks(add, del, func([]bgp.Family) { t.Error("unexpected replay request") })
		if err := gotAdd(&locator.Locator{Name: "LOC2"}); !errors.Is(err, boom) {
			t.Errorf("add was wrapped: %v", err)
		}
		if gotDel == nil {
			t.Error("del lost")
		}
	}
}
