package cplane

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/cplane/native"
	"github.com/takehaya/vinbero/pkg/cplane/wasm"
)

func TestRegistrationCacheConfigChangesCreateFreshInstances(t *testing.T) {
	ctx := context.Background()
	m, _ := newTestManager(t, newFakeSource(), newFakeClaims())
	reg := Registration{Name: "cache-config", Module: fixtureModule(t, "echo"), Config: []byte("first")}
	if err := m.Register(ctx, reg); err != nil {
		t.Fatal(err)
	}
	waitDelivered(t, m, reg.Name)
	old := m.plugins[reg.Name]
	reg.Config = []byte("different configuration")
	if err := m.Register(ctx, reg); err != nil {
		t.Fatal(err)
	}
	waitDelivered(t, m, reg.Name)
	next := m.plugins[reg.Name]
	if next.compilationCache != old.compilationCache || next.cacheLease == old.cacheLease || next.inst == old.inst || next.ops == old.ops {
		t.Fatal("compatible replacement must share only compiled code")
	}
	reg.Config[0] = '!'
	if string(old.config) != "first" || string(next.config) != "different configuration" {
		t.Fatal("configuration state escaped its generation")
	}
	if err := old.inst.Tick(ctx, 1); err == nil {
		t.Fatal("old guest is still running")
	}
	if err := next.inst.Tick(ctx, 2); err != nil {
		t.Fatalf("old runtime close invalidated the new guest: %v", err)
	}
}

func TestRegistrationCacheDoesNotKeepIncompatibleHistory(t *testing.T) {
	otherModule := fixtureModule(t, "clock")
	for _, tc := range []struct {
		name   string
		change func(*Registration)
	}{
		{"module", func(r *Registration) { r.Module = bytes.Clone(otherModule) }},
		{"capabilities", func(r *Registration) { r.Capabilities = nil }},
		{"scope", func(r *Registration) { r.Scope.HeadendPrefixes = []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")} }},
		{"limits", func(r *Registration) { r.Limits.MaxBufferBytes = 1 << 20 }},
		{"input", func(r *Registration) { r.Input = &v1.CplaneInputPolicy{Version: 1} }},
		{"families", func(r *Registration) { r.Families = []bgp.Family{bgp.FamilyVPNv6} }},
		{"behaviors", func(r *Registration) { r.Behaviors = []uint16{0xFE01} }},
		{"native", func(r *Registration) { r.Backend, r.NativeID, r.Module = BackendNative, native.BGPObserver, nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			m, _ := newTestManager(t, newFakeSource(), newFakeClaims())
			m.allowNative = true
			reg := Registration{Name: "cache-boundary", Module: fixtureModule(t, "echo"),
				Capabilities: wasm.Capabilities{wasm.CapHeadend: {}}, Scope: testScope(), Families: []bgp.Family{bgp.FamilyVPNv4}}
			if err := m.Register(ctx, reg); err != nil {
				t.Fatal(err)
			}
			waitDelivered(t, m, reg.Name)
			old := m.plugins[reg.Name]
			observed := &observedCacheClose{CompilationCache: old.compilationCache}
			old.cacheLease.owner.cache = observed
			tc.change(&reg)
			err := m.Register(ctx, reg)
			if tc.name == "input" {
				if err == nil || m.plugins[reg.Name] != old || observed.calls.Load() != 0 {
					t.Fatal("cache reuse bypassed immutable input policy")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			waitDelivered(t, m, reg.Name)
			if m.plugins[reg.Name].compilationCache == old.compilationCache || observed.calls.Load() != 1 || old.cacheLease.retain() != nil {
				t.Fatal("incompatible replacement retained compiled history")
			}
		})
	}
}

func TestRegistrationCacheIsScopedToRegistrationName(t *testing.T) {
	ctx := context.Background()
	m, _ := newTestManager(t, newFakeSource(), newFakeClaims())
	reg := Registration{Name: "cache-one", Module: fixtureModule(t, "echo")}
	if err := m.Register(ctx, reg); err != nil {
		t.Fatal(err)
	}
	reg.Name = "cache-two"
	if err := m.Register(ctx, reg); err != nil {
		t.Fatal(err)
	}
	if m.plugins["cache-one"].compilationCache == m.plugins["cache-two"].compilationCache {
		t.Fatal("different registrations shared a cache")
	}
}

func TestRegistrationCacheOwnsAuthorityAndMatchesDefaultLimits(t *testing.T) {
	ctx := context.Background()
	m, _ := newTestManager(t, newFakeSource(), newFakeClaims())
	reg := Registration{Name: "cache-owned", Module: fixtureModule(t, "echo"), Capabilities: wasm.Capabilities{wasm.CapHeadend: {}},
		Scope: testScope(), Families: []bgp.Family{bgp.FamilyVPNv4}, Behaviors: []uint16{0xFE01}}
	if err := m.Register(ctx, reg); err != nil {
		t.Fatal(err)
	}
	waitDelivered(t, m, reg.Name)
	old := m.plugins[reg.Name]
	delete(reg.Capabilities, wasm.CapHeadend)
	reg.Scope.Locators[0], reg.Scope.VRFs[0] = "changed", "changed"
	reg.Scope.HeadendPrefixes[0] = netip.MustParsePrefix("192.0.2.0/24")
	reg.Scope.HeadendV4Slots[0], reg.Scope.HeadendV6Slots[0], reg.Scope.EndpointSlots[0] = 100, 101, 102
	reg.Families[0], reg.Behaviors[0] = bgp.FamilyVPNv6, 0xFE02
	if !reflect.DeepEqual(old.reg.Scope, testScope()) || !old.reg.Capabilities.Has(wasm.CapHeadend) ||
		old.reg.Families[0] != bgp.FamilyVPNv4 || old.reg.Behaviors[0] != 0xFE01 {
		t.Fatal("caller mutated the running registration's authority")
	}
	reg = old.reg
	reg.Limits = wasm.DefaultLimits()
	if err := m.Register(ctx, reg); err != nil {
		t.Fatal(err)
	}
	waitDelivered(t, m, reg.Name)
	if m.plugins[reg.Name].compilationCache != old.compilationCache {
		t.Fatal("explicit defaults missed the compatible cache")
	}
}

func TestRegistrationCacheCandidateFailuresKeepOldGeneration(t *testing.T) {
	for _, kind := range []string{"configure", "subscribe"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			src := newFakeSource()
			var source EventSource = src
			if kind == "configure" {
				source = nil // A tiny buffer deliberately excludes replay batches.
			}
			m, err := NewManager(ManagerConfig{Headend: newFakeHeadendOps(), Source: source})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { m.Close(ctx) })
			reg := Registration{Name: "cache-failure", Module: fixtureModule(t, "echo"), Config: []byte("ok")}
			if kind == "configure" {
				reg.Limits.MaxBufferBytes = 16
			}
			if err := m.Register(ctx, reg); err != nil {
				t.Fatal(err)
			}
			if !m.WaitIdle(reg.Name, 5*time.Second) {
				t.Fatal("initial registration not idle")
			}
			old := m.plugins[reg.Name]
			observed := &observedCacheClose{CompilationCache: old.compilationCache}
			old.cacheLease.owner.cache = observed
			if kind == "configure" {
				reg.Config = bytes.Repeat([]byte("x"), 32)
			} else {
				src.regErr = errors.New("injected subscription failure")
			}
			if err := m.Register(ctx, reg); err == nil {
				t.Fatal("accepted failing candidate")
			}
			old.cacheLease.owner.mu.Lock()
			refs := old.cacheLease.owner.refs
			old.cacheLease.owner.mu.Unlock()
			if m.plugins[reg.Name] != old || refs != 1 || observed.calls.Load() != 0 {
				t.Fatal("failed candidate leaked a lease or closed the old cache")
			}
			if err := old.inst.Tick(ctx, 1); err != nil {
				t.Fatalf("failed candidate invalidated the old runtime: %v", err)
			}
		})
	}
}
