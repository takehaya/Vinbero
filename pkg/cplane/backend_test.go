package cplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/cplane/native"
	"github.com/takehaya/vinbero/pkg/cplane/wasm"
)

func compositionBackendRegistration(t *testing.T, backend string) Registration {
	t.Helper()
	reg := Registration{Backend: backend}
	if backend == BackendNative {
		reg.NativeID = native.MUPComposition
		reg.NativeVersion = native.ImplementationVersion
	} else {
		var err error
		reg.Module, err = os.ReadFile("../../out/cplane-route-composition.wasm")
		if err != nil {
			t.Skip("make cplane-route-composition")
		}
	}
	return reg
}

func nativeObserverRegistration() Registration {
	policy := compositionPolicy()
	policy.Contexts[0].DelegateMupTypes = nil
	policy.Contexts[0].DelegateEvpn = false
	policy.Contexts[0].BridgeDomain = 0
	return Registration{Name: "native-test", Backend: BackendNative, NativeID: native.MUPCompositionObserver, NativeVersion: native.ImplementationVersion, Input: policy, Config: []byte(`{"context":"mobile","source":"fd00:feed::1","args_offset":7}`)}
}

func TestNativeBackendAdmissionAndPersistence(t *testing.T) {
	ctx := context.Background()
	source := &compositionSource{newFakeSource()}
	f := newServiceFake()
	store := newTestStore(t)
	m, err := NewManager(ManagerConfig{Headend: f, ForwardingMaps: f, Source: source, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	reg := nativeObserverRegistration()
	if err = m.Register(ctx, reg); !errors.Is(err, ErrNativeDisabled) {
		t.Fatalf("disabled: %v", err)
	}
	m.Close(ctx)
	m, err = NewManager(ManagerConfig{Headend: f, ForwardingMaps: f, AllowNative: true, Source: source, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close(ctx)
	for _, change := range []func(*Registration){func(r *Registration) { r.Module = []byte("wasm") }, func(r *Registration) { r.NativeID = "missing" }, func(r *Registration) { r.NativeVersion = "missing" }, func(r *Registration) { r.Backend = "other" }, func(r *Registration) { r.NativeIdentity = "changed" }, func(r *Registration) { r.Backend = BackendWASM }} {
		bad := reg
		change(&bad)
		if err = m.Register(ctx, bad); !errors.Is(err, wasm.ErrAdmission) {
			t.Fatalf("accepted invalid identity: %v", err)
		}
	}
	if err = m.Register(ctx, reg); err != nil {
		t.Fatal(err)
	}
	if !m.WaitIdle(reg.Name, 5*time.Second) {
		t.Fatal("idle")
	}
	st, _ := m.StatsFor(reg.Name)
	if st.Backend != BackendNative || st.NativeIdentity == "" || st.NativeID != reg.NativeID {
		t.Fatalf("stats: %+v", st)
	}
	regs, err := store.List()
	if err != nil || len(regs) != 1 {
		t.Fatalf("stored: %+v %v", regs, err)
	}
	if len(regs[0].Module) != 0 || regs[0].NativeIdentity != st.NativeIdentity {
		t.Fatal("native identity lost")
	}
	entries, err := os.ReadDir(store.Dir())
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".wasm") {
			t.Fatal("native wrote WASM file")
		}
	}
	m.Close(ctx)
	restored, err := NewManager(ManagerConfig{Headend: f, ForwardingMaps: f, AllowNative: true, Source: source, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close(ctx)
	if err = restored.Restore(ctx); err != nil {
		t.Fatal(err)
	}
	if !restored.WaitIdle(reg.Name, 5*time.Second) {
		t.Fatal("restored idle")
	}
	got, ok := restored.StatsFor(reg.Name)
	if !ok || got.NativeIdentity != st.NativeIdentity {
		t.Fatal("native did not restore")
	}
	restored.Close(ctx)
	// A source/dependency mismatch keeps the registration visible, never swaps backend.
	manifest, err := store.readManifest(reg.Name)
	if err != nil {
		t.Fatal(err)
	}
	manifest.NativeIdentity = "old-implementation"
	raw, _ := json.Marshal(manifest)
	if err = os.WriteFile(store.manifestPath(reg.Name), raw, 0600); err != nil {
		t.Fatal(err)
	}
	failed, err := NewManager(ManagerConfig{Headend: f, ForwardingMaps: f, AllowNative: true, Source: source, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	defer failed.Close(ctx)
	if err = failed.Restore(ctx); err != nil {
		t.Fatal(err)
	}
	if len(failed.List()) != 0 || len(failed.Unrestored()) != 1 || !strings.Contains(failed.Unrestored()[0].Reason, "identity changed") {
		t.Fatal("missing identity not retained")
	}
}

func TestNativeFailedReplacementAndRestart(t *testing.T) {
	ctx := context.Background()
	f := newServiceFake()
	src := &compositionSource{newFakeSource()}
	src.rib = mupFixture(t)
	scope, _ := ParseScope(ScopeSpec{HeadendPrefixes: []string{"10.0.0.0/8", "192.0.2.0/24"}})
	m, err := NewManager(ManagerConfig{AllowNative: true, Source: src, Headend: f, ForwardingMaps: f, ResolveMUPInstance: func(string) (uint32, error) { return 7, nil }, ResolveInputTarget: func(bgp.RouteEvent) (string, uint16, bool) { return "", 0, true }})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close(ctx)
	caps, _ := wasm.ParseCapabilities([]string{"headend", "mup"})
	reg := Registration{Name: "composition", Backend: BackendNative, NativeID: native.MUPComposition, NativeVersion: native.ImplementationVersion, Input: compositionPolicy(), Capabilities: caps, Scope: scope, Config: []byte(`{"context":"mobile","source":"fd00:feed::1","args_offset":7,"observe_only":false}`)}
	reg.Input.Contexts[0].DelegateEvpn = false
	reg.Input.Contexts[0].BridgeDomain = 0
	if err = m.Register(ctx, reg); err != nil {
		t.Fatal(err)
	}
	if !m.WaitIdle(reg.Name, 5*time.Second) {
		t.Fatal("idle")
	}
	old := m.plugins[reg.Name]
	before := *f.v4["10.0.0.1/32"]
	bad := reg
	bad.Config = []byte(`{"context":"missing"}`)
	if err = m.Register(ctx, bad); err == nil {
		t.Fatal("invalid replacement accepted")
	}
	if m.plugins[reg.Name] != old || f.v4["10.0.0.1/32"] == nil || *f.v4["10.0.0.1/32"] != before {
		t.Fatal("failed replacement disturbed running state")
	}
	// Simulate the worker observing a closed instance, exercising the shared restart factory.
	if err = old.inst.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if !src.emit(reg.Name, src.rib[0]) {
		t.Fatal("subscription absent")
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if m.WaitIdle(reg.Name, 100*time.Millisecond) {
			st, _ := m.StatsFor(reg.Name)
			if !st.Dead && st.Snapshots >= 2 && st.AppliedRevision == st.DesiredRevision && f.v4["10.0.0.1/32"] != nil {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("native restart did not replay and recover")
}

func TestNativeStoreRejectsMalformedBackendIdentity(t *testing.T) {
	store := newTestStore(t)
	for _, m := range []manifest{
		{Version: nativeManifestVersion, Name: "invalid"},
		{Version: nativeManifestVersion, Name: "invalid", Backend: BackendWASM},
		{Version: nativeManifestVersion, Name: "invalid", Backend: BackendNative},
		{Version: nativeManifestVersion, Name: "invalid", Backend: BackendNative, NativeID: native.MUPComposition, NativeVersion: "1"},
		{Version: contextManifestVersion, Name: "invalid", Backend: BackendNative, NativeID: native.MUPComposition, NativeVersion: "1", NativeIdentity: "digest"},
	} {
		raw, _ := json.Marshal(m)
		if err := os.WriteFile(store.manifestPath("invalid"), raw, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := store.load("invalid"); err == nil {
			t.Fatalf("accepted malformed manifest %+v", m)
		}
		if len(store.Unloadable()) != 1 {
			t.Fatal("malformed manifest disappeared")
		}
	}
}

func TestCompositionBackendReplacement(t *testing.T) {
	ctx := context.Background()
	f := newServiceFake()
	src := &compositionSource{newFakeSource()}
	src.rib = mupFixture(t)
	scope, _ := ParseScope(ScopeSpec{HeadendPrefixes: []string{"10.0.0.0/8", "192.0.2.0/24"}})
	m, err := NewManager(ManagerConfig{AllowNative: true, Source: src, Headend: f, ForwardingMaps: f, ResolveMUPInstance: func(string) (uint32, error) { return 7, nil }, ResolveInputTarget: func(bgp.RouteEvent) (string, uint16, bool) { return "", 0, true }})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close(ctx)
	caps, _ := wasm.ParseCapabilities([]string{"headend", "mup"})
	for _, backend := range []string{BackendNative, BackendWASM, BackendNative} {
		reg := compositionBackendRegistration(t, backend)
		reg.Name = "composition"
		reg.Capabilities = caps
		reg.Scope = scope
		reg.Input = compositionPolicy()
		reg.Input.Contexts[0].DelegateEvpn = false
		reg.Input.Contexts[0].BridgeDomain = 0
		reg.Config = []byte(`{"context":"mobile","source":"fd00:feed::1","args_offset":7,"observe_only":false}`)
		if err = m.Register(ctx, reg); err != nil {
			t.Fatalf("%s: %v", backend, err)
		}
		if !m.WaitIdle(reg.Name, 5*time.Second) {
			t.Fatal("replacement idle")
		}
		st, _ := m.StatsFor(reg.Name)
		if st.Backend != backend || st.OutputFailure != "" || !st.InputReady || st.AppliedRevision != st.DesiredRevision || len(f.uplinks) != 1 || f.v4["10.0.0.1/32"] == nil {
			t.Fatalf("%s replacement lost forwarding: %+v", backend, st)
		}
	}
	if err = m.Unregister(ctx, "composition"); err != nil {
		t.Fatal(err)
	}
	if len(f.v4) != 0 || len(f.uplinks) != 0 {
		t.Fatal("backend replacement leaked owner entries")
	}
}
