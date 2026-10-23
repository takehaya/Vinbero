package cplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/takehaya/vinbero/pkg/config"
	"github.com/takehaya/vinbero/pkg/cplane/native"
	"github.com/takehaya/vinbero/pkg/cplane/wasm"
)

func TestDefaultNativeRegistrationAndRestore(t *testing.T) {
	ctx := context.Background()
	cfg, err := config.Load("")
	if err != nil {
		t.Fatal(err)
	}
	store := newTestStore(t)
	newManager := func() *Manager {
		m, err := NewManager(ManagerConfig{AllowNative: cfg.Setting.CplanePlugins.NativeEnabled, Headend: newFakeHeadendOps(), Store: store})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { m.Close(ctx) })
		return m
	}
	m := newManager()
	for _, reg := range []Registration{
		{Name: native.BGPObserver},
		{Name: "another-observer", NativeID: native.BGPObserver},
	} {
		if err := m.Register(ctx, reg); err != nil {
			t.Fatal(err)
		}
	}
	regs, err := store.List()
	if err != nil || len(regs) != 2 {
		t.Fatalf("stored registrations: %+v, %v", regs, err)
	}
	for _, reg := range regs {
		d, _ := native.Lookup(native.BGPObserver)
		if reg.Backend != BackendNative || reg.NativeID != d.ID || reg.NativeVersion != d.Version || reg.NativeIdentity != d.Identity || len(reg.Module) != 0 {
			t.Fatalf("defaults were not pinned: %+v", reg)
		}
	}
	m.Close(ctx)
	restored := newManager()
	if err := restored.Restore(ctx); err != nil {
		t.Fatal(err)
	}
	for _, reg := range regs {
		st, ok := restored.StatsFor(reg.Name)
		if !ok || st.Backend != BackendNative || st.NativeID != reg.NativeID || st.NativeVersion != reg.NativeVersion || st.NativeIdentity != reg.NativeIdentity {
			t.Fatalf("restored backend changed: %+v", st)
		}
	}
}

func TestDefaultBackendAdmission(t *testing.T) {
	for _, tc := range []struct {
		name    string
		reg     Registration
		allowed bool
		wantErr error
		backend string
	}{
		{name: "native by name", reg: Registration{Name: native.BGPObserver}, allowed: true, backend: BackendNative},
		{name: "legacy module", reg: Registration{Name: native.BGPObserver, Module: []byte("invalid WASM")}, backend: BackendWASM},
		{name: "native disabled", reg: Registration{Name: native.BGPObserver}, wantErr: ErrNativeDisabled},
		{name: "unknown name", reg: Registration{Name: "unknown"}, allowed: true, wantErr: wasm.ErrAdmission},
		{name: "unknown version", reg: Registration{Name: native.BGPObserver, NativeVersion: "unknown"}, allowed: true, wantErr: wasm.ErrAdmission},
		{name: "mixed native module", reg: Registration{Name: native.BGPObserver, Backend: BackendNative, Module: []byte("module")}, allowed: true, wantErr: wasm.ErrAdmission},
		{name: "WASM with ID", reg: Registration{Backend: BackendWASM, NativeID: native.BGPObserver}, allowed: true, wantErr: wasm.ErrAdmission},
		{name: "WASM with version", reg: Registration{Backend: BackendWASM, NativeVersion: "1"}, allowed: true, wantErr: wasm.ErrAdmission},
		{name: "WASM with identity", reg: Registration{Backend: BackendWASM, NativeIdentity: "identity"}, allowed: true, wantErr: wasm.ErrAdmission},
		{name: "legacy module with ID", reg: Registration{Module: []byte("module"), NativeID: native.BGPObserver}, allowed: true, wantErr: wasm.ErrAdmission},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &Manager{allowNative: tc.allowed}
			err := m.validateBackend(&tc.reg)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("got %v, want %v", err, tc.wantErr)
				}
			} else if err != nil || tc.reg.Backend != tc.backend {
				t.Fatalf("backend=%q err=%v", tc.reg.Backend, err)
			}
		})
	}
}

func TestInvalidWASMNeverFallsBackToDefaultNative(t *testing.T) {
	for _, reg := range []Registration{
		{Name: native.BGPObserver, Backend: BackendWASM},
		{Name: native.BGPObserver, Module: []byte("invalid WASM")},
	} {
		m, err := NewManager(ManagerConfig{AllowNative: true, Headend: newFakeHeadendOps()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { m.Close(context.Background()) })
		if err := m.Register(context.Background(), reg); !errors.Is(err, wasm.ErrAdmission) || len(m.List()) != 0 {
			t.Fatalf("invalid WASM became native: error=%v running=%v", err, m.List())
		}
	}
}

func TestLegacyWASMRestoreKeepsBackend(t *testing.T) {
	for _, version := range []int{storeManifestVersion, contextManifestVersion} {
		for _, tc := range []struct {
			module      string
			allowNative bool
		}{{"valid", true}, {"empty", true}, {"corrupt", true}, {"missing", true}, {"valid", false}} {
			t.Run(fmt.Sprintf("v%d/%s/native=%t", version, tc.module, tc.allowNative), func(t *testing.T) {
				module := tc.module
				store := newTestStore(t)
				reg := Registration{Name: native.BGPObserver, Module: declareModule(t), Capabilities: testCaps(), Scope: testScope()}
				if module == "empty" {
					reg.Module = nil
				} else if module == "corrupt" {
					reg.Module = []byte("invalid WASM")
				}
				if err := store.Save(reg); err != nil {
					t.Fatal(err)
				}
				manifest, err := store.readManifest(reg.Name)
				if err != nil {
					t.Fatal(err)
				}
				manifest.Version, manifest.Backend = version, ""
				body, err := json.Marshal(manifest)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(store.manifestPath(reg.Name), body, 0600); err != nil {
					t.Fatal(err)
				}
				if module == "missing" {
					path, err := store.modulePathFor(reg.Name, manifest)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
				}
				m, err := NewManager(ManagerConfig{AllowNative: tc.allowNative, Headend: newFakeHeadendOps(), Store: store})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { m.Close(context.Background()) })
				err = m.Restore(context.Background())
				if module == "missing" {
					if !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("missing module error = %v", err)
					}
				} else if err != nil {
					t.Fatal(err)
				}
				st, running := m.StatsFor(reg.Name)
				if module == "valid" {
					if !running || st.Backend != BackendWASM || st.NativeID != "" {
						t.Fatalf("legacy WASM changed backend: %+v", st)
					}
				} else if running || len(m.Unrestored()) != 1 {
					t.Fatalf("broken legacy WASM became native: running=%v unrestored=%v", running, m.Unrestored())
				}
			})
		}
	}
}
