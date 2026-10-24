package cplane

import (
	"context"
	"os"
	"testing"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/cplane/native"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestBGPObserverBackendReplay(t *testing.T) {
	for _, backend := range []string{BackendNative, BackendWASM} {
		t.Run(backend, func(t *testing.T) {
			src, maps := newFakeSource(), newFakeHeadendOps()
			src.rib = mupFixture(t)[:1]
			core, logs := observer.New(zapcore.InfoLevel)
			m, err := NewManager(ManagerConfig{AllowNative: true, Source: src, Headend: maps, Logger: zap.New(core)})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { m.Close(context.Background()) })
			reg := Registration{Name: "observer", Backend: backend, Families: []bgp.Family{bgp.FamilyMUPIPv4}, Config: []byte{0xff}}
			if backend == BackendNative {
				reg.NativeID, reg.NativeVersion = native.BGPObserver, native.ImplementationVersion
			} else {
				reg.Module, err = os.ReadFile("../../out/cplane-bgp-observer.wasm")
				if err != nil {
					if os.Getenv("VINBERO_CPLANE_PARITY") == "1" {
						t.Fatal(err)
					}
					t.Skip("make cplane-bgp-observer")
				}
			}
			if err := m.Register(context.Background(), reg); err != nil {
				t.Fatal(err)
			}
			waitDelivered(t, m, reg.Name)
			if logs.FilterMessageSnippet("BGP family=").Len() != 1 || maps.countV4() != 0 {
				t.Fatal("read-only observer failed to decode its replay or changed forwarding maps")
			}
			st, ok := m.StatsFor(reg.Name)
			if !ok || len(st.Capabilities) != 0 || st.OutputFailure != "" {
				t.Fatalf("observer needed write grants or failed output: %+v", st)
			}
		})
	}
}
