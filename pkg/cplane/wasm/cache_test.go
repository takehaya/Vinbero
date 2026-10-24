package wasm

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/tetratelabs/wazero"
)

func TestBorrowedCompilationCacheKeepsInstancesIndependent(t *testing.T) {
	ctx := context.Background()
	cache := wazero.NewCompilationCache()
	// Registered first so all instance cleanups run before the cache closes.
	t.Cleanup(func() { _ = cache.Close(ctx) })
	first := mustInstantiate(t, "echo", Config{CompilationCache: cache, ConfigBlob: []byte("first"), NowMonotonic: func() int64 { return 111 }})
	second := mustInstantiate(t, "echo", Config{CompilationCache: cache, ConfigBlob: []byte("second config"), NowMonotonic: func() int64 { return 222 }})
	if !first.mod.Memory().Write(128, []byte{9}) {
		t.Fatal("write first memory")
	}
	value, ok := second.mod.Memory().ReadByte(128)
	if !ok || value != 0 {
		t.Fatal("cached code shared linear memory")
	}
	for _, tc := range []struct {
		inst             *Instance
		configLen, clock uint64
	}{{first, 5, 111}, {second, 13, 222}} {
		for name, want := range map[string]uint64{"config_len": tc.configLen, "read_clock": tc.clock} {
			got, err := tc.inst.mod.ExportedFunction(name).Call(ctx)
			if err != nil || len(got) != 1 || got[0] != want {
				t.Fatalf("%s = %v, %v; want %d", name, got, err, want)
			}
		}
	}
	if err := first.Close(ctx); err != nil {
		t.Fatal(err)
	}
	// Closing one runtime does not close its borrowed cache or another runtime.
	for _, inst := range []*Instance{second, mustInstantiate(t, "echo", Config{CompilationCache: cache})} {
		input := []byte("still independent")
		got, err := inst.HandleEvents(ctx, input)
		if err != nil || !bytes.Equal(got, input) {
			t.Fatalf("instance after close: %q %v", got, err)
		}
	}
}

func TestCompilationCacheStillAdmitsAndConfiguresEachInstance(t *testing.T) {
	ctx := context.Background()
	cache := wazero.NewCompilationCache()
	t.Cleanup(func() { _ = cache.Close(ctx) })
	first := mustInstantiate(t, "apply", Config{CompilationCache: cache, Capabilities: mustCaps(t, "headend")})
	for name, cfg := range map[string]Config{
		"ungranted":         {CompilationCache: cache, Capabilities: mustCaps(t)},
		"configure missing": {CompilationCache: cache, Capabilities: mustCaps(t, "headend"), ConfigBlob: []byte("not supported")},
	} {
		t.Run(name, func(t *testing.T) {
			inst, err := instantiate(t, "apply", cfg)
			if inst != nil {
				_ = inst.Close(ctx)
			}
			if !errors.Is(err, ErrAdmission) {
				t.Fatalf("cached module bypassed fresh admission/configure: %v", err)
			}
		})
	}
	if _, err := first.HandleEvents(ctx, []byte("still admitted")); err != nil {
		t.Fatalf("failed construction closed another runtime's cache: %v", err)
	}
	last := mustInstantiate(t, "apply", Config{CompilationCache: cache, Capabilities: mustCaps(t, "headend")})
	if _, err := last.HandleEvents(ctx, []byte("new host bindings")); err != nil {
		t.Fatal(err)
	}
}
