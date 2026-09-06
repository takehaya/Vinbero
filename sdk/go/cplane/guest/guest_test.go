package guest_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/cplane/wasm"
	"google.golang.org/protobuf/proto"
)

type logHost struct {
	wasm.HostOps // Write methods must never be reachable without a capability.
	messages     []string
}

func (h *logHost) Log(_ int32, message string) { h.messages = append(h.messages, message) }

func TestGuestExportsWorkWithoutWriteCapabilities(t *testing.T) {
	for _, tinygo := range []bool{false, true} {
		name := "Go"
		if tinygo {
			name = "TinyGo"
		}
		t.Run(name, func(t *testing.T) {
			testObserver(t, buildGuest(t, "observer.go", tinygo))
		})
	}
}

func buildGuest(t *testing.T, sourceName string, tinygo bool) []byte {
	t.Helper()
	compiler, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	mod := "module observer\n\ngo 1.25.5\n\nrequire github.com/takehaya/vinbero v0.0.0\n\nreplace github.com/takehaya/vinbero => " + strconv.Quote(root) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(mod), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile(filepath.Join("testdata", sourceName))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), source, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	build := exec.CommandContext(ctx, compiler, "build", "-buildmode=c-shared", "-trimpath", "-ldflags=-s -w", "-o", "observer.wasm", ".")
	if tinygo {
		compiler, err = exec.LookPath("tinygo")
		if err != nil {
			t.Skip("optional TinyGo compatibility test requires TinyGo")
		}
		build = exec.CommandContext(ctx, compiler, "build", "-o", "observer.wasm", "-target=wasm-unknown", "-scheduler=none", "-gc=conservative", "-panic=trap", "-no-debug", ".")
	}
	build.Dir = dir
	build.Env = append(os.Environ(), "GOFLAGS=-buildvcs=false")
	if !tinygo {
		build.Env = append(build.Env, "GOOS=wasip1", "GOARCH=wasm")
	}
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	module, err := os.ReadFile(filepath.Join(dir, "observer.wasm"))
	if err != nil {
		t.Fatal(err)
	}
	return module
}

func testObserver(t *testing.T, module []byte) {
	t.Helper()
	host := &logHost{}
	inst, err := wasm.Instantiate(t.Context(), wasm.Config{
		Name: "observer", Module: module, Ops: host, ConfigBlob: []byte("configured"),
		NowMonotonic: func() int64 { return 123 },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inst.Close(context.Background()) })
	batch, err := proto.Marshal(&v1.PluginEventBatch{Events: []*v1.PluginEvent{{
		Kind: v1.PluginEventKind_PLUGIN_EVENT_KIND_ROUTE, Sequence: 7,
		Route: &v1.PluginRoute{Family: "vpnv4", Prefix: "10.0.0.0/24"},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := inst.HandleEvents(t.Context(), batch)
	if err != nil {
		t.Fatal(err)
	}
	var status v1.PluginEventStatus
	if err := proto.Unmarshal(raw, &status); err != nil {
		t.Fatal(err)
	}
	if len(status.Results) != 1 || status.Results[0].Sequence != 7 || status.Results[0].Disposition != v1.PluginEventDisposition_PLUGIN_EVENT_DISPOSITION_QUARANTINE || status.Results[0].Reason != "observation only" {
		t.Fatalf("wrong returned status: %v", &status)
	}
	if len(host.messages) != 2 || host.messages[0] != "configured" || host.messages[1] != "10.0.0.0/24" {
		t.Fatalf("logs: %v", host.messages)
	}
	if err := inst.Tick(t.Context(), 123); err != nil {
		t.Fatal(err)
	}
}

// This guest uses standard library services that require WASI. It also tries
// resource access from inside the sandbox, where host environment and files
// must remain unavailable even though their WASI functions can be imported.
func TestStandardGoRuntime(t *testing.T) {
	t.Setenv("VINBERO_WASI_HOST_ONLY", "must not be inherited")
	module := buildGuest(t, "standard_go.go", false)
	newInstance := func(t *testing.T, config string) (*wasm.Instance, error) {
		t.Helper()
		inst, err := wasm.Instantiate(t.Context(), wasm.Config{
			Name: "go-runtime", Module: module, Ops: &logHost{},
			ConfigBlob: []byte(config), Limits: wasm.Limits{CallTimeout: 200 * time.Millisecond},
		})
		if inst != nil {
			t.Cleanup(func() { _ = inst.Close(context.Background()) })
		}
		return inst, err
	}
	t.Run("services and isolation", func(t *testing.T) {
		inst, err := newInstance(t, "check")
		if err != nil {
			t.Fatal(err)
		}
		batch, err := proto.Marshal(&v1.PluginEventBatch{Events: []*v1.PluginEvent{{Kind: v1.PluginEventKind_PLUGIN_EVENT_KIND_ROUTE}}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := inst.HandleEvents(t.Context(), batch); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("configure sleep respects budget", func(t *testing.T) {
		// Compilation precedes the call budget and is much slower under
		// the race detector. Only guest execution must report a timeout.
		_, err := newInstance(t, "sleep")
		if !errors.Is(err, wasm.ErrCallTimeout) {
			t.Fatalf("want timeout, got %v", err)
		}
	})
	t.Run("tick sleep respects budget", func(t *testing.T) {
		inst, err := newInstance(t, "")
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		err = inst.Tick(t.Context(), 0)
		if !errors.Is(err, wasm.ErrCallTimeout) {
			t.Fatalf("want timeout, got %v", err)
		}
		if time.Since(start) > 5*time.Second {
			t.Fatal("WASI sleep outlived the call budget")
		}
	})
	t.Run("tick sleep respects caller cancellation", func(t *testing.T) {
		inst, err := newInstance(t, "")
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		timer := time.AfterFunc(20*time.Millisecond, cancel)
		defer timer.Stop()
		err = inst.Tick(ctx, 0)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("want cancellation, got %v", err)
		}
	})
}
