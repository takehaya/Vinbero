package guest_test

import (
	"context"
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
	tinygo, err := exec.LookPath("tinygo")
	if err != nil {
		t.Skip("TinyGo is required; the artifact CI job runs this test")
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
	source, err := os.ReadFile("testdata/observer.go")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), source, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	build := exec.CommandContext(ctx, tinygo, "build", "-o", "observer.wasm", "-target=wasm-unknown", "-scheduler=none", "-gc=conservative", "-panic=trap", "-no-debug", ".")
	build.Dir = dir
	build.Env = append(os.Environ(), "GOFLAGS=-buildvcs=false")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	module, err := os.ReadFile(filepath.Join(dir, "observer.wasm"))
	if err != nil {
		t.Fatal(err)
	}
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
