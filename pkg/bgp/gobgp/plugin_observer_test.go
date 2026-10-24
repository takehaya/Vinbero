package gobgp

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/cplane"
	"github.com/takehaya/vinbero/pkg/cplane/wasm"
)

type bgpObserverHost struct {
	wasm.HostOps // No write capability is granted; write methods must be unreachable.
	logs         []string
}

func (h *bgpObserverHost) Log(_ int32, msg string) { h.logs = append(h.logs, msg) }

func TestGoBGPObserverWASM(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	moduleFile := filepath.Join(t.TempDir(), "observer.wasm")
	build := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-buildmode=c-shared", "-trimpath", "-buildvcs=false", "-ldflags=-s -w", "-o", moduleFile, ".")
	build.Dir = "../../../sdk/examples/cplane-bgp-observer"
	build.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm")
	if data, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build observer: %v\n%s", err, data)
	}
	module, err := os.ReadFile(moduleFile)
	if err != nil {
		t.Fatal(err)
	}
	host := &bgpObserverHost{}
	inst, err := wasm.Instantiate(t.Context(), wasm.Config{Name: "bgp-observer", Module: module, Ops: host})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inst.Close(context.Background()) })
	for name, p := range pluginBGPFixtures(t) {
		t.Run(name, func(t *testing.T) {
			for _, withdraw := range []bool{false, true} {
				p.Withdrawal = withdraw
				ev, _ := pathToRouteEvent(p)
				before := len(host.logs)
				batch, err := proto.Marshal(&v1.PluginEventBatch{Events: []*v1.PluginEvent{{Kind: v1.PluginEventKind_PLUGIN_EVENT_KIND_ROUTE, Sequence: 1, Route: cplane.EncodeRouteEvent(ev)}}})
				if err != nil {
					t.Fatal(err)
				}
				raw, err := inst.HandleEvents(t.Context(), batch)
				if err != nil {
					t.Fatal(err)
				}
				var status v1.PluginEventStatus
				if err := proto.Unmarshal(raw, &status); err != nil || len(status.Results) != 0 {
					t.Fatalf("observer rejected route: %v, %v", &status, err)
				}
				wantAttrs := len(p.Attrs)
				if withdraw {
					wantAttrs = 0
				}
				wantLog := fmt.Sprintf("BGP family=%d/%d peer=%s path_id=17 withdraw=%t nlri=%s attributes=%d",
					p.Family.Afi(), p.Family.Safi(), p.PeerAddress, withdraw, p.Nlri.String(), wantAttrs)
				if len(host.logs) != before+1 || host.logs[before] != wantLog {
					t.Fatalf("observer log = %v, want %q", host.logs[before:], wantLog)
				}
			}
		})
	}
	if len(inst.Capabilities()) != 0 {
		t.Fatal("observer unexpectedly granted writes")
	}
}
