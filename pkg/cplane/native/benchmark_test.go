package native

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	gp "github.com/osrg/gobgp/v4/pkg/packet/bgp"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/cplane/wasm"
	"github.com/takehaya/vinbero/sdk/go/cplane"
	"google.golang.org/protobuf/proto"
)

type benchmarkOps struct {
	commits       int
	last, pending []byte
}

func (*benchmarkOps) Log(int32, string)                   {}
func (o *benchmarkOps) ApplyBegin(uint32) (uint64, error) { o.pending = o.pending[:0]; return 1, nil }
func (o *benchmarkOps) ApplyPut(_ uint64, chunk []byte) error {
	o.pending = append(o.pending, chunk...)
	return nil
}
func (o *benchmarkOps) ApplyCommit(uint64) error {
	o.commits++
	o.last = append(o.last[:0], o.pending...)
	return nil
}
func (*benchmarkOps) ApplyAbort(uint64) {}

// BenchmarkCompositionEncodedUpdates changes one ISD SID on every call. It
// includes input/output codecs and the SDK declaration transport to a cheap sink;
// worker queues, PluginOps authorization and real BPF are measured separately.
func BenchmarkCompositionEncodedUpdates(b *testing.B) {
	mode := os.Getenv("VINBERO_CPLANE_BACKEND")
	if mode != "native" && mode != "wasm" {
		b.Fatal("VINBERO_CPLANE_BACKEND must be native or wasm")
	}
	ops := &benchmarkOps{}
	cfg := wasm.Config{Name: "composition-bench", Ops: ops, ConfigBlob: configuration(false), Capabilities: wasm.Capabilities{wasm.CapMUP: {}}}
	if mode == "wasm" {
		if path := os.Getenv("VINBERO_CPLANE_WASM"); path != "" {
			var readErr error
			cfg.Module, readErr = os.ReadFile(path)
			if readErr != nil {
				b.Fatal(readErr)
			}
		} else {
			cfg.Module = parityModule(b, false)
		}
	}
	var instance eventInstance
	ctx := context.Background()
	started := time.Now()
	var err error
	if mode == "native" {
		instance, err = Instantiate(ctx, Config{Config: cfg, Implementation: MUPComposition, Version: ImplementationVersion})
	} else {
		instance, err = wasm.Instantiate(ctx, cfg)
	}
	startup := time.Since(started)
	if err != nil {
		b.Fatal(err)
	}
	defer instance.Close(ctx)
	events := parityRoutes(b, 256)[:2]
	encode := func(e ...*v1.PluginEvent) []byte {
		raw, err := proto.Marshal(&v1.PluginEventBatch{Events: e})
		if err != nil {
			b.Fatal(err)
		}
		return raw
	}
	replay := encode(append([]*v1.PluginEvent{{Kind: v1.PluginEventKind_PLUGIN_EVENT_KIND_START_OF_REPLAY, ReplaySource: cplane.BGPSource}}, append(events, &v1.PluginEvent{Kind: v1.PluginEventKind_PLUGIN_EVENT_KIND_END_OF_REPLAY, ReplaySource: cplane.BGPSource})...)...)
	if _, err = instance.HandleEvents(ctx, replay); err != nil {
		b.Fatal(err)
	}
	var updates [2][]byte
	for k, sid := range []string{"fd00:b:0:100::", "fd00:a:0:100::"} {
		e := proto.Clone(events[1]).(*v1.PluginEvent)
		attribute := gp.NewPathAttributePrefixSID(gp.NewSRv6ServiceTLV(gp.TLVTypeSRv6L3Service, gp.NewSRv6InformationSubTLV(netip.MustParseAddr(sid), gp.ENDM_GTP4E, gp.NewSRv6SIDStructureSubSubTLV(32, 16, 8, 72, 0, 0))))
		raw, err := attribute.Serialize()
		if err != nil {
			b.Fatal(err)
		}
		e.Route.BgpPath.Attributes = [][]byte{raw}
		updates[k] = encode(e)
	}
	inputs := [][]byte{cfg.ConfigBlob, replay, updates[0], updates[1]}
	digest := sha256.New()
	for _, raw := range inputs {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(raw)))
		digest.Write(length[:])
		digest.Write(raw)
	}
	b.Logf("input_sha256=%x", digest.Sum(nil))
	if dir := os.Getenv("VINBERO_CPLANE_TRACE_DIR"); dir != "" && b.N > 1 {
		if err := os.Mkdir(dir, 0700); err != nil {
			b.Fatal(err)
		}
		for k, name := range []string{"config.bin", "replay.bin", "update-0.bin", "update-1.bin"} {
			if err := os.WriteFile(filepath.Join(dir, name), inputs[k], 0600); err != nil {
				b.Fatal(err)
			}
		}
	}
	// Verify real output and eliminate lazy initialization before timing.
	for _, raw := range updates {
		if _, err = instance.HandleEvents(ctx, raw); err != nil {
			b.Fatal(err)
		}
	}
	before := ops.commits
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		status, err := instance.HandleEvents(ctx, updates[i&1])
		if err != nil {
			b.Fatal(err)
		}
		if len(status) != 0 {
			b.Fatalf("unexpected status: %x", status)
		}
	}
	b.StopTimer()
	if ops.commits-before != b.N {
		b.Fatalf("cache-hit/incomplete benchmark: %d commits for %d updates", ops.commits-before, b.N)
	}
	var chunk v1.PluginApplyChunk
	if err := proto.Unmarshal(ops.last, &chunk); err != nil {
		b.Fatal(err)
	}
	if chunk.DesiredRevision == 0 || len(chunk.ForwardingHeadends) != 1 {
		b.Fatal("benchmark did not build exactly one headend")
	}
	expected := "fd00:b:0:1ac:1000:124:0:100"
	if (b.N-1)&1 == 1 {
		expected = "fd00:a:0:1ac:1000:124:0:100"
	}
	entry := chunk.ForwardingHeadends[0].Entry
	if entry == nil || len(entry.Segments) != 1 || entry.Segments[0] != expected {
		b.Fatal("final timed update did not change the forwarding SID")
	}
	if dir := os.Getenv("VINBERO_CPLANE_TRACE_DIR"); dir != "" && b.N > 1 {
		if err := os.WriteFile(filepath.Join(dir, "final-chunk.bin"), ops.last, 0600); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(startup.Nanoseconds()), "init-ns")
}
