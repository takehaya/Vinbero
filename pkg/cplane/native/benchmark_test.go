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
	benchmarkCompositionUpdates(b, "downlink-gtp4-v4")
}

// BenchmarkCompositionBehaviorUpdates selects an existing controller profile.
// The selected remote endpoint behavior is input data; this benchmark does not
// execute the endpoint's BPF packet processing.
func BenchmarkCompositionBehaviorUpdates(b *testing.B) {
	benchmarkCompositionUpdates(b, os.Getenv("VINBERO_CPLANE_CASE"))
}

func benchmarkCompositionUpdates(b *testing.B, profile string) {
	events, behavior, uplink, prefix := compositionBenchmarkRoutes(b, profile)
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
	defer func() {
		if err := instance.Close(ctx); err != nil {
			b.Errorf("close instance: %v", err)
		}
	}()
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
		attribute := gp.NewPathAttributePrefixSID(gp.NewSRv6ServiceTLV(gp.TLVTypeSRv6L3Service, gp.NewSRv6InformationSubTLV(netip.MustParseAddr(sid), behavior, gp.NewSRv6SIDStructureSubSubTLV(32, 16, 8, 72, 0, 0))))
		raw, err := attribute.Serialize()
		if err != nil {
			b.Fatal(err)
		}
		e.Route.BgpPath.Attributes = [][]byte{raw}
		if uplink {
			// Keep the Direct Segment community needed to join ST2 with DSD.
			e.Route.BgpPath.Attributes = append(e.Route.BgpPath.Attributes, events[1].Route.BgpPath.Attributes[0])
		}
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
	for k, raw := range updates {
		before := ops.commits
		if _, err = instance.HandleEvents(ctx, raw); err != nil {
			b.Fatal(err)
		}
		if ops.commits != before+1 {
			b.Fatal("warmup update did not commit exactly once")
		}
		var output v1.PluginApplyChunk
		if err := proto.Unmarshal(ops.last, &output); err != nil {
			b.Fatal(err)
		}
		verifyCompositionBenchmarkOutput(b, &output, uplink, prefix, k+1)
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
	verifyCompositionBenchmarkOutput(b, &chunk, uplink, prefix, b.N)
	if dir := os.Getenv("VINBERO_CPLANE_TRACE_DIR"); dir != "" && b.N > 1 {
		if err := os.WriteFile(filepath.Join(dir, "final-chunk.bin"), ops.last, 0600); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(startup.Nanoseconds()), "init-ns")
}

func compositionBenchmarkRoutes(t testing.TB, profile string) ([]*v1.PluginEvent, gp.SRBehavior, bool, string) {
	t.Helper()
	events := parityRoutes(t, 256)
	switch profile {
	case "downlink-gtp4-v4":
		return events[:2], gp.ENDM_GTP4E, false, "10.0.0.1/32"
	case "downlink-gtp4-v6":
		rd := gp.NewRouteDistinguisherTwoOctetAS(65000, 7)
		events[0] = parityRoute(t, gp.NewMUPType1SessionTransformedRoute(rd,
			netip.MustParsePrefix("2001:db8:100::1/128"), netip.MustParseAddr("0.0.1.0"),
			9, netip.MustParseAddr("172.16.0.1"), nil))
		events[0].Route.Family = "mup_ipv6"
		return events[:2], gp.ENDM_GTP4E, false, "2001:db8:100::1/128"
	case "uplink-dt4", "uplink-dt6", "uplink-dt46":
		behavior := map[string]gp.SRBehavior{"uplink-dt4": gp.END_DT4, "uplink-dt6": gp.END_DT6, "uplink-dt46": gp.END_DT46}[profile]
		events = events[2:]
		attr := gp.NewPathAttributePrefixSID(gp.NewSRv6ServiceTLV(gp.TLVTypeSRv6L3Service,
			gp.NewSRv6InformationSubTLV(netip.MustParseAddr("fd00:a:0:100::"), behavior,
				gp.NewSRv6SIDStructureSubSubTLV(32, 16, 8, 72, 0, 0))))
		raw, err := attr.Serialize()
		if err != nil {
			t.Fatal(err)
		}
		events[1].Route.BgpPath.Attributes[1] = raw
		return events, behavior, true, ""
	default:
		t.Fatalf("unsupported VINBERO_CPLANE_CASE %q: use downlink-gtp4-v4, downlink-gtp4-v6, uplink-dt4, uplink-dt6 or uplink-dt46", profile)
		return nil, 0, false, ""
	}
}

func verifyCompositionBenchmarkOutput(t testing.TB, chunk *v1.PluginApplyChunk, uplink bool, prefix string, iterations int) {
	t.Helper()
	if chunk.DesiredRevision == 0 {
		t.Fatal("benchmark did not publish a desired revision")
	}
	location := "b"
	if (iterations-1)&1 == 1 {
		location = "a"
	}
	if uplink {
		if len(chunk.ForwardingHeadends) != 0 || len(chunk.MupUplinks) != 1 {
			t.Fatal("benchmark did not build exactly one uplink")
		}
		entry := chunk.MupUplinks[0]
		if entry.Context != "mobile" || entry.Endpoint != "192.0.2.1" || entry.Teid != 256 || entry.TeidBits != 32 || entry.SrcAddr != "fd00:feed::1" || len(entry.Segments) != 1 || entry.Segments[0] != "fd00:"+location+":0:100::" {
			t.Fatal("final timed update did not produce the expected uplink")
		}
		return
	}
	if len(chunk.ForwardingHeadends) != 1 || len(chunk.MupUplinks) != 0 {
		t.Fatal("benchmark did not build exactly one headend")
	}
	entry := chunk.ForwardingHeadends[0].Entry
	if chunk.ForwardingHeadends[0].Context != "mobile" || entry == nil || entry.TriggerPrefix != prefix || entry.SrcAddr != "fd00:feed::1" || entry.Mode != 2 || len(entry.Segments) != 1 || entry.Segments[0] != "fd00:"+location+":0:1ac:1000:124:0:100" {
		t.Fatal("final timed update did not produce the expected forwarding headend")
	}
}
