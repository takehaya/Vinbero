package native

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	gp "github.com/osrg/gobgp/v4/pkg/packet/bgp"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/cplane/wasm"
	"github.com/takehaya/vinbero/sdk/go/cplane"
	"github.com/takehaya/vinbero/sdk/go/cplane/mupcontroller"
	"google.golang.org/protobuf/proto"
)

type scaleFixture struct {
	sessions, batch int
	change          string
	replay          []byte
	updates         [2][]byte
	typedReplay     []cplane.Event
	typed           [2][]cplane.Event
}

func scalePrefix(i int) string { return fmt.Sprintf("10.64.%d.%d/32", i/256, i%256) }
func scaleEvents(t testing.TB, events ...*v1.PluginEvent) []byte {
	t.Helper()
	raw, err := proto.Marshal(&v1.PluginEventBatch{Events: events})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func newScaleFixture(t testing.TB, n, batch int, change string) scaleFixture {
	t.Helper()
	if n < 1 || n > 1024 || batch < 1 || batch > n || (change != "st1" && change != "isd") || (change == "isd" && batch != 1) {
		t.Fatal("invalid scale fixture")
	}
	f := scaleFixture{sessions: n, batch: batch, change: change}
	rd := gp.NewRouteDistinguisherTwoOctetAS(65000, 7)
	session := func(i int, teid uint32) *v1.PluginEvent {
		var bytes [4]byte
		binary.BigEndian.PutUint32(bytes[:], teid)
		e := parityRoute(t, gp.NewMUPType1SessionTransformedRoute(rd, netip.MustParsePrefix(scalePrefix(i)), netip.AddrFrom4(bytes), 9, netip.MustParseAddr("172.16.0.1"), nil))
		// A TEID change replaces the same session rather than growing the View.
		e.Route.BgpPath.RouteKey = []byte(scalePrefix(i))
		return e
	}
	sessions := make([]*v1.PluginEvent, n)
	for i := range sessions {
		sessions[i] = session(i, 256)
	}
	discovery := func(location string) *v1.PluginEvent {
		attribute := gp.NewPathAttributePrefixSID(gp.NewSRv6ServiceTLV(gp.TLVTypeSRv6L3Service, gp.NewSRv6InformationSubTLV(netip.MustParseAddr("fd00:"+location+":0:100::"), gp.ENDM_GTP4E, gp.NewSRv6SIDStructureSubSubTLV(32, 16, 8, 72, 0, 0))))
		return parityRoute(t, gp.NewMUPInterworkSegmentDiscoveryRoute(rd, netip.MustParsePrefix("172.16.0.0/24")), attribute)
	}
	events := []*v1.PluginEvent{{Kind: v1.PluginEventKind_PLUGIN_EVENT_KIND_START_OF_REPLAY, ReplaySource: cplane.BGPSource}}
	events = append(events, sessions...)
	events = append(events, discovery("a"), &v1.PluginEvent{Kind: v1.PluginEventKind_PLUGIN_EVENT_KIND_END_OF_REPLAY, ReplaySource: cplane.BGPSource})
	f.replay = scaleEvents(t, events...)
	for k, location := range []string{"b", "a"} {
		if change == "isd" {
			f.updates[k] = scaleEvents(t, discovery(location))
		} else {
			updates := make([]*v1.PluginEvent, batch)
			teid := uint32(512)
			if k == 1 {
				teid = 256
			}
			for i := range updates {
				updates[i] = session(i, teid)
			}
			f.updates[k] = scaleEvents(t, updates...)
		}
	}
	var err error
	f.typedReplay, err = cplane.DecodeEvents(f.replay)
	if err != nil {
		t.Fatal(err)
	}
	for k, raw := range f.updates {
		f.typed[k], err = cplane.DecodeEvents(raw)
		if err != nil {
			t.Fatal(err)
		}
	}
	return f
}

type scaleSink struct {
	last    cplane.Composition
	commits int
}

func (s *scaleSink) ApplyComposition(set cplane.Composition) error {
	s.last = set
	s.commits++
	return nil
}

type scaleHost struct{ ops *benchmarkOps }

func (h scaleHost) Begin(kind cplane.Kind) uint64 { id, _ := h.ops.ApplyBegin(uint32(kind)); return id }
func (h scaleHost) Put(id uint64, b []byte) cplane.Status {
	if h.ops.ApplyPut(id, b) != nil {
		return cplane.StatusInternal
	}
	return cplane.StatusOK
}
func (h scaleHost) Commit(id uint64) cplane.Status {
	if h.ops.ApplyCommit(id) != nil {
		return cplane.StatusInternal
	}
	return cplane.StatusOK
}
func (h scaleHost) Abort(id uint64) { h.ops.ApplyAbort(id) }
func scaleController(t testing.TB, sink *scaleSink) *mupcontroller.Controller {
	t.Helper()
	input, err := cplane.DecodeInputConfig(configuration(false), cplane.FeatureBGPPath|cplane.FeatureInputContexts)
	if err != nil {
		t.Fatal(err)
	}
	c, err := mupcontroller.New(input, sink, func(cplane.LogLevel, string) {})
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func verifyScale(t testing.TB, f scaleFixture, raw []byte, iteration int) {
	t.Helper()
	var chunk v1.PluginApplyChunk
	if err := proto.Unmarshal(raw, &chunk); err != nil {
		t.Fatal(err)
	}
	if chunk.DesiredRevision == 0 || len(chunk.ForwardingHeadends) != f.sessions || len(chunk.MupUplinks) != 0 {
		t.Fatalf("wrong scaled desired set: revision=%d headends=%d uplinks=%d", chunk.DesiredRevision, len(chunk.ForwardingHeadends), len(chunk.MupUplinks))
	}
	expected := map[string]string{}
	for i := 0; i < f.sessions; i++ {
		location := "a"
		teid := uint32(256)
		if iteration&1 == 1 {
			if f.change == "isd" {
				location = "b"
			} else if i < f.batch {
				teid = 512
			}
		}
		sid := netip.MustParseAddr("fd00:" + location + ":0:100::").As16()
		copy(sid[7:11], []byte{172, 16, 0, 1})
		sid[11] = 9 << 2
		binary.BigEndian.PutUint32(sid[12:], teid)
		expected[scalePrefix(i)] = netip.AddrFrom16(sid).String()
	}
	for _, h := range chunk.ForwardingHeadends {
		if h.Context != "mobile" || h.Entry == nil {
			t.Fatal("invalid scaled headend")
		}
		e := h.Entry
		sid, ok := expected[e.TriggerPrefix]
		if !ok || e.Mode != 2 || e.SrcAddr != "fd00:feed::1" || len(e.Segments) != 1 || e.Segments[0] != sid {
			t.Fatalf("unexpected headend: %+v", e)
		}
		delete(expected, e.TriggerPrefix)
	}
	if len(expected) != 0 {
		t.Fatal("missing scaled headend")
	}
}

// BenchmarkCompositionScale measures explicit boundaries; core still includes
// GoBGP decoding inside View. The stages are not additive cost percentages.
func BenchmarkCompositionScale(b *testing.B) {
	n, _ := strconv.Atoi(os.Getenv("VINBERO_CPLANE_SESSIONS"))
	batch, _ := strconv.Atoi(os.Getenv("VINBERO_CPLANE_BATCH"))
	change := os.Getenv("VINBERO_CPLANE_CHANGE")
	stage := os.Getenv("VINBERO_CPLANE_STAGE")
	f := newScaleFixture(b, n, batch, change)
	ops := &benchmarkOps{}
	sink := &scaleSink{}
	ctx := context.Background()
	var run func(int)
	switch stage {
	case "core", "encode":
		controller := scaleController(b, sink)
		if results := controller.Update(f.typedReplay); len(results) != 0 {
			b.Fatal(results)
		}
		if stage == "core" {
			run = func(k int) {
				if results := controller.Update(f.typed[k]); len(results) != 0 {
					b.Fatal(results)
				}
			}
		} else {
			replayRevision := sink.last.Revision
			var sets [2]cplane.Composition
			for k := range sets {
				if results := controller.Update(f.typed[k]); len(results) != 0 {
					b.Fatal(results)
				}
				sets[k] = sink.last
			}
			client := &cplane.Client{Host: scaleHost{ops}}
			revision := replayRevision
			run = func(k int) {
				revision += uint64(f.batch)
				set := sets[k]
				set.Revision = revision
				if err := client.ApplyComposition(set); err != nil {
					b.Fatal(err)
				}
			}
		}
	case "native", "wasm":
		cfg := wasm.Config{Name: "scale-bench", ConfigBlob: configuration(false), Ops: ops, Capabilities: wasm.Capabilities{wasm.CapMUP: {}}}
		var instance eventInstance
		var err error
		if stage == "native" {
			instance, err = Instantiate(ctx, Config{Config: cfg, Implementation: MUPComposition, Version: ImplementationVersion})
		} else {
			path := os.Getenv("VINBERO_CPLANE_WASM")
			if path != "" {
				cfg.Module, err = os.ReadFile(path)
			} else {
				cfg.Module = parityModule(b, false)
			}
			if err == nil {
				instance, err = wasm.Instantiate(ctx, cfg)
			}
		}
		if err != nil {
			b.Fatal(err)
		}
		defer instance.Close(ctx)
		if status, err := instance.HandleEvents(ctx, f.replay); err != nil || len(status) != 0 {
			b.Fatalf("replay failed: %x %v", status, err)
		}
		run = func(k int) {
			status, err := instance.HandleEvents(ctx, f.updates[k])
			if err != nil || len(status) != 0 {
				b.Fatalf("update failed: %x %v", status, err)
			}
		}
	case "decode":
		run = func(k int) {
			events, err := cplane.DecodeEvents(f.updates[k])
			if err != nil || len(events) != len(f.typed[k]) {
				b.Fatalf("decode failed: %v", err)
			}
			for _, e := range events {
				if e.Route.BGPPath == nil || len(e.Route.BGPPath.NLRI) == 0 {
					b.Fatal("missing decoded path")
				}
			}
		}
	default:
		b.Fatal("VINBERO_CPLANE_STAGE must be core/native/wasm/decode/encode")
	}
	rawOutput := func() []byte {
		if stage == "core" {
			capture := &benchmarkOps{}
			client := cplane.Client{Host: scaleHost{capture}}
			if err := client.ApplyComposition(sink.last); err != nil {
				b.Fatal(err)
			}
			return capture.last
		}
		return ops.last
	}
	for k := 0; k < 2; k++ {
		run(k)
		if stage != "decode" {
			verifyScale(b, f, rawOutput(), k+1)
		}
	}
	before := ops.commits
	if stage == "core" {
		before = sink.commits
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		run(i & 1)
	}
	b.StopTimer()
	var final []byte
	if stage != "decode" {
		after := ops.commits
		if stage == "core" {
			after = sink.commits
		}
		if after-before != b.N {
			b.Fatalf("wrong commit count: %d for%d", after-before, b.N)
		}
		final = rawOutput()
		verifyScale(b, f, final, b.N)
	}
	b.ReportMetric(float64(batch), "updates/batch")
	b.ReportMetric(float64(n), "sessions")
	if dir := os.Getenv("VINBERO_CPLANE_TRACE_DIR"); dir != "" && b.N > 1 {
		if err := os.Mkdir(dir, 0700); err != nil {
			b.Fatal(err)
		}
		for name, raw := range map[string][]byte{"config.bin": configuration(false), "replay.bin": f.replay, "update-0.bin": f.updates[0], "update-1.bin": f.updates[1], "final-chunk.bin": final} {
			if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
				b.Fatal(err)
			}
		}
		meta, _ := json.Marshal(map[string]any{"sessions": n, "batch": batch, "change": change, "stage": stage, "iterations": b.N})
		if err := os.WriteFile(filepath.Join(dir, "case.json"), meta, 0600); err != nil {
			b.Fatal(err)
		}
	}
	h := sha256.New()
	for _, raw := range [][]byte{configuration(false), f.replay, f.updates[0], f.updates[1]} {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(raw)))
		h.Write(length[:])
		h.Write(raw)
	}
	b.Logf("input_sha256=%x", h.Sum(nil))
}

func TestScaleFixtures(t *testing.T) {
	for _, n := range []int{1, 64, 512} {
		for _, change := range []string{"st1", "isd"} {
			t.Run(fmt.Sprintf("%d-%s", n, change), func(t *testing.T) {
				f := newScaleFixture(t, n, 1, change)
				sink := &scaleSink{}
				c := scaleController(t, sink)
				if out := c.Update(f.typedReplay); len(out) != 0 {
					t.Fatal(out)
				}
				for k := 0; k < 2; k++ {
					if out := c.Update(f.typed[k]); len(out) != 0 {
						t.Fatal(out)
					}
					ops := &benchmarkOps{}
					client := cplane.Client{Host: scaleHost{ops}}
					if err := client.ApplyComposition(sink.last); err != nil {
						t.Fatal(err)
					}
					verifyScale(t, f, ops.last, k+1)
				}
			})
		}
	}
}

func TestScaleBatchFixture(t *testing.T) {
	f := newScaleFixture(t, 512, 16, "st1")
	sink := &scaleSink{}
	c := scaleController(t, sink)
	if out := c.Update(f.typedReplay); len(out) != 0 {
		t.Fatal(out)
	}
	for k := 0; k < 2; k++ {
		if out := c.Update(f.typed[k]); len(out) != 0 {
			t.Fatal(out)
		}
		ops := &benchmarkOps{}
		client := cplane.Client{Host: scaleHost{ops}}
		if err := client.ApplyComposition(sink.last); err != nil {
			t.Fatal(err)
		}
		verifyScale(t, f, ops.last, k+1)
	}
}
