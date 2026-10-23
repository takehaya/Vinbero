package cplane

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/cplane/native"
	"github.com/takehaya/vinbero/pkg/cplane/wasm"
	"google.golang.org/protobuf/proto"
)

// This is a recovery/isolation test with an artificial worker stall, not an
// offered-rate benchmark or a claim that another plugin's latency is unchanged.
// Both controllers use real Manager/PluginOps against in-memory forwarding maps.
func TestOverflowReplayPreservesOtherPluginProgress(t *testing.T) {
	for _, backend := range []string{BackendNative, BackendWASM} {
		t.Run(backend, func(t *testing.T) {
			ctx := context.Background()
			a := overflowRegistration(t, backend)
			bScope, err := ParseScope(ScopeSpec{HeadendPrefixes: []string{"198.51.100.0/24"}})
			if err != nil {
				t.Fatal(err)
			}
			b := Registration{Name: "overflow-sentinel", Backend: BackendNative,
				NativeID: native.CustomBehavior, NativeVersion: native.ImplementationVersion,
				Families: []bgp.Family{bgp.FamilyVPNv4}, Scope: bScope,
				Capabilities: wasm.Capabilities{wasm.CapHeadend: {}}}
			discovery, session := offeredDiscovery(t), offeredSession(t, 1, 0)
			sentinel := customBehaviorRoute("198.51.100.0/24", "fd00:b::1")
			src := &overflowSource{&compositionSource{newFakeSource()}}
			src.setRib(discovery, session, sentinel)
			maps := newServiceFake()
			newManager := func(source *overflowSource, output *serviceFake) *Manager {
				m, err := NewManager(ManagerConfig{AllowNative: true, Source: source,
					Headend: output, ForwardingMaps: output, EncapSource: testEncapSource,
					ResolveMUPInstance: func(string) (uint32, error) { return 7, nil },
					ResolveInputTarget: func(bgp.RouteEvent) (string, uint16, bool) { return "", 0, true }})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { m.Close(ctx) })
				return m
			}
			m := newManager(src, maps)
			for _, reg := range []Registration{a, b} {
				if err := m.Register(ctx, reg); err != nil {
					t.Fatal(err)
				}
			}
			report := &offeredReport{Origin: time.Now()}
			initialA, err := report.drain(m, a.Name)
			if err != nil {
				t.Fatal(err)
			}
			checkSentinel := func(sid string) {
				t.Helper()
				if !m.WaitIdle(b.Name, 5*time.Second) {
					t.Fatal("sentinel did not make progress while the other worker was stalled")
				}
				st, ok := m.StatsFor(b.Name)
				if !ok || st.Dead || st.DroppedEvents != 0 || st.Restarts != 0 || st.Quarantined != 0 ||
					st.InputFault != "" || st.OutputFailure != "" || st.CleanupPending || st.PendingDeclarations != 0 {
					t.Fatalf("sentinel unhealthy: %+v", st)
				}
				entry, ok := maps.getV4("198.51.100.0/24")
				if !ok || entry.NumSegments != 1 || netip.AddrFrom16(entry.Segments[0]).String() != sid {
					t.Fatalf("sentinel did not apply %s: %+v", sid, entry)
				}
			}
			checkSentinel("fd00:b::1")
			initialMaps := offeredMapSnapshot(maps)
			m.mu.Lock()
			pa, pb := m.plugins[a.Name], m.plugins[b.Name]
			originalA, originalB := pa.inst, pb.inst
			m.mu.Unlock()
			var failures, replayStarts, replayEnds atomic.Int64
			entered, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			// Release before Manager cleanup, including after an assertion failure.
			t.Cleanup(unblock)
			for _, p := range []*plugin{pa, pb} {
				installedOne := make(chan struct{})
				if !p.worker.submitBarrier(func() {
					oldFail := p.worker.onFail
					p.worker.onFail = func(err error) { failures.Add(1); oldFail(err) }
					if p == pa {
						handler := p.worker.handler
						first := true
						p.worker.handler = func(ctx context.Context, raw []byte) ([]byte, error) {
							if first {
								first = false
								close(entered)
								<-release // Outside the instance's runtime call budget.
							}
							out, err := handler(ctx, raw)
							var batch v1.PluginEventBatch
							if err == nil && proto.Unmarshal(raw, &batch) == nil {
								for _, event := range batch.Events {
									switch event.Kind {
									case v1.PluginEventKind_PLUGIN_EVENT_KIND_START_OF_REPLAY:
										replayStarts.Add(1)
									case v1.PluginEventKind_PLUGIN_EVENT_KIND_END_OF_REPLAY:
										replayEnds.Add(1)
									}
								}
							}
							return out, err
						}
					}
					close(installedOne)
				}) {
					t.Fatal("could not install worker instrumentation")
				}
				select {
				case <-installedOne:
				case <-time.After(5 * time.Second):
					t.Fatal("instrumentation barrier did not run")
				}
			}
			if !src.emit(a.Name, session) {
				t.Fatal("missing A subscription")
			}
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("A handler did not reach the artificial stall")
			}
			// Fill both production queue and replay hold, without changing limits.
			for i := 0; i < 3*deliveryQueueDepth; i++ {
				if !src.emit(a.Name, session) {
					t.Fatal("A subscription disappeared")
				}
			}
			beforeFinal := pa.worker.droppedCount()
			session = offeredSession(t, 1, 999)
			src.setRib(discovery, session, sentinel)
			if !src.emit(a.Name, session) || pa.worker.droppedCount() <= beforeFinal {
				t.Fatal("latest update was not dropped; replay recovery was not exercised")
			}
			for i := 2; i <= 4; i++ {
				sid := fmt.Sprintf("fd00:b::%x", i)
				sentinel = customBehaviorRoute("198.51.100.0/24", sid)
				src.setRib(discovery, session, sentinel)
				if !src.emit(b.Name, sentinel) {
					t.Fatal("missing sentinel subscription")
				}
				checkSentinel(sid)
			}
			unblock()
			finalA, err := report.drain(m, a.Name)
			if err != nil {
				t.Fatal(err)
			}
			checkSentinel("fd00:b::4")
			if finalA.Dropped <= initialA.Dropped || finalA.Stats.Snapshots <= initialA.Stats.Snapshots ||
				replayStarts.Load() == 0 || replayEnds.Load() == 0 || failures.Load() != 0 {
				t.Fatalf("missing recovery or runtime failure: initial=%+v final=%+v replay=%d/%d failures=%d",
					initialA, finalA, replayStarts.Load(), replayEnds.Load(), failures.Load())
			}
			m.mu.Lock()
			unchanged := pa.inst == originalA && pb.inst == originalB
			m.mu.Unlock()
			if !unchanged {
				t.Fatal("instance was replaced during recovery")
			}
			// Fresh full-RIB native replay is a state oracle, not independent BPF proof.
			refSource := &overflowSource{&compositionSource{newFakeSource()}}
			refSource.setRib(discovery, session, sentinel)
			refMaps := newServiceFake()
			ref := newManager(refSource, refMaps)
			refA := overflowRegistration(t, BackendNative)
			for _, reg := range []Registration{refA, b} {
				if err := ref.Register(ctx, reg); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := report.drain(ref, refA.Name); err != nil || !ref.WaitIdle(b.Name, 5*time.Second) {
				t.Fatalf("reference did not drain: %v", err)
			}
			got, want := offeredMapSnapshot(maps), offeredMapSnapshot(refMaps)
			if len(got.V4) != 2 || !reflect.DeepEqual(got, want) || got.V4["10.64.0.1/32"] == initialMaps.V4["10.64.0.1/32"] {
				t.Fatalf("recovery maps differ from the latest full RIB: got=%+v want=%+v", got, want)
			}
			t.Logf("artificial stall recovered: backend=%s dropped_batches=%d snapshots=%d replay_markers=%d/%d sentinel_updates=3 failures=%d",
				backend, finalA.Dropped-initialA.Dropped, finalA.Stats.Snapshots-initialA.Stats.Snapshots,
				replayStarts.Load(), replayEnds.Load(), failures.Load())
		})
	}
}

func overflowRegistration(t *testing.T, backend string) Registration {
	t.Helper()
	scope, err := ParseScope(ScopeSpec{HeadendPrefixes: []string{"10.64.0.1/32"}})
	if err != nil {
		t.Fatal(err)
	}
	reg := Registration{Name: "overflow-mup", Backend: backend, Scope: scope,
		Families:     []bgp.Family{bgp.FamilyMUPIPv4, bgp.FamilyMUPIPv6},
		Capabilities: wasm.Capabilities{wasm.CapHeadend: {}, wasm.CapMUP: {}},
		Config:       []byte(`{"context":"mobile","source":"fd00:feed::1","args_offset":7,"observe_only":false}`),
		Input: &v1.CplaneInputPolicy{Version: 1, Contexts: []*v1.CplaneInputContext{{Name: "mobile",
			Grants:           []*v1.CplaneInputGrant{{Families: []string{"mup_ipv4", "mup_ipv6"}, RouteTargets: []string{"65000:7"}}},
			DelegateMupTypes: []uint32{3}}}}}
	if backend == BackendNative {
		reg.NativeID, reg.NativeVersion = native.MUPComposition, native.ImplementationVersion
	} else {
		path := os.Getenv("VINBERO_CPLANE_WASM")
		if path == "" {
			path = "../../out/cplane-route-composition.wasm"
		}
		reg.Module, err = os.ReadFile(path)
		if err != nil {
			if os.Getenv("VINBERO_CPLANE_PARITY") == "1" || os.Getenv("VINBERO_CPLANE_WASM") != "" {
				t.Fatal(err)
			}
			t.Skip("make cplane-route-composition or set VINBERO_CPLANE_WASM")
		}
	}
	return reg
}

// fakeSource deliberately ignores snapshot families. This mixed-family fixture
// honors the subscription filter so unrelated routes never reach strict input
// authorization, matching the real source's SnapshotTo contract.
type overflowSource struct{ *compositionSource }

func (s *overflowSource) SnapshotTo(families []bgp.Family, handler bgp.RouteHandler) error {
	return s.compositionSource.SnapshotTo(families, func(event bgp.RouteEvent) {
		if len(families) == 0 || slices.Contains(families, event.Family) {
			handler(event)
		}
	})
}
