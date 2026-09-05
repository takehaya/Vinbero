package cplane

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"testing"
	"time"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bgp/demux"
	"github.com/takehaya/vinbero/pkg/cplane/wasm"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

type rollbackSubscriber struct{ handler bgp.RouteHandler }

func (s *rollbackSubscriber) Subscribe(_ bgp.Family, h bgp.RouteHandler) (func(), error) {
	s.handler = h
	return func() {}, nil
}

type rollbackClaims struct {
	*demux.ClaimRegistry
	afterReplace func()
}

func (c *rollbackClaims) Replace(name string, behaviors []uint16) error {
	if err := c.ClaimRegistry.Replace(name, behaviors); err != nil {
		return err
	}
	c.afterReplace()
	return nil
}

type rejectingDemux struct{ *demux.Demux }

func (d *rejectingDemux) RegisterQuiet(string, []bgp.Family, bgp.RouteHandler) (func(), error) {
	return nil, errors.New("subscription refused")
}

func TestFailedRegistrationRestoresBuiltinView(t *testing.T) {
	for _, stage := range []string{"build", "subscribe"} {
		for _, withdrawn := range []bool{false, true} {
			t.Run(stage+map[bool]string{false: "/retained", true: "/withdrawn"}[withdrawn], func(t *testing.T) {
				sub := &rollbackSubscriber{}
				registry := demux.NewClaimRegistry(nil)
				d := demux.New(sub, nil, nil)
				d.SetClaimRegistry(registry)
				installed := false
				if _, err := d.RegisterBuiltin("applier", nil, func(ev bgp.RouteEvent) { installed = !ev.IsWithdraw }); err != nil {
					t.Fatal(err)
				}
				if err := d.Start(); err != nil {
					t.Fatal(err)
				}
				defer d.Stop()
				route := bgp.RouteEvent{
					Family: bgp.FamilyVPNv4, EndpointBehavior: 0xFE01,
					Source: bgp.PathSource{Peer: netip.MustParseAddr("192.0.2.1")},
					VPN:    &bgp.VPNRoute{RD: "65000:1", Prefix: "10.0.0.0/24"},
				}
				sub.handler(route)
				if !installed {
					t.Fatal("initial route was not installed")
				}
				claims := &rollbackClaims{ClaimRegistry: registry, afterReplace: func() {
					if registry.IsClaimed(0xFE01) {
						sub.handler(route)
						if installed {
							t.Fatal("tentative claim did not retract the route")
						}
						if withdrawn {
							gone := route
							gone.IsWithdraw = true
							gone.EndpointBehavior = 0
							sub.handler(gone)
						}
					}
				}}
				var source EventSource = d
				module := []byte("not wasm")
				if stage == "subscribe" {
					source = &rejectingDemux{d}
					module = declareModule(t)
				}
				m, _ := newTestManager(t, source, claims)
				if err := m.Register(context.Background(), Registration{
					Name: "declare", Module: module, Behaviors: []uint16{0xFE01},
					Capabilities: testCaps(), Scope: testScope(),
				}); err == nil {
					t.Fatal("registration unexpectedly succeeded")
				}
				if registry.IsClaimed(0xFE01) || installed == withdrawn {
					t.Fatalf("rollback left claimed=%v installed=%v withdrawn=%v", registry.IsClaimed(0xFE01), installed, withdrawn)
				}
			})
		}
	}
}

// replayingSource supports snapshots but only the ordinary registration API.
// Its synchronous registration replay occurs before the new plugin is visible.
type replayingSource struct{ inner *fakeSource }

func (s *replayingSource) Register(name string, families []bgp.Family, h bgp.RouteHandler) (func(), error) {
	cancel, err := s.inner.Register(name, families, h)
	if err != nil {
		return nil, err
	}
	h(bgp.RouteEvent{Family: bgp.FamilyVPNv4})
	return cancel, nil
}

func (s *replayingSource) SnapshotTo(families []bgp.Family, h bgp.RouteHandler) error {
	return s.inner.SnapshotTo(families, h)
}

func TestRegistrationReplayStillPublishesThroughSnapshot(t *testing.T) {
	src := &replayingSource{inner: newFakeSource()}
	m, headend := newTestManager(t, src, newFakeClaims())
	if err := m.Register(context.Background(), Registration{
		Name: "declare", Module: declareModule(t), Capabilities: testCaps(), Scope: testScope(),
	}); err != nil {
		t.Fatal(err)
	}
	waitDelivered(t, m, "declare")
	if src.inner.snapshotCount() != 1 || headend.countV4() != 1 {
		t.Fatal("registration replay left the declaration unpublished")
	}
}

func TestMalformedStatusStillCompletesReplay(t *testing.T) {
	completed := make(chan struct{})
	statuses := 0
	w := newWorker("replay", zap.NewNop(), func(context.Context, []byte) ([]byte, error) {
		return []byte{0xff}, nil
	}, func(err error) { t.Error(err) }, func(*v1.PluginEventStatus) { statuses++ }, nil, 0, nil)
	defer w.close()
	m := &Manager{}
	if !w.submitCompletion(m.endOfReplayBatch(ReplaySourceBGP), func() { close(completed) }) {
		t.Fatal("replay completion was not queued")
	}
	select {
	case <-completed:
		if statuses != 1 {
			t.Fatal("successful guest call did not report delivery")
		}
	case <-time.After(time.Second):
		t.Fatal("malformed status lost a successful replay's completion")
	}
}

func TestEmptySuccessfulStatusResetsFailures(t *testing.T) {
	m := &Manager{logger: zap.NewNop()}
	p := &plugin{counters: newCounters()}
	w := &worker{
		logger:   zap.NewNop(),
		handler:  func(context.Context, []byte) ([]byte, error) { return nil, nil },
		onFail:   func(err error) { t.Error(err) },
		onStatus: func(s *v1.PluginEventStatus) { m.delivered(p, s) },
	}
	for i := 0; i < maxRestarts+2; i++ {
		p.restarts++
		w.deliver(&v1.PluginEventBatch{})
		if p.restarts != 0 {
			t.Fatalf("successful empty status left restart counter=%d", p.restarts)
		}
	}
}

func TestStagedDeclarationsKeepOnlyTheLatestSet(t *testing.T) {
	h := newFakeHeadendOps()
	ops, err := NewPluginOps(PluginOpsConfig{
		Owner: ownerA, Headend: h, Capabilities: testCaps(), Guard: testGuard(),
		EncapSource: testEncapSource, MaxOpenTransactions: 1, MaxEntriesPerTransaction: 1,
		MaxBytesPerTransaction: 4096,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := proto.Marshal(&v1.PluginApplyChunk{HeadendEntries: []*v1.PluginHeadendEntry{{TriggerPrefix: "10.0.1.0/24", Segments: []string{"fd00:2::1"}}}})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10000; i++ {
		gen, err := ops.ApplyBegin(uint32(v1.PluginApplyKind_PLUGIN_APPLY_KIND_HEADEND_V4))
		if err != nil {
			t.Fatal(err)
		}
		if err := ops.ApplyPut(gen, raw); err != nil {
			t.Fatal(err)
		}
		if err := ops.ApplyCommit(gen); err != nil {
			t.Fatal(err)
		}
	}
	if len(ops.staged) != 1 || ops.staged[0].seq != 10000 {
		t.Fatalf("staged %d sets instead of only the latest", len(ops.staged))
	}
	if err := ops.Publish(); err != nil {
		t.Fatal(err)
	}
	if ops.lastApplied[v1.PluginApplyKind_PLUGIN_APPLY_KIND_HEADEND_V4] != 10000 {
		t.Fatal("publication did not apply the latest declaration")
	}
}

func TestReplayPublicationWaitsForGuestCompletion(t *testing.T) {
	for _, gate := range []v1.PluginEventKind{
		v1.PluginEventKind_PLUGIN_EVENT_KIND_END_OF_REPLAY,
		v1.PluginEventKind_PLUGIN_EVENT_KIND_ROUTE,
	} {
		t.Run(gate.String(), func(t *testing.T) {
			h := newFakeHeadendOps()
			if _, err := ApplyHeadendSet(h, nil, ownerA, AFv4, desire("10.0.1.0/24"), unlimited); err != nil {
				t.Fatal(err)
			}
			ops, err := NewPluginOps(PluginOpsConfig{
				Owner: ownerA, Headend: h, Capabilities: testCaps(), Guard: testGuard(), EncapSource: testEncapSource,
			})
			if err != nil {
				t.Fatal(err)
			}
			// configure has an empty view; replay will replace this declaration.
			gen, err := ops.ApplyBegin(uint32(v1.PluginApplyKind_PLUGIN_APPLY_KIND_HEADEND_V4))
			if err != nil {
				t.Fatal(err)
			}
			if err := ops.ApplyCommit(gen); err != nil {
				t.Fatal(err)
			}
			entered, release := make(chan struct{}), make(chan struct{})
			w := newWorker("replay", zap.NewNop(), func(_ context.Context, raw []byte) ([]byte, error) {
				var batch v1.PluginEventBatch
				if err := proto.Unmarshal(raw, &batch); err != nil {
					return nil, err
				}
				if batch.Events[0].Kind == gate {
					close(entered)
					<-release
					gen, err := ops.ApplyBegin(uint32(v1.PluginApplyKind_PLUGIN_APPLY_KIND_HEADEND_V4))
					if err != nil {
						return nil, err
					}
					chunk, err := proto.Marshal(&v1.PluginApplyChunk{HeadendEntries: []*v1.PluginHeadendEntry{{TriggerPrefix: "10.0.1.0/24", Segments: []string{"fd00:2::1"}}}})
					if err != nil {
						return nil, err
					}
					if err := ops.ApplyPut(gen, chunk); err != nil {
						return nil, err
					}
					return nil, ops.ApplyCommit(gen)
				}
				return nil, nil
			}, func(err error) { t.Error(err) }, func(*v1.PluginEventStatus) {}, nil, 0, nil)
			defer w.close()
			released := false
			defer func() {
				if !released {
					close(release)
				}
			}()
			p := &plugin{name: "replay", worker: w, ops: ops, counters: newCounters()}
			m := &Manager{plugins: map[string]*plugin{p.name: p}, snapshots: newFakeSource(), logger: zap.NewNop()}
			if gate == v1.PluginEventKind_PLUGIN_EVENT_KIND_ROUTE {
				m.snapshots = snapshotFunc(func([]bgp.Family, bgp.RouteHandler) error {
					w.submit(m.routeBatch(bgp.RouteEvent{Family: bgp.FamilyVPNv4}))
					return nil
				})
			}
			m.snapshot(p)
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("publication gate never reached the guest")
			}
			ops.mu.Lock()
			published := ops.published
			ops.mu.Unlock()
			if published || h.countV4() != 1 {
				t.Fatal("published or pruned while the guest was still replaying")
			}
			close(release)
			released = true
			deadline := time.Now().Add(time.Second)
			for !w.caughtUp() && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if !w.caughtUp() {
				t.Fatal("worker did not finish replay")
			}
			ops.mu.Lock()
			published = ops.published
			ops.mu.Unlock()
			if !published || h.countV4() != 1 {
				t.Fatal("completed replay did not publish its final set")
			}
		})
	}
}

func TestOldReplayCannotPublishReplacement(t *testing.T) {
	ops, err := NewPluginOps(PluginOpsConfig{Owner: ownerA, Headend: newFakeHeadendOps()})
	if err != nil {
		t.Fatal(err)
	}
	old, replacement := &wasm.Instance{}, &wasm.Instance{}
	p := &plugin{name: "replay", ops: ops, inst: replacement}
	m := &Manager{plugins: map[string]*plugin{p.name: p}}
	m.publish(p, old)
	if ops.published {
		t.Fatal("an old replay published the replacement")
	}
}

type snapshotFunc func([]bgp.Family, bgp.RouteHandler) error

func (f snapshotFunc) SnapshotTo(families []bgp.Family, handler bgp.RouteHandler) error {
	return f(families, handler)
}

func TestReplayDebtKeepsInheritedStateUntilFreshCompletion(t *testing.T) {
	headend := newFakeHeadendOps()
	if _, err := ApplyHeadendSet(headend, nil, ownerA, AFv4, desire("10.0.1.0/24"), unlimited); err != nil {
		t.Fatal(err)
	}
	ops, err := NewPluginOps(PluginOpsConfig{
		Owner: ownerA, Headend: headend, Capabilities: testCaps(), Guard: testGuard(), EncapSource: testEncapSource,
	})
	if err != nil {
		t.Fatal(err)
	}
	gen, err := ops.ApplyBegin(uint32(v1.PluginApplyKind_PLUGIN_APPLY_KIND_HEADEND_V4))
	if err != nil {
		t.Fatal(err)
	}
	if err := ops.ApplyCommit(gen); err != nil {
		t.Fatal(err)
	}
	rawSet, err := proto.Marshal(&v1.PluginApplyChunk{HeadendEntries: []*v1.PluginHeadendEntry{{
		TriggerPrefix: "10.0.1.0/24", Segments: []string{"fd00:2::1"},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	ends := 0
	w := newWorker("replay", zap.NewNop(), func(_ context.Context, raw []byte) ([]byte, error) {
		var batch v1.PluginEventBatch
		if err := proto.Unmarshal(raw, &batch); err != nil {
			return nil, err
		}
		if batch.Events[0].Kind == v1.PluginEventKind_PLUGIN_EVENT_KIND_END_OF_REPLAY {
			ends++
			if ends == 2 {
				gen, err := ops.ApplyBegin(uint32(v1.PluginApplyKind_PLUGIN_APPLY_KIND_HEADEND_V4))
				if err != nil {
					return nil, err
				}
				if err := ops.ApplyPut(gen, rawSet); err != nil {
					return nil, err
				}
				return nil, ops.ApplyCommit(gen)
			}
		}
		return nil, nil
	}, func(err error) { t.Error(err) }, func(*v1.PluginEventStatus) {}, nil, 0, nil)
	defer w.close()
	secondStarted, release := make(chan struct{}), make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	p := &plugin{name: "replay", worker: w, ops: ops, counters: newCounters()}
	m := &Manager{plugins: map[string]*plugin{p.name: p}, logger: zap.NewNop()}
	snapshots := 0
	m.snapshots = snapshotFunc(func([]bgp.Family, bgp.RouteHandler) error {
		snapshots++
		if snapshots == 1 {
			// The first RIB is already stale: held live events overflow.
			for i := 0; i <= deliveryQueueDepth; i++ {
				w.submit(m.routeBatch(bgp.RouteEvent{Family: bgp.FamilyVPNv4}))
			}
		} else {
			close(secondStarted)
			<-release
		}
		return nil
	})
	m.snapshot(p)
	select {
	case <-secondStarted:
	case <-time.After(time.Second):
		t.Fatal("snapshot debt was not repaid")
	}
	deadline := time.Now().Add(time.Second)
	for !w.caughtUp() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !w.caughtUp() {
		t.Fatal("first replay did not finish")
	}
	ops.mu.Lock()
	published := ops.published
	ops.mu.Unlock()
	if published || headend.countV4() != 1 {
		t.Fatal("stale EOR published and pruned before replay debt was repaid")
	}
	close(release)
	released = true
	deadline = time.Now().Add(time.Second)
	for !published && time.Now().Before(deadline) {
		ops.mu.Lock()
		published = ops.published
		ops.mu.Unlock()
		if !published {
			time.Sleep(time.Millisecond)
		}
	}
	if !published || headend.countV4() != 1 {
		t.Fatal("fresh EOR did not publish the recovered set")
	}
}

func TestManagerTickAndNowShareClockAcrossInstances(t *testing.T) {
	module, err := os.ReadFile("wasm/testdata/clock.wasm")
	if err != nil {
		t.Fatal(err)
	}
	m := &Manager{started: time.Now().Add(-time.Hour)}
	for i := 0; i < 2; i++ {
		ops, err := NewPluginOps(PluginOpsConfig{Owner: ownerA, Headend: newFakeHeadendOps()})
		if err != nil {
			t.Fatal(err)
		}
		inst, err := wasm.Instantiate(context.Background(), wasm.Config{
			Name: "clock", Module: module, Ops: ops, NowMonotonic: m.nowMonotonic,
		})
		if err != nil {
			t.Fatal(err)
		}
		err = m.tick(&plugin{inst: inst})
		_ = inst.Close(context.Background())
		if err != nil {
			t.Fatalf("tick and now_monotonic disagree: %v", err)
		}
	}
}
