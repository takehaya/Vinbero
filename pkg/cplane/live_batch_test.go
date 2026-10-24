package cplane

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/cplane/wasm"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

func liveTestRoute(sequence uint64) *v1.PluginEventBatch {
	return &v1.PluginEventBatch{Events: []*v1.PluginEvent{{Kind: v1.PluginEventKind_PLUGIN_EVENT_KIND_ROUTE,
		Sequence: sequence, Route: &v1.PluginRoute{Family: "mup_ipv4", Prefix: "10.0.0.1/32"}}}}
}

func pausedBatchWorker(t *testing.T, limit int, handler func(context.Context, []byte) ([]byte, error), fail func(error), status func(*v1.PluginEventStatus)) (*worker, func()) {
	t.Helper()
	w := newWorker("batch", zap.NewNop(), handler, fail, status, nil, 0, nil)
	t.Cleanup(w.close)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unpause := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unpause)
	w.submitBarrier(func() { close(entered); <-release })
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not reach setup barrier")
	}
	w.maxBatchEvents, w.maxBatchBytes = limit, 4<<20
	return w, unpause
}

func batchWorkerIdle(t *testing.T, w *worker) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !w.caughtUp() {
		if time.Now().After(deadline) {
			t.Fatal("worker did not account every original delivery")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestLiveBatchPreservesBoundariesOrderAndStatuses(t *testing.T) {
	var batches [][]uint64
	var quarantined []uint64
	w, release := pausedBatchWorker(t, 16, func(_ context.Context, raw []byte) ([]byte, error) {
		var b v1.PluginEventBatch
		if err := proto.Unmarshal(raw, &b); err != nil {
			return nil, err
		}
		var seq []uint64
		status := &v1.PluginEventStatus{}
		for _, ev := range b.Events {
			seq = append(seq, ev.Sequence)
			status.Results = append(status.Results, &v1.PluginEventResult{Sequence: ev.Sequence, Disposition: v1.PluginEventDisposition_PLUGIN_EVENT_DISPOSITION_QUARANTINE})
		}
		batches = append(batches, seq)
		return proto.Marshal(status)
	}, func(err error) { t.Errorf("handler: %v", err) }, func(s *v1.PluginEventStatus) {
		for _, r := range s.Results {
			quarantined = append(quarantined, r.Sequence)
		}
	})
	marker := func(seq uint64, kind v1.PluginEventKind) *v1.PluginEventBatch {
		return &v1.PluginEventBatch{Events: []*v1.PluginEvent{{Kind: kind, Sequence: seq}}}
	}
	w.submitBlocking(marker(1, v1.PluginEventKind_PLUGIN_EVENT_KIND_START_OF_REPLAY))
	w.submitBlocking(liveTestRoute(2)) // Replay routes never gain live eligibility.
	w.submitBlocking(liveTestRoute(3))
	w.submitCompletion(marker(4, v1.PluginEventKind_PLUGIN_EVENT_KIND_END_OF_REPLAY), func() {
		if len(batches) != 4 {
			t.Errorf("replay completion overtook its deliveries: %v", batches)
		}
	})
	for seq := uint64(5); seq <= 26; seq++ {
		w.submitLiveRoute(liveTestRoute(seq))
	}
	w.submitBarrier(func() {
		if len(batches) != 6 {
			t.Errorf("barrier overtook live groups: %v", batches)
		}
	})
	w.submit(marker(27, v1.PluginEventKind_PLUGIN_EVENT_KIND_LOCAL_SID))
	w.submitLiveRoute(liveTestRoute(28))
	release()
	batchWorkerIdle(t, w)
	want := [][]uint64{{1}, {2}, {3}, {4}, {}, {}, {27}, {28}}
	for seq := uint64(5); seq <= 26; seq++ {
		i := 4 + int((seq-5)/16)
		want[i] = append(want[i], seq)
	}
	if !reflect.DeepEqual(batches, want) {
		t.Fatalf("order/group boundaries: got %v, want %v", batches, want)
	}
	for i, seq := range quarantined {
		if seq != uint64(i+1) {
			t.Fatalf("per-event status sequence lost: %v", quarantined)
		}
	}
	if len(quarantined) != 28 {
		t.Fatal("missing event status")
	}
}

func TestLiveBatchDefaultAndHeldEligibility(t *testing.T) {
	for _, limit := range []int{0, 1, 2, 16} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			var widths []int
			w, release := pausedBatchWorker(t, limit, func(_ context.Context, raw []byte) ([]byte, error) {
				var b v1.PluginEventBatch
				if err := proto.Unmarshal(raw, &b); err != nil {
					return nil, err
				}
				widths = append(widths, len(b.Events))
				return nil, nil
			}, func(err error) { t.Errorf("handler: %v", err) }, func(*v1.PluginEventStatus) {})
			w.beginSnapshot()
			for seq := uint64(1); seq <= 5; seq++ {
				w.submitLiveRoute(liveTestRoute(seq))
			}
			w.endSnapshot()
			release()
			batchWorkerIdle(t, w)
			want := []int{1, 1, 1, 1, 1}
			if limit == 2 {
				want = []int{2, 2, 1}
			} else if limit > 1 {
				want = []int{5}
			}
			if !reflect.DeepEqual(widths, want) {
				t.Fatalf("held group sizes %v, want %v", widths, want)
			}
		})
	}
}

func TestLiveBatchDoesNotWaitForAnotherArrival(t *testing.T) {
	seen := make(chan struct{})
	w, release := pausedBatchWorker(t, 16, func(context.Context, []byte) ([]byte, error) {
		close(seen)
		return nil, nil
	}, func(err error) { t.Errorf("handler: %v", err) }, func(*v1.PluginEventStatus) {})
	w.submitLiveRoute(liveTestRoute(1))
	release()
	select {
	case <-seen:
	case <-time.After(time.Second):
		t.Fatal("isolated update waited for a batch to fill")
	}
	batchWorkerIdle(t, w)
}

func TestLiveBatchKeepsIneligibleLookaheadAheadOfQueue(t *testing.T) {
	for _, kind := range []string{"snapshot", "completion", "unknown-fields", "mixed-events", "missing-route"} {
		t.Run(kind, func(t *testing.T) {
			next := delivery{batch: liveTestRoute(2), live: true}
			switch kind {
			case "snapshot":
				next.live = false
			case "completion":
				next.complete = func() {}
			case "unknown-fields":
				next.batch.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 1})
			case "mixed-events":
				next.batch.Events = append(next.batch.Events, &v1.PluginEvent{Kind: v1.PluginEventKind_PLUGIN_EVENT_KIND_MAC})
			case "missing-route":
				next.batch.Events[0].Route = nil
			}
			w := &worker{queue: make(chan delivery, 2), maxBatchEvents: 16, maxBatchBytes: 4 << 20}
			w.queue <- next
			w.queue <- delivery{batch: liveTestRoute(3), live: true}
			out, count, carry := w.coalesce(delivery{batch: liveTestRoute(1), live: true})
			if count != 1 || len(out.batch.Events) != 1 || carry == nil || carry.batch != next.batch ||
				(<-w.queue).batch.Events[0].Sequence != 3 {
				t.Fatal("ineligible lookahead was merged or moved behind a newer route")
			}
		})
	}
}

func TestLiveBatchFailureAccountsOriginalsOnce(t *testing.T) {
	var failed, statuses, calls int
	w, release := pausedBatchWorker(t, 16, func(context.Context, []byte) ([]byte, error) {
		calls++
		return nil, errors.New("guest failed")
	}, func(error) { failed++ }, func(*v1.PluginEventStatus) { statuses++ })
	for seq := uint64(1); seq <= 16; seq++ {
		w.submitLiveRoute(liveTestRoute(seq))
	}
	completed := false
	w.submitBarrier(func() { completed = true })
	release()
	batchWorkerIdle(t, w)
	if calls != 1 || failed != 1 || statuses != 0 || !completed {
		t.Fatalf("calls=%d failures=%d statuses=%d barrier=%t", calls, failed, statuses, completed)
	}
}

func TestLiveBatchBoundsAuthorizedContextsAndPreservesCarry(t *testing.T) {
	spec := compositionPolicy()
	spec.Contexts = nil
	for i := 0; i < 64; i++ {
		c := proto.Clone(compositionPolicy().Contexts[0]).(*v1.CplaneInputContext)
		c.Name = fmt.Sprintf("%02d", i) + strings.Repeat("x", 61)
		spec.Contexts = append(spec.Contexts, c)
	}
	policy, err := parseInputPolicy(spec, nil)
	if err != nil {
		t.Fatal(err)
	}
	contexts := &v1.PluginRoute{}
	for _, c := range spec.Contexts {
		contexts.Contexts = append(contexts.Contexts, c.Name)
	}
	for _, payload := range []int{0, 127, 16383} {
		t.Run(fmt.Sprint(payload), func(t *testing.T) {
			w := &worker{queue: make(chan delivery, 16), maxBatchEvents: 16, maxBatchBytes: 20000, contextBytes: proto.Size(contexts)}
			var first delivery
			for i := 0; i < 5; i++ {
				route := inputRoute(t, "65000:7")
				route.NextHop = strings.Repeat("x", payload)
				b := inputBatch(route)
				b.Events[0].Sequence = uint64(i + 1)
				d := delivery{batch: b, live: true}
				if i == 0 {
					first = d
				} else {
					w.queue <- d
				}
			}
			original := proto.Clone(first.batch)
			out, count, carry := w.coalesce(first)
			if !proto.Equal(first.batch, original) || count < 1 || count > 5 {
				t.Fatal("coalescing mutated source or lost count")
			}
			d := &inputDelivery{policy: policy}
			prepared, err := d.prepare(out.batch)
			if err != nil {
				t.Fatal(err)
			}
			if count > 1 && proto.Size(prepared) > w.maxBatchBytes {
				t.Fatalf("authorized group exceeds cap: %d", proto.Size(prepared))
			}
			if count < 5 && (carry == nil || carry.batch.Events[0].Sequence != uint64(count+1)) {
				// An individually oversized event stays on its original path;
				// in that case no lookahead is consumed at all.
				if count != 1 || carry != nil || len(w.queue) != 4 {
					t.Fatal("byte-bound lookahead lost or reordered an event")
				}
			}
		})
	}
}

func TestLiveBatchMalformedGroupFailsClosedAndReplayRecovers(t *testing.T) {
	src := &compositionSource{newFakeSource()}
	rib := mupFixture(t)
	src.setRib(rib...)
	maps := newServiceFake()
	m, err := NewManager(ManagerConfig{AllowNative: true, Source: src, Headend: maps, ForwardingMaps: maps,
		ResolveMUPInstance: func(string) (uint32, error) { return 7, nil },
		ResolveInputTarget: func(bgp.RouteEvent) (string, uint16, bool) { return "", 0, true }})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close(context.Background())
	reg := compositionBackendRegistration(t, BackendNative)
	reg.Name = "batch-malformed"
	reg.Input = compositionPolicy()
	reg.Input.MaxBatchEvents = 16
	reg.Input.Contexts[0].DelegateEvpn = false
	reg.Input.Contexts[0].BridgeDomain = 0
	reg.Scope, _ = ParseScope(ScopeSpec{HeadendPrefixes: []string{"10.0.0.0/8", "192.0.2.0/24"}})
	reg.Capabilities, _ = wasm.ParseCapabilities([]string{"headend", "mup"})
	reg.Config = []byte(`{"context":"mobile","source":"fd00:feed::1","args_offset":7,"observe_only":false}`)
	if err := m.Register(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	if !m.WaitIdle(reg.Name, 5*time.Second) {
		t.Fatal("initial replay did not finish")
	}
	initial := *maps.v4["10.0.0.1/32"]
	p := m.plugins[reg.Name]
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unpause := func() { once.Do(func() { close(release) }) }
	defer unpause()
	calls := 0
	p.worker.submitBarrier(func() {
		handler := p.worker.handler
		p.worker.handler = func(ctx context.Context, raw []byte) ([]byte, error) { calls++; return handler(ctx, raw) }
		close(entered)
		<-release
	})
	<-entered
	updates := mupFixtureWithTEID(t, 512)
	for _, i := range []int{0, 2} {
		updates[i].BGPPath.RouteKey = rib[i].BGPPath.RouteKey
	}
	bad := rib[1]
	path := *bad.BGPPath
	path.NLRI = []byte{255}
	bad.BGPPath = &path
	for _, ev := range []bgp.RouteEvent{updates[0], bad, updates[2]} {
		if !src.emit(reg.Name, ev) {
			t.Fatal("missing subscription")
		}
	}
	unpause()
	if !m.WaitIdle(reg.Name, 5*time.Second) {
		t.Fatal("malformed group did not finish")
	}
	st, _ := m.StatsFor(reg.Name)
	if calls != 0 || st.InputReady || st.InputFault == "" || len(maps.v4) != 0 || len(maps.uplinks) != 0 {
		t.Fatalf("malformed group was not rejected as a unit: calls=%d stats=%+v", calls, st)
	}
	rib[0], rib[2] = updates[0], updates[2]
	src.setRib(rib...)
	m.snapshot(p)
	if !m.WaitIdle(reg.Name, 5*time.Second) {
		t.Fatal("corrected replay did not finish")
	}
	st, _ = m.StatsFor(reg.Name)
	current := maps.v4["10.0.0.1/32"]
	if !st.InputReady || st.InputFault != "" || st.DesiredRevision != st.AppliedRevision || current == nil || *current == initial ||
		len(maps.uplinks) != 1 || maps.uplinks[serviceKey(7, "192.0.2.1", 512, 32)] == "" {
		t.Fatalf("corrected full replay did not rebuild desired state: %+v", st)
	}
	// Replacing, withdrawing and replacing the same key in one group must
	// match a full replay containing only its final value.
	entered2, release2 := make(chan struct{}), make(chan struct{})
	var once2 sync.Once
	unpause2 := func() { once2.Do(func() { close(release2) }) }
	defer unpause2()
	width := 0
	p.worker.submitBarrier(func() {
		handler := p.worker.handler
		p.worker.handler = func(ctx context.Context, raw []byte) ([]byte, error) {
			var b v1.PluginEventBatch
			if err := proto.Unmarshal(raw, &b); err != nil {
				return nil, err
			}
			width = len(b.Events)
			return handler(ctx, raw)
		}
		close(entered2)
		<-release2
	})
	<-entered2
	first, last := mupFixtureWithTEID(t, 768)[0], mupFixtureWithTEID(t, 1024)[0]
	first.BGPPath.RouteKey, last.BGPPath.RouteKey = rib[0].BGPPath.RouteKey, rib[0].BGPPath.RouteKey
	withdrawal := first
	withdrawal.IsWithdraw = true
	for _, ev := range []bgp.RouteEvent{first, withdrawal, last} {
		if !src.emit(reg.Name, ev) {
			t.Fatal("missing subscription during same-key updates")
		}
	}
	unpause2()
	if !m.WaitIdle(reg.Name, 5*time.Second) || width != 3 {
		t.Fatalf("same-key updates were not delivered as one group: width=%d", width)
	}
	observed := maps.snapshotV4()
	rib[0] = last
	src.setRib(rib...)
	m.snapshot(p)
	if !m.WaitIdle(reg.Name, 5*time.Second) || !reflect.DeepEqual(observed, maps.snapshotV4()) {
		t.Fatal("same-key group differs from a full replay of its latest value")
	}
}
