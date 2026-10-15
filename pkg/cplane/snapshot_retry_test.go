package cplane

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
	"go.uber.org/zap"
)

func snapshotRetryManager(t *testing.T) (*Manager, *plugin) {
	t.Helper()
	ops, err := NewPluginOps(PluginOpsConfig{Owner: ownerA, Headend: newFakeHeadendOps()})
	if err != nil {
		t.Fatal(err)
	}
	w := newWorker("retry", zap.NewNop(),
		func(context.Context, []byte) ([]byte, error) { return nil, nil },
		func(err error) { t.Error(err) }, func(*v1.PluginEventStatus) {}, nil, 0, nil)
	p := &plugin{name: "retry", worker: w, ops: ops, counters: newCounters()}
	m := &Manager{plugins: map[string]*plugin{p.name: p}, logger: zap.NewNop()}
	t.Cleanup(func() {
		m.mu.Lock()
		delete(m.plugins, p.name)
		m.mu.Unlock()
		w.close()
	})
	return m, p
}

func TestSnapshotRetryBackoffAndRecovery(t *testing.T) {
	m, p := snapshotRetryManager(t)
	attempts := make(chan time.Time, 16)
	var calls atomic.Int64
	m.snapshots = snapshotFunc(func([]bgp.Family, bgp.RouteHandler) error {
		attempts <- time.Now()
		if calls.Add(1) < 3 {
			return bgp.ErrSessionNotStarted
		}
		return nil
	})
	m.snapshot(p)
	// Even an explicit request while retry is pending must respect the deadline.
	go m.snapshot(p)
	// Exercise the watch callback too: live traffic and queue overflow must
	// not turn a pending retry into an immediate source read.
	handler := m.handlerFor(p.name)
	for n := 0; n < deliveryQueueDepth*4; n++ {
		handler(bgp.RouteEvent{Family: bgp.FamilyVPNv4})
	}
	var previous time.Time
	for n := 0; n < 3; n++ {
		select {
		case now := <-attempts:
			if n > 0 && now.Sub(previous) < snapshotRetryMin*time.Duration(1<<(n-1)) {
				t.Fatalf("retry %d ran after %s", n, now.Sub(previous))
			}
			previous = now
		case <-time.After(3 * time.Second):
			t.Fatal("snapshot did not retry and recover")
		}
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		settled := !p.snapshotting && p.snapshotBackoff == 0 && p.snapshotRetryAt.IsZero()
		m.mu.Unlock()
		if settled && p.worker.caughtUp() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("successful snapshot did not clear retry state")
}

func TestSnapshotRetryStopsWithWorker(t *testing.T) {
	m, p := snapshotRetryManager(t)
	var calls atomic.Int64
	m.snapshots = snapshotFunc(func([]bgp.Family, bgp.RouteHandler) error {
		calls.Add(1)
		return bgp.ErrSessionNotStarted
	})
	m.snapshot(p)
	p.worker.close()
	time.Sleep(2 * snapshotRetryMin)
	if got := calls.Load(); got != 1 {
		t.Fatalf("closed worker retried snapshot %d times", got)
	}
	m.mu.Lock()
	running := p.snapshotting
	m.mu.Unlock()
	if running {
		t.Fatal("closed worker retained a pending snapshot")
	}
}

func TestSnapshotRetryDelayIsCapped(t *testing.T) {
	m, p := snapshotRetryManager(t)
	// A subsequent failure would double this past the configured ceiling.
	p.snapshotBackoff = snapshotRetryMax * 3 / 4
	m.snapshots = snapshotFunc(func([]bgp.Family, bgp.RouteHandler) error { return bgp.ErrSessionNotStarted })
	start := time.Now()
	m.snapshot(p)
	end := time.Now()
	m.mu.Lock()
	retryAt, backoff := p.snapshotRetryAt, p.snapshotBackoff
	m.mu.Unlock()
	if backoff != snapshotRetryMax || retryAt.Before(start.Add(snapshotRetryMax)) || retryAt.After(end.Add(snapshotRetryMax)) {
		t.Fatalf("next retry %v, delay %v: expected capped delay %v", retryAt, backoff, snapshotRetryMax)
	}
}
