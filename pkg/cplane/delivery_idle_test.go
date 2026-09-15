package cplane

import (
	"context"
	"slices"
	"testing"
	"time"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
	"go.uber.org/zap"
)

func TestDeliveryIdleWaitsForPublicationBarrier(t *testing.T) {
	w := newWorker("idle", zap.NewNop(),
		func(context.Context, []byte) ([]byte, error) { return nil, nil },
		func(error) {}, func(*v1.PluginEventStatus) {}, nil, 0, nil)
	defer w.close()
	w.beginSnapshot()
	if w.idle() {
		t.Fatal("empty but held replay reported idle")
	}
	w.endSnapshot()
	entered, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	w.submitBarrier(func() {
		close(entered)
		<-release
	})
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("publication barrier did not run")
	}
	if w.idle() {
		t.Fatal("publication barrier still running, but delivery reported idle")
	}
}

func TestDeliveryIdleRejectsReplayDebtAndReportsSubscription(t *testing.T) {
	m, _ := newTestManager(t, newFakeSource(), newFakeClaims())
	reg := Registration{Name: "idle-stats", Module: declareModule(t),
		Capabilities: testCaps(), Scope: testScope(), Families: []bgp.Family{bgp.FamilyVPNv6}}
	if err := m.Register(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	waitDelivered(t, m, reg.Name)
	st, ok := m.StatsFor(reg.Name)
	if !ok || !st.DeliveryIdle || !slices.Equal(st.Families, []string{"vpnv6"}) {
		t.Fatalf("wrong completed state: %+v", st)
	}
	m.mu.Lock()
	p := m.plugins[reg.Name]
	p.worker.owe()
	m.mu.Unlock()
	st, _ = m.StatsFor(reg.Name)
	if st.DeliveryIdle {
		t.Fatal("replay debt was reported as idle")
	}
	// No event callback runs in this fixture now, so consuming the debt here
	// lets the remaining manager-level conditions be checked independently.
	p.worker.takeSnapshotDebt()
	m.mu.Lock()
	p.snapshotting = true
	m.mu.Unlock()
	st, _ = m.StatsFor(reg.Name)
	if st.DeliveryIdle {
		t.Fatal("snapshot producer still running, but reported idle")
	}
	m.mu.Lock()
	p.snapshotting = false
	p.dead = true
	m.mu.Unlock()
	st, _ = m.StatsFor(reg.Name)
	if st.DeliveryIdle {
		t.Fatal("dead plugin reported idle")
	}
}
