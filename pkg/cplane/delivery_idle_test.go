package cplane

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/cplane/native"
	"github.com/takehaya/vinbero/pkg/cplane/wasm"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/protobuf/reflect/protoreflect"
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

func TestDeliveryIdleTracksAsynchronousReplayBeforeAndAfterItsProducer(t *testing.T) {
	m, _ := newTestManager(t, newFakeSource(), newFakeClaims())
	reg := Registration{Name: "queued-replay", Module: declareModule(t),
		Capabilities: testCaps(), Scope: testScope()}
	if err := m.Register(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	waitDelivered(t, m, reg.Name)
	produced, release := make(chan struct{}), make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	m.mu.Lock()
	p := m.plugins[reg.Name]
	m.launchSnapshotLocked(p, func() {
		close(produced)
		<-release
	})
	// The replay goroutine cannot acquire m.mu yet. Pending work must
	// already be visible even though its producer has not started.
	pending, producing, workerIdle := p.pendingSnapshots, p.snapshotting, p.worker.idle()
	m.mu.Unlock()
	if pending != 1 || producing || !workerIdle {
		t.Fatalf("pending=%d producing=%v workerIdle=%v before producer start", pending, producing, workerIdle)
	}
	select {
	case <-produced:
	case <-time.After(5 * time.Second):
		t.Fatal("replay producer did not finish")
	}
	waitDelivered(t, m, reg.Name)
	st, _ := m.StatsFor(reg.Name)
	if st.DeliveryIdle {
		t.Fatal("asynchronous replay completion still pending, but delivery reported idle")
	}
	close(release)
	released = true
	deadline := time.Now().Add(5 * time.Second)
	for {
		st, _ = m.StatsFor(reg.Name)
		if st.DeliveryIdle {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("finished asynchronous replay did not become idle")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestDeliveryIdleTracksInputRecoveryBeforeProducerStarts(t *testing.T) {
	m, _ := newTestManager(t, newFakeSource(), newFakeClaims())
	reg := Registration{Name: "input-recovery-idle", Module: declareModule(t), Capabilities: testCaps(), Scope: testScope()}
	if err := m.Register(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	waitDelivered(t, m, reg.Name)
	m.mu.Lock()
	p := m.plugins[reg.Name]
	p.ops.mu.Lock()
	p.ops.inputRecoveryReplay = true
	p.ops.inputCleanupPending = true
	p.ops.mu.Unlock()
	m.mu.Unlock()
	st, _ := m.StatsFor(reg.Name)
	if st.DeliveryIdle {
		t.Fatal("cleanup still owes a replay, but delivery reported idle")
	}
	m.mu.Lock()
	m.repayInputRecoveryLocked(p)
	if p.pendingSnapshots != 0 {
		m.mu.Unlock()
		t.Fatal("replay started before cleanup completed")
	}
	p.ops.mu.Lock()
	pending := p.ops.inputRecoveryReplay
	p.ops.inputCleanupPending = false
	p.ops.mu.Unlock()
	m.repayInputRecoveryLocked(p)
	queued, producing := p.pendingSnapshots, p.snapshotting
	p.ops.mu.Lock()
	consumed := !p.ops.inputRecoveryReplay
	p.ops.mu.Unlock()
	// The producer cannot acquire m.mu until this observation is complete.
	m.mu.Unlock()
	if !pending || !consumed || queued != 1 || producing {
		t.Fatalf("pending=%v consumed=%v queued=%d producing=%v", pending, consumed, queued, producing)
	}
	waitDelivered(t, m, reg.Name)
}

func TestDeliveryIdleReplacementWaitsForRegistrationReplay(t *testing.T) {
	m, _ := newTestManager(t, newFakeSource(), newFakeClaims())
	m.allowNative = true
	reg := Registration{Name: "replacement-idle", Backend: BackendNative, NativeID: native.BGPObserver, NativeVersion: native.ImplementationVersion}
	if err := m.Register(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	waitDelivered(t, m, reg.Name)
	m.mu.Lock()
	old := m.plugins[reg.Name]
	m.mu.Unlock()
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	old.worker.submitBarrier(func() { close(entered); <-release })
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("old worker did not enter barrier")
	}
	result := make(chan error, 1)
	go func() { result <- m.Register(context.Background(), reg) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		m.mu.Lock()
		current := m.plugins[reg.Name]
		pending := current.pendingSnapshots
		m.mu.Unlock()
		if current != old {
			st, _ := m.StatsFor(reg.Name)
			if pending == 0 || st.DeliveryIdle {
				t.Fatalf("replacement awaiting old worker close reported idle: pending=%d stats=%+v", pending, st)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("replacement not made visible")
		}
		time.Sleep(time.Millisecond)
	}
	once.Do(func() { close(release) })
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("registration did not finish")
	}
	waitDelivered(t, m, reg.Name)
	st, _ := m.StatsFor(reg.Name)
	if !st.DeliveryIdle {
		t.Fatalf("replacement never settled: %+v", st)
	}
}

func TestDeliveryStatsWireFieldsRemainCompatible(t *testing.T) {
	fields := (&v1.CplanePluginStat{}).ProtoReflect().Descriptor().Fields()
	for name, number := range map[protoreflect.Name]protoreflect.FieldNumber{
		"scope": 17, "input": 18, "input_ready": 19, "input_fault": 20,
		"cleanup_pending": 21, "desired_revision": 22, "applied_revision": 23,
		"output_failure": 24, "backend": 25, "native_id": 26,
		"native_version": 27, "native_identity": 28, "families": 29, "delivery_idle": 30,
	} {
		field := fields.ByName(name)
		if field == nil || field.Number() != number {
			t.Fatalf("wire field %s: got %v, want %d", name, field, number)
		}
	}
}

// Tick failure has no accepted delivery keeping submitted != processed.
type idleFailingTick struct {
	pluginInstance
	beforeClose func()
}

func (i *idleFailingTick) Tick(context.Context, int64) error {
	return errors.New("injected tick failure")
}
func (i *idleFailingTick) Close(ctx context.Context) error {
	i.beforeClose()
	return i.pluginInstance.Close(ctx)
}

func TestDeliveryIdleWaitsForTickRestartConfigureAndClose(t *testing.T) {
	m, _ := newTestManager(t, newFakeSource(), newFakeClaims())
	m.allowNative = true
	configureEntered, configureRelease := make(chan struct{}), make(chan struct{})
	closeEntered, closeRelease := make(chan struct{}), make(chan struct{})
	var armed atomic.Bool
	var configureOnce, closeOnce sync.Once
	defer configureOnce.Do(func() { close(configureRelease) })
	defer closeOnce.Do(func() { close(closeRelease) })
	core, _ := observer.New(zap.InfoLevel)
	m.logger = zap.New(core, zap.Hooks(func(e zapcore.Entry) error {
		if e.Message == "local SID unavailable; running without local SID writes" && armed.CompareAndSwap(true, false) {
			close(configureEntered)
			<-configureRelease
		}
		return nil
	}))
	reg := Registration{Name: "tick-restart-idle", Backend: BackendNative,
		NativeID: native.CustomBehavior, NativeVersion: native.ImplementationVersion,
		Capabilities: wasm.Capabilities{wasm.CapHeadend: {}}, Scope: testScope(),
		// This asks for locator main/slot 1 without SID permission. The
		// shared constructor logs the refusal inside Instantiate, where we pause it.
		Config: []byte{0x12, 4, 'm', 'a', 'i', 'n', 0x28, 1}}
	if err := m.Register(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	waitDelivered(t, m, reg.Name)
	m.mu.Lock()
	p := m.plugins[reg.Name]
	p.inst = &idleFailingTick{pluginInstance: p.inst, beforeClose: func() {
		close(closeEntered)
		<-closeRelease
	}}
	m.mu.Unlock()
	armed.Store(true)
	finished := make(chan struct{})
	go func() {
		if err := m.tick(p); err != nil {
			m.instanceFailed(p, err)
		}
		close(finished)
	}()
	for _, stage := range []struct {
		name    string
		entered <-chan struct{}
		release chan struct{}
		once    *sync.Once
	}{{"configure", configureEntered, configureRelease, &configureOnce}, {"old close", closeEntered, closeRelease, &closeOnce}} {
		select {
		case <-stage.entered:
		case <-time.After(5 * time.Second):
			t.Fatalf("restart did not reach %s", stage.name)
		}
		st, _ := m.StatsFor(reg.Name)
		if st.DeliveryIdle || !p.worker.idle() || p.reg.Input != nil {
			t.Errorf("%s: idle=%v worker idle=%v input=%v", stage.name, st.DeliveryIdle, p.worker.idle(), p.reg.Input)
		}
		stage.once.Do(func() { close(stage.release) })
	}
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("restart did not finish")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		st, _ := m.StatsFor(reg.Name)
		if st.DeliveryIdle {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("restart pending reservation leaked")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestDeliveryIdleRestartFailureReleasesReservation(t *testing.T) {
	for _, failure := range []string{"admission", "restart limit"} {
		t.Run(failure, func(t *testing.T) {
			m, _ := newTestManager(t, newFakeSource(), newFakeClaims())
			m.allowNative = true
			reg := Registration{Name: "failed-restart", Backend: BackendNative, NativeID: native.BGPObserver, NativeVersion: native.ImplementationVersion}
			if err := m.Register(context.Background(), reg); err != nil {
				t.Fatal(err)
			}
			waitDelivered(t, m, reg.Name)
			m.mu.Lock()
			p := m.plugins[reg.Name]
			if failure == "admission" {
				p.reg.NativeVersion = "invalid"
			} else {
				p.restarts = maxRestarts
			}
			m.mu.Unlock()
			m.instanceFailed(p, errors.New("injected failure"))
			m.mu.Lock()
			pending, dead := p.pendingSnapshots, p.dead
			m.mu.Unlock()
			st, _ := m.StatsFor(reg.Name)
			if pending != 0 || !dead || st.DeliveryIdle {
				t.Fatalf("pending=%d dead=%v idle=%v", pending, dead, st.DeliveryIdle)
			}
		})
	}
}
