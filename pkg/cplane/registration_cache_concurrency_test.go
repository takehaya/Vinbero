package cplane

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/tetratelabs/wazero"
)

func TestCompilationCacheLeaseConcurrentRetainRelease(t *testing.T) {
	ctx := context.Background()
	observed := &observedCacheClose{CompilationCache: wazero.NewCompilationCache()}
	guard := &compilationCacheLease{owner: &compilationCacheOwner{cache: observed, refs: 1}}
	const consumers = 32
	leases := make([]*compilationCacheLease, consumers)
	for i := range leases {
		leases[i] = guard.retain()
		if leases[i] == nil {
			t.Fatal("live cache refused a lease")
		}
	}
	start := make(chan struct{})
	var done sync.WaitGroup
	for _, lease := range leases {
		done.Add(2)
		go func() {
			defer done.Done()
			<-start
			child := lease.retain()
			if child == nil {
				// The concurrent release is allowed to win the handoff.
				return
			}
			for range 2 {
				if err := child.release(ctx); err != nil {
					t.Error(err)
				}
			}
			if child.retain() != nil {
				t.Error("released child created a new consumer")
			}
		}()
		go func() {
			defer done.Done()
			<-start
			for range 2 {
				if err := lease.release(ctx); err != nil {
					t.Error(err)
				}
			}
			if lease.retain() != nil {
				t.Error("released lease created a new consumer")
			}
		}()
	}
	close(start)
	done.Wait()
	if observed.calls.Load() != 0 {
		t.Fatal("parallel consumers closed the cache while its guard remained")
	}
	if err := guard.release(ctx); err != nil {
		t.Fatal(err)
	}
	if err := guard.release(ctx); err != nil {
		t.Fatal(err)
	}
	guard.owner.mu.Lock()
	refs := guard.owner.refs
	guard.owner.mu.Unlock()
	if refs != 0 || observed.calls.Load() != 1 || guard.retain() != nil {
		t.Fatalf("final release: refs=%d close calls=%d", refs, observed.calls.Load())
	}
}

type registrationCacheGateSource struct {
	*fakeSource
	calls   atomic.Int32
	entered chan struct{}
	resume  chan struct{}
}

func (s *registrationCacheGateSource) RegisterQuiet(name string, families []bgp.Family, handler bgp.RouteHandler) (func(), error) {
	if s.calls.Add(1) == 2 {
		close(s.entered)
		<-s.resume
	}
	return s.fakeSource.RegisterQuiet(name, families, handler)
}

func TestCompilationCacheCloseSerializesWithCandidateRegistration(t *testing.T) {
	ctx := context.Background()
	source := &registrationCacheGateSource{fakeSource: newFakeSource(), entered: make(chan struct{}), resume: make(chan struct{})}
	var resume sync.Once
	defer resume.Do(func() { close(source.resume) })
	m, _ := newTestManager(t, source, newFakeClaims())
	reg := Registration{Name: "cache-register-close", Module: fixtureModule(t, "echo")}
	if err := m.Register(ctx, reg); err != nil {
		t.Fatal(err)
	}
	waitDelivered(t, m, reg.Name)
	p := m.plugins[reg.Name]
	observed := &observedCacheClose{CompilationCache: p.compilationCache}
	p.cacheLease.owner.cache = observed
	registered := make(chan error, 1)
	go func() { registered <- m.Register(ctx, reg) }()
	waitCacheSignal(t, "candidate subscription", source.entered)
	closed, closeStarted := make(chan error, 1), make(chan struct{})
	go func() { close(closeStarted); m.Close(ctx); closed <- nil }()
	waitCacheSignal(t, "Close start", closeStarted)
	select {
	case <-closed:
		t.Fatal("Close passed a registration blocked in subscription")
	case <-time.After(20 * time.Millisecond):
	}
	m.mu.Lock()
	closing := m.closed
	m.mu.Unlock()
	if closing || observed.calls.Load() != 0 {
		t.Fatal("Close invalidated a candidate before Register finished")
	}
	resume.Do(func() { close(source.resume) })
	if err := waitCacheResult(t, registered); err != nil {
		t.Fatal(err)
	}
	if err := waitCacheResult(t, closed); err != nil {
		t.Fatal(err)
	}
	if observed.calls.Load() != 1 || len(m.List()) != 0 {
		t.Fatal("Close did not drain the registered generation and its cache")
	}
	if err := m.Register(ctx, reg); !errors.Is(err, errManagerClosed) {
		t.Fatalf("registration after Close: %v", err)
	}
}

type cacheRestartPausedClose struct {
	pluginInstance
	entered chan struct{}
	resume  chan struct{}
	once    sync.Once
}

func (p *cacheRestartPausedClose) Close(ctx context.Context) error {
	p.once.Do(func() { close(p.entered); <-p.resume })
	return p.pluginInstance.Close(ctx)
}

func TestCompilationCacheRestartOverlapsRetirement(t *testing.T) {
	for _, action := range []string{"replacement", "manager Close"} {
		t.Run(action, func(t *testing.T) {
			ctx := context.Background()
			source := newFakeSource()
			m, _ := newTestManager(t, source, newFakeClaims())
			reg := Registration{Name: "cache-restart-retire", Module: fixtureModule(t, "echo")}
			if err := m.Register(ctx, reg); err != nil {
				t.Fatal(err)
			}
			waitDelivered(t, m, reg.Name)
			p := m.plugins[reg.Name]
			original := p.inst
			paused := &cacheRestartPausedClose{pluginInstance: original, entered: make(chan struct{}), resume: make(chan struct{})}
			var resume sync.Once
			defer resume.Do(func() { close(paused.resume) })
			// The worker installs a new runtime, then blocks closing the old one.
			m.mu.Lock()
			p.inst = paused
			m.mu.Unlock()
			var runtimesMu sync.Mutex
			runtimes := []pluginInstance{original}
			observed := &observedCacheClose{CompilationCache: p.compilationCache, before: func() {
				select {
				case <-p.worker.done:
				default:
					t.Error("cache closed before restarting worker stopped")
				}
				runtimesMu.Lock()
				defer runtimesMu.Unlock()
				for _, instance := range runtimes {
					if _, err := instance.HandleEvents(ctx, nil); err == nil {
						t.Error("cache closed while an associated runtime was alive")
					}
				}
			}}
			p.cacheLease.owner.cache = observed
			installed := make(chan struct{})
			p.worker.submitBarrier(func() {
				p.worker.handler = func(context.Context, []byte) ([]byte, error) { return nil, errors.New("restart under retirement") }
				close(installed)
			})
			waitCacheSignal(t, "failing handler installation", installed)
			if !source.emit(reg.Name, bgp.RouteEvent{Family: bgp.FamilyVPNv4}) {
				t.Fatal("missing subscription")
			}
			waitCacheSignal(t, "restart runtime handoff", paused.entered)
			m.mu.Lock()
			restarted := p.inst
			m.mu.Unlock()
			if restarted == paused {
				t.Fatal("worker did not install its restarted runtime")
			}
			runtimesMu.Lock()
			runtimes = append(runtimes, restarted)
			runtimesMu.Unlock()
			retired := make(chan error, 1)
			var lateRegistration chan error
			if action == "replacement" {
				go func() { retired <- m.Register(ctx, reg) }()
				waitCacheCondition(t, func() bool {
					m.mu.Lock()
					defer m.mu.Unlock()
					return m.plugins[reg.Name] != p
				})
				m.mu.Lock()
				candidate := m.plugins[reg.Name]
				m.mu.Unlock()
				if candidate.compilationCache != p.compilationCache {
					t.Fatal("compatible candidate did not borrow the active cache")
				}
				runtimesMu.Lock()
				runtimes = append(runtimes, candidate.inst)
				runtimesMu.Unlock()
			} else {
				go func() { m.Close(ctx); retired <- nil }()
				waitCacheCondition(t, func() bool {
					m.mu.Lock()
					defer m.mu.Unlock()
					return m.closed && len(m.plugins) == 0
				})
				lateRegistration = make(chan error, 1)
				go func() { lateRegistration <- m.Register(ctx, reg) }()
			}
			select {
			case err := <-retired:
				t.Fatalf("retirement passed an in-flight restart: %v", err)
			default:
			}
			if observed.calls.Load() != 0 {
				t.Fatal("in-flight restart lost its compilation cache")
			}
			resume.Do(func() { close(paused.resume) })
			if err := waitCacheResult(t, retired); err != nil {
				t.Fatal(err)
			}
			if action == "replacement" {
				waitDelivered(t, m, reg.Name)
				if observed.calls.Load() != 0 || p.cacheLease.retain() != nil {
					t.Fatal("retired generation closed a borrowed cache or retained again")
				}
				m.Close(ctx)
			} else if err := waitCacheResult(t, lateRegistration); !errors.Is(err, errManagerClosed) {
				t.Fatalf("registration queued behind Close: %v", err)
			}
			if observed.calls.Load() != 1 {
				t.Fatalf("cache final Close count=%d", observed.calls.Load())
			}
		})
	}
}

func waitCacheSignal(t *testing.T, label string, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", label)
	}
}

func waitCacheResult(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for cache lifecycle operation")
		return nil
	}
}

func waitCacheCondition(t *testing.T, ready func() bool) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for !ready() {
		select {
		case <-deadline:
			t.Fatal("cache lifecycle state did not become observable")
		case <-tick.C:
		}
	}
}
