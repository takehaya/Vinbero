package cplane

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/tetratelabs/wazero"
)

// This wrapper is used only to observe owner Close, never passed to wazero's
// RuntimeConfig (which intentionally accepts only wazero's own cache type).
type observedCacheClose struct {
	wazero.CompilationCache
	calls  atomic.Int32
	before func()
}

func (c *observedCacheClose) Close(ctx context.Context) error {
	c.calls.Add(1)
	if c.before != nil {
		c.before()
	}
	return c.CompilationCache.Close(ctx)
}

func TestRestartCacheOwnsModuleBytesAndEndsWithRegistration(t *testing.T) {
	ctx := context.Background()
	src := newFakeSource()
	m, _ := newTestManager(t, src, newFakeClaims())
	reg := Registration{Name: "cached-restart", Module: fixtureModule(t, "echo"), Config: []byte("immutable config")}
	originalModule, originalConfig := bytes.Clone(reg.Module), bytes.Clone(reg.Config)
	if err := m.Register(ctx, reg); err != nil {
		t.Fatal(err)
	}
	if !m.WaitIdle(reg.Name, 5*time.Second) {
		t.Fatal("initial replay not idle")
	}
	m.mu.Lock()
	p := m.plugins[reg.Name]
	first, cache := p.inst, p.compilationCache
	m.mu.Unlock()
	if cache == nil {
		t.Fatal("WASM registration has no owned compilation cache")
	}
	// Changing the caller's slices after Register must not change a restart
	// or add another module to this generation's compilation cache.
	reg.Module[0] = 0xff
	reg.Config[0] = '!'
	if !bytes.Equal(p.reg.Module, originalModule) || !bytes.Equal(p.config, originalConfig) {
		t.Fatal("registration retained mutable caller storage")
	}
	installed := make(chan struct{})
	p.worker.submitBarrier(func() {
		p.worker.handler = func(context.Context, []byte) ([]byte, error) { return nil, errors.New("injected restart") }
		close(installed)
	})
	<-installed
	if !src.emit(reg.Name, bgp.RouteEvent{Family: bgp.FamilyVPNv4}) {
		t.Fatal("missing subscription")
	}
	if !m.WaitIdle(reg.Name, 5*time.Second) {
		t.Fatal("restart did not finish")
	}
	m.mu.Lock()
	current, dead, reused := p.inst, p.dead, p.compilationCache == cache
	m.mu.Unlock()
	if current == first || dead || !reused {
		t.Fatal("restart did not reuse this generation's cache with immutable input")
	}
	// New registration, even with identical bytes, gets a separate cache.
	observed := &observedCacheClose{CompilationCache: cache}
	p.compilationCache = observed // No more failures are injected in this worker.
	reg.Module, reg.Config = originalModule, originalConfig
	if err := m.Register(ctx, reg); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	replacement := m.plugins[reg.Name]
	m.mu.Unlock()
	if replacement == p || replacement.compilationCache == cache || observed.calls.Load() != 1 {
		t.Fatal("replacement shared or retained the old generation's cache")
	}
	m.teardown(ctx, p)
	if observed.calls.Load() != 1 {
		t.Fatal("repeated teardown closed the cache twice")
	}
}

func TestRestartCacheCloseWaitsForWorkerAndRuntime(t *testing.T) {
	ctx := context.Background()
	src := newFakeSource()
	m, _ := newTestManager(t, src, newFakeClaims())
	reg := Registration{Name: "cache-close-order", Module: fixtureModule(t, "echo")}
	if err := m.Register(ctx, reg); err != nil {
		t.Fatal(err)
	}
	if !m.WaitIdle(reg.Name, 5*time.Second) {
		t.Fatal("initial replay not idle")
	}
	p := m.plugins[reg.Name]
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unpause := func() { once.Do(func() { close(release) }) }
	defer unpause()
	p.worker.submitBarrier(func() { close(entered); <-release })
	<-entered
	observed := &observedCacheClose{CompilationCache: p.compilationCache, before: func() {
		select {
		case <-p.worker.done:
		default:
			t.Error("cache closed before worker stopped")
		}
		if _, err := p.inst.HandleEvents(ctx, nil); err == nil {
			t.Error("cache closed before runtime closed")
		}
	}}
	p.compilationCache = observed
	finished := make(chan error, 1)
	go func() { finished <- m.Unregister(ctx, reg.Name) }()
	select {
	case err := <-finished:
		unpause()
		t.Fatalf("unregister did not wait for in-flight worker: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if observed.calls.Load() != 0 {
		t.Fatal("cache closed during an in-flight worker callback")
	}
	unpause()
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	if observed.calls.Load() != 1 {
		t.Fatal("unregister did not release its cache")
	}
}
