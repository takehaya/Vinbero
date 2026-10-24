package gobgp_test

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/takehaya/vinbero/pkg/bgp"
)

// Direct E2E subscribers own BPF maps that cleanup closes. Watch cancellation
// does not join an in-flight callback, so close also drains and rejects late work.
type e2eRouteHandler struct {
	mu      sync.Mutex
	closed  bool
	handler bgp.RouteHandler
}

func (h *e2eRouteHandler) apply(ev bgp.RouteEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.closed {
		h.handler(ev)
	}
}

func (h *e2eRouteHandler) close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = true
}

func subscribeE2E(t *testing.T, source bgp.RouteSubscriber, handler bgp.RouteHandler) {
	t.Helper()
	guard := &e2eRouteHandler{handler: handler}
	t.Cleanup(guard.close)
	cancel, err := source.Subscribe("", guard.apply)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	t.Cleanup(cancel)
}

func TestE2ERouteHandlerCloseDrainsAndRejectsLateCallbacks(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	guard := &e2eRouteHandler{handler: func(bgp.RouteEvent) {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
		}
	}}
	applied := make(chan struct{})
	go func() {
		guard.apply(bgp.RouteEvent{})
		close(applied)
	}()
	<-entered
	closing, closed := make(chan struct{}), make(chan struct{})
	go func() {
		close(closing)
		guard.close()
		close(closed)
	}()
	<-closing
	select {
	case <-closed:
		t.Error("close returned while callback still accesses its resources")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	<-applied
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("close did not finish after callback returned")
	}
	// A watch goroutine can already have decoded another event when cancelled.
	guard.apply(bgp.RouteEvent{})
	guard.close()
	if got := calls.Load(); got != 1 {
		t.Fatalf("callbacks after close: got %d total calls, want 1", got)
	}
}
