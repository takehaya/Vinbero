package demux

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/takehaya/vinbero/pkg/bgp"
)

type lifecycleSubscriber func(bgp.Family, bgp.RouteHandler) (func(), error)

func (s lifecycleSubscriber) Subscribe(f bgp.Family, h bgp.RouteHandler) (func(), error) {
	return s(f, h)
}

func awaitLifecycle(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("lifecycle operation did not finish")
	}
}

func TestStopDrainsCallbackAndRejectsOldGeneration(t *testing.T) {
	handlers := make(chan bgp.RouteHandler, 2)
	cancelled := make(chan struct{}, 2)
	d := New(lifecycleSubscriber(func(_ bgp.Family, h bgp.RouteHandler) (func(), error) {
		handlers <- h
		return func() { cancelled <- struct{}{} }, nil
	}), nil, nil)
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	var calls atomic.Int32
	_, err := d.RegisterQuiet("consumer", nil, func(bgp.RouteEvent) {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
			// Stop must not hold the registry lock while draining a handler.
			cancel, err := d.RegisterQuiet("temporary", nil, func(bgp.RouteEvent) {})
			if err != nil {
				t.Error(err)
				return
			}
			cancel()
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Start(); err != nil {
		t.Fatal(err)
	}
	old := <-handlers
	applied := make(chan struct{})
	ev := peerEvent(bgp.FamilyEVPN, "2001:db8::1")
	go func() { old(ev); close(applied) }()
	awaitLifecycle(t, entered)
	stopped := make(chan struct{})
	go func() { d.Stop(); close(stopped) }()
	awaitLifecycle(t, cancelled)
	select {
	case <-stopped:
		t.Error("Stop returned while callback still holds resources")
	case <-time.After(50 * time.Millisecond):
	}
	unblock()
	awaitLifecycle(t, applied)
	awaitLifecycle(t, stopped)
	old(ev)
	if got := calls.Load(); got != 1 {
		t.Errorf("late callback after Stop: got %d calls, want 1", got)
	}
	if err := d.Start(); err != nil {
		t.Fatal(err)
	}
	current := <-handlers
	old(ev)
	current(ev)
	if got := calls.Load(); got != 2 {
		t.Errorf("old generation resumed after restart: got %d calls, want 2", got)
	}
	d.Stop()
}

func TestStopWaitsForSubscribePublication(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	var cancellations atomic.Int32
	handlers := make(chan bgp.RouteHandler, 1)
	d := New(lifecycleSubscriber(func(_ bgp.Family, h bgp.RouteHandler) (func(), error) {
		handlers <- h
		close(entered)
		<-release
		return func() { cancellations.Add(1) }, nil
	}), nil, nil)
	var calls atomic.Int32
	if _, err := d.RegisterQuiet("consumer", nil, func(bgp.RouteEvent) { calls.Add(1) }); err != nil {
		t.Fatal(err)
	}
	started := make(chan error, 1)
	go func() { started <- d.Start() }()
	awaitLifecycle(t, entered)
	stopping, stopped := make(chan struct{}), make(chan struct{})
	go func() { close(stopping); d.Stop(); close(stopped) }()
	awaitLifecycle(t, stopping)
	select {
	case <-stopped:
		t.Error("Stop returned before Subscribe published its cancel function")
	case <-time.After(50 * time.Millisecond):
	}
	unblock()
	if err := <-started; err != nil {
		t.Fatal(err)
	}
	awaitLifecycle(t, stopped)
	(<-handlers)(peerEvent(bgp.FamilyVPNv4, "192.0.2.1"))
	if got := calls.Load(); got != 0 {
		t.Errorf("callback delivered after concurrent Stop: %d", got)
	}
	if got := cancellations.Load(); got != 1 {
		t.Errorf("underlying cancellations = %d, want 1", got)
	}
}

func TestFailedSubscribeDrainsAndFencesRetry(t *testing.T) {
	handlers := make(chan bgp.RouteHandler, 2)
	entered, release, applied := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	var subscriptions, cancellations, calls atomic.Int32
	failure := errors.New("subscribe failed after callback launch")
	ev := peerEvent(bgp.FamilyVPNv4, "192.0.2.1")
	d := New(lifecycleSubscriber(func(_ bgp.Family, h bgp.RouteHandler) (func(), error) {
		handlers <- h
		cancel := func() { cancellations.Add(1) }
		if subscriptions.Add(1) == 1 {
			go func() { h(ev); close(applied) }()
			<-entered
			return cancel, failure
		}
		return cancel, nil
	}), nil, nil)
	if _, err := d.RegisterQuiet("consumer", nil, func(bgp.RouteEvent) {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
		}
	}); err != nil {
		t.Fatal(err)
	}
	started := make(chan error, 1)
	go func() { started <- d.Start() }()
	awaitLifecycle(t, entered)
	var startErr error
	returned := false
	select {
	case startErr = <-started:
		returned = true
		t.Error("failed Start returned before its callback drained")
	case <-time.After(50 * time.Millisecond):
	}
	unblock()
	awaitLifecycle(t, applied)
	if !returned {
		startErr = <-started
	}
	if !errors.Is(startErr, failure) {
		t.Fatalf("Start error = %v, want wrapped failure", startErr)
	}
	if got := cancellations.Load(); got != 1 {
		t.Errorf("failed subscription cancellations = %d, want 1", got)
	}
	old := <-handlers
	if err := d.Start(); err != nil {
		t.Fatal(err)
	}
	old(ev)
	(<-handlers)(ev)
	if got := calls.Load(); got != 2 {
		t.Errorf("failed generation delivered after retry: got %d calls, want 2", got)
	}
	d.Stop()
}
