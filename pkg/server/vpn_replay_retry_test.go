package server

import (
	"errors"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bgp/apply"
)

// scriptedTracked counts tracked-only passes and returns scripted errors, then
// nil.
type scriptedTracked struct {
	calls atomic.Int32
	errs  chan error
	seen  chan struct{}
}

func newScriptedTracked() *scriptedTracked {
	return &scriptedTracked{errs: make(chan error, 16), seen: make(chan struct{}, 16)}
}

func (f *scriptedTracked) run() error {
	f.calls.Add(1)
	f.seen <- struct{}{}
	select {
	case err := <-f.errs:
		return err
	default:
		return nil
	}
}

func waitTracked(t *testing.T, f *scriptedTracked) {
	t.Helper()
	select {
	case <-f.seen:
	case <-time.After(5 * time.Second):
		t.Fatal("tracked pass did not run")
	}
}

func newRetryTestReplayer(f *fakeVPNReplay, tr *scriptedTracked, logger *zap.Logger) *vpnReplayer {
	r := newVPNReplayer(f.replay, tr.run, logger)
	r.retryMin, r.retryMax = time.Millisecond, 2*time.Millisecond
	return r
}

// A new request runs at once, even while an earlier failure waits out a
// long backoff: the backoff only spaces retries.
func TestVPNReplayerRequestSkipsBackoff(t *testing.T) {
	f := &fakeVPNReplay{errs: []error{errors.New("list failed")}, seen: make(chan struct{}, 8)}
	r := newRetryTestReplayer(f, newScriptedTracked(), nil)
	r.retryMin, r.retryMax = time.Hour, time.Hour
	r.request([]bgp.Family{bgp.FamilyEVPN})
	waitReplay(t, f) // fails; the retry waits an hour
	r.request([]bgp.Family{bgp.FamilyVPNv4})
	waitReplay(t, f) // must not wait for the hour
	calls := f.snapshot()
	want := []bgp.Family{bgp.FamilyVPNv4, bgp.FamilyEVPN}
	slices.Sort(want)
	if len(calls) != 2 || !slices.Equal(calls[1], want) {
		t.Errorf("calls = %v, want the second to carry the waiting retry too: %v", calls, want)
	}
}

// A failure that does not go away is retried vpnReplayMaxRetries times and
// then given up with one error line. The next request starts a new series.
func TestVPNReplayerBoundsRetries(t *testing.T) {
	boom := errors.New("list failed")
	errs := make([]error, 0, 2*(vpnReplayMaxRetries+1))
	for range 2 * (vpnReplayMaxRetries + 1) {
		errs = append(errs, boom)
	}
	f := &fakeVPNReplay{errs: errs, seen: make(chan struct{}, 32)}
	core, logs := observer.New(zapcore.WarnLevel)
	r := newRetryTestReplayer(f, newScriptedTracked(), zap.New(core))
	r.request([]bgp.Family{bgp.FamilyVPNv4})
	for range vpnReplayMaxRetries + 1 {
		waitReplay(t, f)
	}
	waitReplayerIdle(t, r)
	if n := len(f.snapshot()); n != vpnReplayMaxRetries+1 {
		t.Errorf("replays = %d, want %d (one attempt and %d retries)", n, vpnReplayMaxRetries+1, vpnReplayMaxRetries)
	}
	// The worker stops before it logs the give-up.
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		if logs.FilterLevelExact(zapcore.ErrorLevel).Len() > 0 {
			break
		}
	}
	if n := logs.FilterLevelExact(zapcore.ErrorLevel).Len(); n != 1 {
		t.Errorf("give-up errors = %d, want 1", n)
	}
	r.request([]bgp.Family{bgp.FamilyVPNv4})
	for range vpnReplayMaxRetries + 1 {
		waitReplay(t, f)
	}
	waitReplayerIdle(t, r)
	if n := len(f.snapshot()); n != 2*(vpnReplayMaxRetries+1) {
		t.Errorf("replays after a new request = %d, want a fresh series of %d more", n, vpnReplayMaxRetries+1)
	}
}

// A failed write of tracked state is retried with the tracked pass alone;
// the loc-rib is not read again for it.
func TestVPNReplayerRetriesTrackedOnly(t *testing.T) {
	f := &fakeVPNReplay{errs: []error{&apply.TrackedWriteError{VPN: 1}}, seen: make(chan struct{}, 8)}
	tr := newScriptedTracked()
	r := newRetryTestReplayer(f, tr, nil)
	r.request([]bgp.Family{bgp.FamilyVPNv4})
	waitReplay(t, f)
	waitTracked(t, tr)
	waitReplayerIdle(t, r)
	if n := len(f.snapshot()); n != 1 {
		t.Errorf("replays = %d, want 1", n)
	}
	if n := tr.calls.Load(); n != 1 {
		t.Errorf("tracked passes = %d, want 1", n)
	}
}

// Routes a replay could not write and does not track are replayed again,
// and only their family.
func TestVPNReplayerReplaysUnwrittenFamilyOnly(t *testing.T) {
	f := &fakeVPNReplay{
		errs: []error{errors.Join(&apply.UnwrittenRoutesError{Family: bgp.FamilyEVPN, Routes: 1})},
		seen: make(chan struct{}, 8),
	}
	r := newRetryTestReplayer(f, newScriptedTracked(), nil)
	r.request([]bgp.Family{bgp.FamilyVPNv4, bgp.FamilyEVPN})
	waitReplay(t, f)
	waitReplay(t, f)
	waitReplayerIdle(t, r)
	calls := f.snapshot()
	if len(calls) != 2 || !slices.Equal(calls[1], []bgp.Family{bgp.FamilyEVPN}) {
		t.Errorf("calls = %v, want the retry to replay evpn only", calls)
	}
}

// A tracked-only request runs the tracked pass, retried within the same
// bound when it keeps failing.
func TestVPNReplayerTrackedRequestBounded(t *testing.T) {
	tr := newScriptedTracked()
	for range vpnReplayMaxRetries + 1 {
		tr.errs <- &apply.TrackedWriteError{MUP: 1}
	}
	f := &fakeVPNReplay{seen: make(chan struct{}, 8)}
	r := newRetryTestReplayer(f, tr, nil)
	r.requestTrackedAfterFailure()
	for range vpnReplayMaxRetries + 1 {
		waitTracked(t, tr)
	}
	waitReplayerIdle(t, r)
	if n := tr.calls.Load(); n != vpnReplayMaxRetries+1 {
		t.Errorf("tracked passes = %d, want %d", n, vpnReplayMaxRetries+1)
	}
	if n := len(f.snapshot()); n != 0 {
		t.Errorf("replays = %d, want none", n)
	}
}

// A write that always fails, hit again by a stream of live updates, gets one
// bounded series of passes: a failure-caused request joins the running
// series instead of restarting it, and after the series gave up such
// requests are ignored until the cool-down has passed. A request that is not
// failure-caused starts a series at any time. The storm lands at whatever
// points the scheduler gives it; TestVPNReplayerFailureAtGiveUpBounded pins
// the request to the moment a series gives up.
func TestVPNReplayerFailureStormBounded(t *testing.T) {
	var calls atomic.Int32
	tracked := func() error {
		calls.Add(1)
		return &apply.TrackedWriteError{MUP: 1}
	}
	var clock atomic.Int64
	clock.Store(time.Now().UnixNano())
	f := &fakeVPNReplay{seen: make(chan struct{}, 64)}
	r := newVPNReplayer(f.replay, tracked, nil)
	r.retryMin, r.retryMax = time.Millisecond, 2*time.Millisecond
	r.now = func() time.Time { return time.Unix(0, clock.Load()) }

	storm := func() {
		deadline := time.Now().Add(200 * time.Millisecond)
		for time.Now().Before(deadline) {
			r.requestTrackedAfterFailure()
			time.Sleep(50 * time.Microsecond)
		}
		waitReplayerIdle(t, r)
	}
	series := int32(vpnReplayMaxRetries + 1)
	storm()
	if n := calls.Load(); n != series {
		t.Fatalf("tracked passes during the storm = %d, want one series of %d", n, series)
	}

	// Within the cool-down a failure starts nothing.
	clock.Add(int64(vpnReplayFailureCooldown / 2))
	storm()
	if n := calls.Load(); n != series {
		t.Errorf("tracked passes within the cool-down = %d, want still %d", n, series)
	}

	// After it, one more series.
	clock.Add(int64(vpnReplayFailureCooldown))
	storm()
	if n := calls.Load(); n != 2*series {
		t.Errorf("tracked passes after the cool-down = %d, want %d", n, 2*series)
	}

	// A binding change is not failure-caused: it runs at once and clears
	// the give-up, so the next failure starts a series again.
	r.request([]bgp.Family{bgp.FamilyVPNv4})
	waitReplay(t, f)
	waitReplayerIdle(t, r)
	r.requestTrackedAfterFailure()
	waitReplayerIdle(t, r)
	if n := calls.Load(); n != 3*series {
		t.Errorf("tracked passes after a binding change = %d, want %d", n, 3*series)
	}
}

// onLog returns a logger that runs fn once, on the worker, when it logs at
// level. The worker logs after releasing its lock and before it acts on what
// it decided, so fn acts as a request arriving in between: at ErrorLevel
// right after a series gave up, at InfoLevel right after a replay succeeded
// and before the worker checks whether anything is left to do. done is
// closed after fn returns.
func onLog(level zapcore.Level, fn func()) (logger *zap.Logger, done <-chan struct{}) {
	ch := make(chan struct{})
	var once atomic.Bool
	observed, _ := observer.New(level)
	core := zapcore.RegisterHooks(observed, func(e zapcore.Entry) error {
		if e.Level == level && once.CompareAndSwap(false, true) {
			fn()
			close(ch)
		}
		return nil
	})
	return zap.New(core), ch
}

func waitClosed(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("the worker did not log the line the test waits for")
	}
}

// A failure-caused request that arrives right as a series gives up is under
// the cool-down like any later one: it must not start another series.
func TestVPNReplayerFailureAtGiveUpBounded(t *testing.T) {
	var calls atomic.Int32
	tracked := func() error {
		calls.Add(1)
		return &apply.TrackedWriteError{MUP: 1}
	}
	f := &fakeVPNReplay{seen: make(chan struct{}, 8)}
	var r *vpnReplayer
	logger, done := onLog(zapcore.ErrorLevel, func() { r.requestTrackedAfterFailure() })
	r = newVPNReplayer(f.replay, tracked, logger)
	r.retryMin, r.retryMax = time.Millisecond, 2*time.Millisecond

	r.requestTrackedAfterFailure()
	waitClosed(t, done)
	waitReplayerIdle(t, r)
	if n, want := calls.Load(), int32(vpnReplayMaxRetries+1); n != want {
		t.Errorf("tracked passes = %d, want one series of %d", n, want)
	}
}

// A request that is not failure-caused and arrives right as a series gives
// up still runs, with a fresh series.
func TestVPNReplayerRequestAtGiveUpRuns(t *testing.T) {
	boom := errors.New("list failed")
	errs := make([]error, 0, vpnReplayMaxRetries+1)
	for range vpnReplayMaxRetries + 1 {
		errs = append(errs, boom)
	}
	f := &fakeVPNReplay{errs: errs, seen: make(chan struct{}, 16)}
	var r *vpnReplayer
	logger, done := onLog(zapcore.ErrorLevel, func() { r.request([]bgp.Family{bgp.FamilyEVPN}) })
	r = newVPNReplayer(f.replay, nil, logger)
	r.retryMin, r.retryMax = time.Millisecond, 2*time.Millisecond

	r.request([]bgp.Family{bgp.FamilyVPNv4})
	for range vpnReplayMaxRetries + 1 {
		waitReplay(t, f)
	}
	waitClosed(t, done)
	waitReplay(t, f) // the request made at the give-up
	waitReplayerIdle(t, r)
	calls := f.snapshot()
	if len(calls) != vpnReplayMaxRetries+2 || !slices.Equal(calls[len(calls)-1], []bgp.Family{bgp.FamilyEVPN}) {
		t.Errorf("calls = %v, want %d failed vpnv4 replays and then evpn", calls, vpnReplayMaxRetries+1)
	}
}

// Requests that arrive after a replay succeeded, just before the worker
// would find nothing to do and stop, are not lost: either kind runs.
func TestVPNReplayerRequestBeforeExitRuns(t *testing.T) {
	f := &fakeVPNReplay{seen: make(chan struct{}, 8)}
	var r *vpnReplayer
	logger, done := onLog(zapcore.InfoLevel, func() { r.request([]bgp.Family{bgp.FamilyEVPN}) })
	r = newVPNReplayer(f.replay, nil, logger)
	r.retryMin, r.retryMax = time.Millisecond, 2*time.Millisecond

	r.request([]bgp.Family{bgp.FamilyVPNv4})
	waitReplay(t, f)
	waitClosed(t, done)
	waitReplay(t, f)
	waitReplayerIdle(t, r)
	calls := f.snapshot()
	want := [][]bgp.Family{{bgp.FamilyVPNv4}, {bgp.FamilyEVPN}}
	if !slices.EqualFunc(calls, want, slices.Equal[[]bgp.Family]) {
		t.Errorf("calls = %v, want %v", calls, want)
	}
}

func TestVPNReplayerFailureBeforeExitRuns(t *testing.T) {
	f := &fakeVPNReplay{seen: make(chan struct{}, 8)}
	tr := newScriptedTracked()
	var r *vpnReplayer
	logger, done := onLog(zapcore.InfoLevel, func() { r.requestTrackedAfterFailure() })
	r = newVPNReplayer(f.replay, tr.run, logger)
	r.retryMin, r.retryMax = time.Millisecond, 2*time.Millisecond

	r.request([]bgp.Family{bgp.FamilyVPNv4})
	waitReplay(t, f)
	waitClosed(t, done)
	waitTracked(t, tr)
	waitReplayerIdle(t, r)
	if n := tr.calls.Load(); n != 1 {
		t.Errorf("tracked passes = %d, want 1", n)
	}
}
