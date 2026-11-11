package netlinksub

import (
	"errors"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// An error that does not end the subscription is logged at debug level only;
// the end is a warning carrying the error that ended it; a failure is logged
// when it changes; the wait doubles up to MaxDelay; the recovery is logged
// once and the next end starts from MinDelay again.
func TestStateLogsChangesOnce(t *testing.T) {
	core, logs := observer.New(zapcore.DebugLevel)
	s := New(zap.New(core), "neighbours")
	warns := func() int { return logs.FilterLevelExact(zapcore.WarnLevel).Len() }

	s.OnError(errors.New("Wrong sender portid 2848495606, expected 0"))
	if warns() != 0 {
		t.Fatal("a skipped message was logged as a warning")
	}

	s.OnError(errors.New("no buffer space available"))
	if d := s.Ended(); d != MinDelay {
		t.Errorf("first wait %v, want %v", d, MinDelay)
	}
	ended := logs.FilterMessage("netlink subscription ended; subscribing again; events until then are recovered by a full resync").All()
	if len(ended) != 1 || ended[0].ContextMap()["error"] != "no buffer space available" || ended[0].ContextMap()["subscription"] != "neighbours" {
		t.Fatalf("end logged as %v", ended)
	}

	same := errors.New("operation not permitted")
	var waits []time.Duration
	for range 6 {
		waits = append(waits, s.Failed(same))
	}
	if n := logs.FilterMessage("netlink subscription: cannot subscribe; retrying").Len(); n != 1 {
		t.Errorf("the same failure logged %d times, want 1", n)
	}
	want := []time.Duration{2 * MinDelay, 4 * MinDelay, 8 * MinDelay, 16 * MinDelay, MaxDelay, MaxDelay}
	for i := range want {
		if waits[i] != want[i] {
			t.Errorf("waits %v, want %v", waits, want)
			break
		}
	}
	s.Failed(errors.New("no such file or directory"))
	if n := logs.FilterMessage("netlink subscription: cannot subscribe; retrying").Len(); n != 2 {
		t.Errorf("a new failure logged %d times in all, want 2", n)
	}

	s.Restored()
	s.Restored()
	if n := logs.FilterMessage("netlink subscription restored; resyncing").Len(); n != 1 {
		t.Errorf("recovery logged %d times, want 1", n)
	}
	if d := s.Ended(); d != MinDelay {
		t.Errorf("wait after a recovery %v, want %v", d, MinDelay)
	}
}

// A first subscribe that fails is a failure too, and its recovery is logged.
func TestStateFirstSubscribeFails(t *testing.T) {
	core, logs := observer.New(zapcore.InfoLevel)
	s := New(zap.New(core), "links")
	s.Failed(errors.New("operation not permitted"))
	s.Restored()
	if n := logs.FilterMessage("netlink subscription restored; resyncing").Len(); n != 1 {
		t.Errorf("recovery logged %d times, want 1", n)
	}
}

// Again waits, retries a failing subscribe, and stops when stop is closed.
func TestAgain(t *testing.T) {
	minD, maxD := MinDelay, MaxDelay
	MinDelay, MaxDelay = time.Millisecond, 4*time.Millisecond
	t.Cleanup(func() { MinDelay, MaxDelay = minD, maxD })
	s := New(zap.NewNop(), "routes")
	tries := 0
	if !s.Again(make(chan struct{}), func() error {
		tries++
		if tries < 3 {
			return errors.New("busy")
		}
		return nil
	}) || tries != 3 {
		t.Errorf("Again returned after %d tries, want true after 3", tries)
	}
	stop := make(chan struct{})
	close(stop)
	if s.Again(stop, func() error { t.Error("subscribed after stop"); return nil }) {
		t.Error("Again reported a subscription after stop")
	}
}

// A failed listing is retried with growing waits and logged when its error
// changes; success stops the retries and is logged once after a failure.
func TestListing(t *testing.T) {
	core, logs := observer.New(zapcore.InfoLevel)
	l := NewListing(zap.New(core), "FDB")
	if l.Result(nil) != nil || logs.Len() != 0 {
		t.Fatal("a listing that succeeded asked for a retry or logged")
	}
	err := errors.New("results may be incomplete or inconsistent")
	for range 3 {
		if l.Result(err) == nil {
			t.Fatal("a failed listing asked for no retry")
		}
	}
	if l.delay != 4*MinDelay {
		t.Errorf("third wait %v, want %v", l.delay, 4*MinDelay)
	}
	if n := logs.FilterMessage("netlink listing incomplete; retrying").Len(); n != 1 {
		t.Errorf("the same failure logged %d times, want 1", n)
	}
	if l.Result(nil) != nil {
		t.Error("a listing that succeeded asked for a retry")
	}
	if n := logs.FilterMessage("netlink listing complete after a retry").Len(); n != 1 {
		t.Errorf("the success after a failure logged %d times, want 1", n)
	}
}
