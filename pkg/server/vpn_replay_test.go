package server

import (
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/takehaya/vinbero/pkg/bgp"
)

// fakeVPNReplay records calls and returns scripted errors, then nil.
type fakeVPNReplay struct {
	mu    sync.Mutex
	errs  []error
	calls [][]bgp.Family
	seen  chan struct{}
	gate  chan struct{} // when set, each call waits for one receive
}

func (f *fakeVPNReplay) replay(families []bgp.Family) error {
	if f.gate != nil {
		f.seen <- struct{}{}
		<-f.gate
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	slices.Sort(families)
	f.calls = append(f.calls, families)
	if f.gate == nil {
		f.seen <- struct{}{}
	}
	if len(f.errs) > 0 {
		err := f.errs[0]
		f.errs = f.errs[1:]
		return err
	}
	return nil
}

func (f *fakeVPNReplay) snapshot() [][]bgp.Family {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

func waitReplay(t *testing.T, f *fakeVPNReplay) {
	t.Helper()
	select {
	case <-f.seen:
	case <-time.After(5 * time.Second):
		t.Fatal("replay did not run")
	}
}

func waitReplayerIdle(t *testing.T, r *vpnReplayer) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		idle := !r.running
		r.mu.Unlock()
		if idle {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("replayer did not stop")
}

func newTestReplayer(f *fakeVPNReplay) *vpnReplayer {
	r := newVPNReplayer(f.replay, nil)
	r.retryMin, r.retryMax = time.Millisecond, 2*time.Millisecond
	return r
}

// A failed replay is retried until it succeeds, because the routes it rescues
// are never delivered again.
func TestVPNReplayerRetriesFailure(t *testing.T) {
	boom := errors.New("list failed")
	f := &fakeVPNReplay{errs: []error{boom, boom}, seen: make(chan struct{}, 8)}
	r := newTestReplayer(f)
	r.request([]bgp.Family{bgp.FamilyVPNv4, bgp.FamilyVPNv6})
	for range 3 {
		waitReplay(t, f)
	}
	waitReplayerIdle(t, r)
	want := []bgp.Family{bgp.FamilyVPNv4, bgp.FamilyVPNv6}
	calls := f.snapshot()
	if len(calls) != 3 {
		t.Fatalf("calls = %v, want 3", calls)
	}
	for _, c := range calls {
		if !slices.Equal(c, want) {
			t.Errorf("call = %v, want %v", c, want)
		}
	}
}

// Before the session starts every route still arrives after the binding, so
// a replay has nothing to rescue and is not retried.
func TestVPNReplayerDropsSessionNotStarted(t *testing.T) {
	f := &fakeVPNReplay{
		errs: []error{fmt.Errorf("demux: snapshot vpnv4: %w", bgp.ErrSessionNotStarted)},
		seen: make(chan struct{}, 8),
	}
	r := newTestReplayer(f)
	r.request([]bgp.Family{bgp.FamilyVPNv4})
	waitReplay(t, f)
	waitReplayerIdle(t, r)
	if calls := f.snapshot(); len(calls) != 1 {
		t.Errorf("calls = %v, want 1", calls)
	}
}

// Requests arriving during a replay are merged into one following replay.
func TestVPNReplayerMergesRequests(t *testing.T) {
	f := &fakeVPNReplay{seen: make(chan struct{}, 8), gate: make(chan struct{})}
	r := newTestReplayer(f)
	r.request([]bgp.Family{bgp.FamilyVPNv4})
	waitReplay(t, f) // first replay is in progress
	r.request([]bgp.Family{bgp.FamilyVPNv6})
	r.request([]bgp.Family{bgp.FamilyVPNv4})
	r.request(nil)
	f.gate <- struct{}{}
	waitReplay(t, f) // the merged replay
	f.gate <- struct{}{}
	waitReplayerIdle(t, r)
	calls := f.snapshot()
	want := [][]bgp.Family{{bgp.FamilyVPNv4}, {bgp.FamilyVPNv4, bgp.FamilyVPNv6}}
	if !slices.EqualFunc(calls, want, slices.Equal[[]bgp.Family]) {
		t.Errorf("calls = %v, want %v", calls, want)
	}
}
