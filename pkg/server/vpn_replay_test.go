package server

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/locator"
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

// Registering the BGP source locator requests a VPN replay. A VPN route that
// arrives first is tracked but cannot be programmed, since every headend entry
// takes its encapsulation source from that locator, and nothing else would
// deliver the route again. Other locators and failed registrations request
// nothing.
func TestLocatorCreate_SourceLocatorRequestsVpnReplay(t *testing.T) {
	mgr := locator.NewManager()
	var got [][]bgp.Family
	request := func(families []bgp.Family) {
		got = append(got, slices.Clone(families))
	}
	srv := NewLocatorServer(mgr, replayOnSourceLocator(mgr.Add, "LOC2", request), nil)
	create := func(name, prefix string) {
		t.Helper()
		if _, err := srv.LocatorCreate(context.Background(), connect.NewRequest(&v1.LocatorCreateRequest{
			Locators: []*v1.Locator{{
				Name: name, Prefix: prefix,
				BlockLen: 32, NodeLen: 16, FunctionLen: 16, ArgumentLen: 64,
				Behavior: v1.LocatorBehaviorMode_LOCATOR_BEHAVIOR_MODE_CLASSIC,
			}},
		})); err != nil {
			t.Fatalf("LocatorCreate: %v", err)
		}
	}

	create("LOC1", "fd00:100::/48")
	if len(got) != 0 {
		t.Fatalf("another locator requested a replay: %v", got)
	}
	create("LOC2", "fd00:100::/48") // prefix taken: the add fails
	if len(got) != 0 {
		t.Fatalf("a failed registration requested a replay: %v", got)
	}
	create("LOC2", "fd00:200::/48")
	want := [][]bgp.Family{{bgp.FamilyVPNv4, bgp.FamilyVPNv6}}
	if !slices.EqualFunc(got, want, slices.Equal[[]bgp.Family]) {
		t.Errorf("source locator: replays = %v, want %v", got, want)
	}
	if _, ok := mgr.Get("LOC2"); !ok {
		t.Error("source locator was not registered")
	}
}

// Without BGP or a configured source locator the add is passed through as is.
func TestReplayOnSourceLocatorPassThrough(t *testing.T) {
	add := func(*locator.Locator) error { return nil }
	request := func([]bgp.Family) { t.Error("unexpected replay request") }
	for _, tc := range []struct {
		source  string
		request func([]bgp.Family)
	}{{"", request}, {"LOC2", nil}} {
		wrapped := replayOnSourceLocator(add, tc.source, tc.request)
		if err := wrapped(&locator.Locator{Name: "LOC2"}); err != nil {
			t.Fatal(err)
		}
	}
	if replayOnSourceLocator(nil, "LOC2", request) != nil {
		t.Error("a nil add was wrapped")
	}
}
