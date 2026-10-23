package cplane

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/cplane/wasm"
)

type handoffSource struct {
	*compositionSource
	entered, release chan struct{}
}

func (s *handoffSource) SnapshotTo(f []bgp.Family, h bgp.RouteHandler) error {
	if s.entered != nil {
		close(s.entered)
		<-s.release
	}
	return s.compositionSource.SnapshotTo(f, h)
}

type handoffMaps struct {
	*serviceFake
	uplinkDeletes int
	beforeHeadend func(string)
}

func (f *handoffMaps) CreateHeadendV4(prefix string, entry *bpf.HeadendEntry, owner bpf.OwnerTag) error {
	if f.beforeHeadend != nil {
		f.beforeHeadend(prefix)
	}
	return f.serviceFake.CreateHeadendV4(prefix, entry, owner)
}

func (f *handoffMaps) DeleteMupUplinkV4Owned(id uint32, ep string, teid uint32, bits uint8, owner bpf.OwnerTag) error {
	f.uplinkDeletes++
	return f.serviceFake.DeleteMupUplinkV4Owned(id, ep, teid, bits, owner)
}

func handoffRegistration(t *testing.T, backend string) Registration {
	t.Helper()
	r := compositionBackendRegistration(t, backend)
	r.Name = "handoff"
	r.Capabilities, _ = wasm.ParseCapabilities([]string{"headend", "mup"})
	r.Scope, _ = ParseScope(ScopeSpec{HeadendPrefixes: []string{"10.0.0.0/8", "192.0.2.0/24"}})
	r.Input = compositionPolicy()
	r.Input.Contexts[0].DelegateEvpn = false
	r.Input.Contexts[0].BridgeDomain = 0
	r.Config = []byte(`{"context":"mobile","source":"fd00:feed::1","args_offset":7,"observe_only":false}`)
	return r
}
func handoffManager(t *testing.T, src *handoffSource, f *handoffMaps, stores ...*Store) *Manager {
	t.Helper()
	var store *Store
	if len(stores) != 0 {
		store = stores[0]
	}
	m, err := NewManager(ManagerConfig{Store: store, AllowNative: true, Source: src, Headend: f, ForwardingMaps: f, ResolveMUPInstance: func(string) (uint32, error) { return 7, nil }, ResolveInputTarget: func(bgp.RouteEvent) (string, uint16, bool) { return "", 0, true }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close(context.Background()) })
	return m
}
func handoffIdle(t *testing.T, m *Manager) {
	t.Helper()
	if !m.WaitIdle("handoff", 5*time.Second) {
		t.Fatal("handoff did not drain")
	}
}

func TestInputHandoffRetainsForwardingUntilReplay(t *testing.T) {
	for _, pair := range [][2]string{{BackendNative, BackendNative}, {BackendNative, BackendWASM}, {BackendWASM, BackendNative}} {
		t.Run(pair[0]+"_to_"+pair[1], func(t *testing.T) {
			first, next := handoffRegistration(t, pair[0]), handoffRegistration(t, pair[1])
			f := &handoffMaps{serviceFake: newServiceFake()}
			src := &handoffSource{compositionSource: &compositionSource{newFakeSource()}}
			src.setRib(mupFixture(t)...)
			m := handoffManager(t, src, f)
			if err := m.Register(context.Background(), first); err != nil {
				t.Fatal(err)
			}
			handoffIdle(t, m)
			before := *f.v4["10.0.0.1/32"]
			writes, deleted := len(f.writes), f.uplinkDeletes
			// Change only the downlink TEID; the uplink and its gate must survive too.
			latest := mupFixture(t)
			latest[0] = mupFixtureWithTEID(t, 512)[0]
			src.setRib(latest...)
			src.entered, src.release = make(chan struct{}), make(chan struct{})
			released := false
			defer func() {
				if !released {
					close(src.release)
				}
			}()
			done := make(chan error, 1)
			go func() { done <- m.Register(context.Background(), next) }()
			select {
			case <-src.entered:
			case err := <-done:
				t.Fatalf("registration ended before replay: %v", err)
			case <-time.After(90 * time.Second):
				t.Fatal("replacement did not reach replay")
			}
			// No guest output can be published while the authoritative replay is blocked.
			if got := f.v4["10.0.0.1/32"]; got == nil || *got != before || len(f.uplinks) != 1 || len(f.v4) != 2 {
				t.Fatalf("replacement pruned inherited forwarding: v4=%v uplinks=%v", f.v4, f.uplinks)
			}
			close(src.release)
			released = true
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			handoffIdle(t, m)
			if got := f.v4["10.0.0.1/32"]; got == nil || *got == before {
				t.Fatal("latest replay did not replace TEID")
			}
			if f.uplinkDeletes != deleted {
				t.Fatal("unchanged uplink was deleted during handoff")
			}
			for _, write := range f.writes[writes:] {
				if strings.HasPrefix(write, "delete ") {
					t.Fatalf("retained forwarding key deleted: %s", write)
				}
			}
			st, _ := m.StatsFor("handoff")
			if !st.InputReady || st.OutputFailure != "" || st.AppliedRevision != st.DesiredRevision {
				t.Fatalf("bad final state: %+v", st)
			}
		})
	}
}

func TestInputHandoffRevocationStillFlushes(t *testing.T) {
	for _, change := range []string{"policy", "scope", "capability", "limits", "restore", "input_fault", "output_fault", "not_ready", "cleanup_pending", "dead"} {
		t.Run(change, func(t *testing.T) {
			f := &handoffMaps{serviceFake: newServiceFake()}
			src := &handoffSource{compositionSource: &compositionSource{newFakeSource()}}
			src.setRib(mupFixture(t)...)
			var store *Store
			if change == "restore" {
				var err error
				store, err = NewStore(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
			}
			m := handoffManager(t, src, f, store)
			r := handoffRegistration(t, BackendNative)
			if err := m.Register(context.Background(), r); err != nil {
				t.Fatal(err)
			}
			handoffIdle(t, m)
			next := handoffRegistration(t, BackendNative)
			switch change {
			case "policy":
				next.Input.Contexts[0].Grants[0].RouteTargets = []string{"65000:8"}
			case "scope":
				next.Scope, _ = ParseScope(ScopeSpec{HeadendPrefixes: []string{"192.0.2.0/24"}})
			case "capability":
				delete(next.Capabilities, wasm.CapMUP)
			case "limits":
				next.Limits.CallTimeout = time.Second
			case "restore":
				m.Close(context.Background())
				m = handoffManager(t, src, f, store)
			case "input_fault":
				m.plugins["handoff"].ops.noteInputLoss()
			case "dead":
				m.mu.Lock()
				m.plugins["handoff"].dead = true
				m.mu.Unlock()
			case "not_ready", "cleanup_pending":
				p := m.plugins["handoff"].ops
				p.mu.Lock()
				if change == "not_ready" {
					p.inputReady = false
				} else {
					p.inputCleanupPending = true
				}
				p.mu.Unlock()
			case "output_fault":
				p := m.plugins["handoff"].ops
				p.mu.Lock()
				p.outputFailure = "injected failure"
				p.mu.Unlock()
			}
			if change == "policy" || change == "capability" {
				// These revocations are rejected before replacement by the existing
				// immutable-policy / delegation admission rules.
				if err := m.Register(context.Background(), next); err == nil {
					t.Fatal("invalid authority change accepted")
				}
				if len(f.v4) != 2 || len(f.uplinks) != 1 {
					t.Fatal("rejected replacement touched old forwarding")
				}
				return
			}
			src.entered, src.release = make(chan struct{}), make(chan struct{})
			released := false
			defer func() {
				if !released {
					close(src.release)
				}
			}()
			done := make(chan error, 1)
			go func() {
				if change == "restore" {
					done <- m.Restore(context.Background())
				} else {
					done <- m.Register(context.Background(), next)
				}
			}()
			select {
			case <-src.entered:
			case err := <-done:
				t.Fatalf("registration ended before replay: %v", err)
			case <-time.After(5 * time.Second):
				t.Fatal("replacement did not reach replay")
			}
			if len(f.v4) != 0 || len(f.uplinks) != 0 {
				t.Fatalf("%s retained revoked or untrusted forwarding: v4=%v uplinks=%v", change, f.v4, f.uplinks)
			}
			close(src.release)
			released = true
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			handoffIdle(t, m)
		})
	}
}

// The replacement must judge the completed old call, not its transient
// desired/applied mismatch while a normal map write is still in flight.
func TestInputHandoffWaitsForHealthyInFlightApply(t *testing.T) {
	ctx := context.Background()
	f := &handoffMaps{serviceFake: newServiceFake()}
	src := &handoffSource{compositionSource: &compositionSource{newFakeSource()}}
	src.setRib(mupFixture(t)...)
	m := handoffManager(t, src, f)
	reg := handoffRegistration(t, BackendNative)
	if err := m.Register(ctx, reg); err != nil {
		t.Fatal(err)
	}
	handoffIdle(t, m)
	before := *f.v4["10.0.0.1/32"]
	writes, deleted := len(f.writes), f.uplinkDeletes
	m.mu.Lock()
	old := m.plugins[reg.Name]
	m.mu.Unlock()

	applying, finishApply := make(chan struct{}), make(chan struct{})
	var enteredOnce, finishOnce sync.Once
	defer finishOnce.Do(func() { close(finishApply) })
	f.beforeHeadend = func(prefix string) {
		if prefix == "10.0.0.1/32" {
			enteredOnce.Do(func() { close(applying); <-finishApply })
		}
	}
	latest := mupFixture(t)
	latest[0] = mupFixtureWithTEID(t, 512)[0]
	src.setRib(latest...)
	if !src.emit(reg.Name, latest[0]) {
		t.Fatal("missing old subscription")
	}
	select {
	case <-applying:
	case <-time.After(5 * time.Second):
		t.Fatal("old apply did not reach map write")
	}
	old.ops.mu.Lock()
	ready, desired, applied := old.ops.inputReady, old.ops.desiredRevision, old.ops.appliedRevision
	old.ops.mu.Unlock()
	if !ready || desired <= applied {
		t.Fatalf("not a healthy in-flight apply: ready=%t desired=%d applied=%d", ready, desired, applied)
	}

	src.entered, src.release = make(chan struct{}), make(chan struct{})
	var replayOnce sync.Once
	defer replayOnce.Do(func() { close(src.release) })
	done := make(chan error, 1)
	next := handoffRegistration(t, BackendNative)
	go func() { done <- m.Register(ctx, next) }()
	// close(stop) follows the handoff decision and precedes waiting for this
	// in-flight call, so the ordering does not depend on a sleep or polling.
	select {
	case <-old.worker.stop:
	case <-time.After(5 * time.Second):
		t.Fatal("replacement did not wait for old worker")
	}
	finishOnce.Do(func() { close(finishApply) })
	select {
	case <-src.entered:
	case err := <-done:
		t.Fatalf("replacement ended before replay: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("replacement did not reach replay")
	}
	if got := f.v4["10.0.0.1/32"]; got == nil || *got == before || len(f.v4) != 2 || len(f.uplinks) != 1 {
		t.Fatalf("completed old apply was flushed before replay: v4=%v uplinks=%v", f.v4, f.uplinks)
	}
	replayOnce.Do(func() { close(src.release) })
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	handoffIdle(t, m)
	if f.uplinkDeletes != deleted {
		t.Fatal("unchanged uplink deleted during in-flight handoff")
	}
	for _, write := range f.writes[writes:] {
		if strings.HasPrefix(write, "delete ") {
			t.Fatalf("forwarding deleted during in-flight handoff: %s", write)
		}
	}
	st, _ := m.StatsFor(reg.Name)
	if !st.InputReady || st.OutputFailure != "" || st.DesiredRevision != st.AppliedRevision {
		t.Fatalf("bad final state: %+v", st)
	}
}
