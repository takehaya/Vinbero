package demux

import (
	"errors"
	"net/netip"
	"sync"
	"testing"

	"github.com/takehaya/vinbero/pkg/bgp"
)

// fakeSource is a stub RouteSubscriber + RouteLister. emit pushes a live
// event through whatever handler Subscribe installed; rib is what
// ListRoutes replays.
type fakeSource struct {
	mu        sync.Mutex
	handler   bgp.RouteHandler
	subscribe int
	cancelled int
	rib       map[bgp.Family][]bgp.RouteEvent
	listErr   error
	subErr    error
}

func (f *fakeSource) Subscribe(_ bgp.Family, h bgp.RouteHandler) (func(), error) {
	if f.subErr != nil {
		return nil, f.subErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.subscribe++
	f.handler = h
	return func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.cancelled++
		f.handler = nil
	}, nil
}

func (f *fakeSource) ListRoutes(fam bgp.Family, h bgp.RouteHandler) error {
	if f.listErr != nil {
		return f.listErr
	}
	for _, ev := range f.rib[fam] {
		h(ev)
	}
	return nil
}

func (f *fakeSource) emit(ev bgp.RouteEvent) {
	f.mu.Lock()
	h := f.handler
	f.mu.Unlock()
	if h != nil {
		h(ev)
	}
}

// peerEvent builds a peer-learned event of the given family.
func peerEvent(fam bgp.Family, peer string) bgp.RouteEvent {
	return bgp.RouteEvent{
		Family: fam,
		Source: bgp.PathSource{Peer: netip.MustParseAddr(peer)},
	}
}

// localEvent builds a locally originated event (zero peer address).
func localEvent(fam bgp.Family) bgp.RouteEvent {
	return bgp.RouteEvent{Family: fam}
}

// collector records the events handed to a consumer.
type collector struct {
	mu  sync.Mutex
	got []bgp.RouteEvent
}

func (c *collector) handle(ev bgp.RouteEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.got = append(c.got, ev)
}

func (c *collector) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.got)
}

func TestDispatchDropsLocalOriginOnLiveStream(t *testing.T) {
	src := &fakeSource{}
	d := New(src, src, nil)
	var c collector
	if _, err := d.Register("applier", nil, c.handle); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := d.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}

	src.emit(localEvent(bgp.FamilyEVPN))
	if got := c.len(); got != 0 {
		t.Fatalf("local-origin event delivered: got %d events, want 0", got)
	}

	src.emit(peerEvent(bgp.FamilyEVPN, "2001:db8::1"))
	if got := c.len(); got != 1 {
		t.Fatalf("peer event not delivered: got %d events, want 1", got)
	}
}

func TestDispatchFansOutToEveryConsumer(t *testing.T) {
	src := &fakeSource{}
	d := New(src, src, nil)
	var a, b collector
	if _, err := d.Register("a", nil, a.handle); err != nil {
		t.Fatalf("register a: %v", err)
	}
	if _, err := d.Register("b", nil, b.handle); err != nil {
		t.Fatalf("register b: %v", err)
	}
	if err := d.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}

	src.emit(peerEvent(bgp.FamilyVPNv4, "192.0.2.1"))
	if a.len() != 1 || b.len() != 1 {
		t.Fatalf("fan-out incomplete: a=%d b=%d, want 1 each", a.len(), b.len())
	}
	if src.subscribe != 1 {
		t.Fatalf("underlying Subscribe called %d times, want exactly 1", src.subscribe)
	}
}

func TestDispatchRespectsDeclaredFamilies(t *testing.T) {
	src := &fakeSource{}
	d := New(src, src, nil)
	var evpnOnly collector
	if _, err := d.Register("evpn", []bgp.Family{bgp.FamilyEVPN}, evpnOnly.handle); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := d.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}

	src.emit(peerEvent(bgp.FamilyVPNv4, "192.0.2.1"))
	if got := evpnOnly.len(); got != 0 {
		t.Fatalf("undeclared family delivered: got %d events, want 0", got)
	}
	src.emit(peerEvent(bgp.FamilyEVPN, "192.0.2.1"))
	if got := evpnOnly.len(); got != 1 {
		t.Fatalf("declared family not delivered: got %d events, want 1", got)
	}
}

func TestRegisterRejectsUnknownFamily(t *testing.T) {
	src := &fakeSource{}
	d := New(src, src, nil)
	if _, err := d.Register("bad", []bgp.Family{bgp.Family("nonsense")}, func(bgp.RouteEvent) {}); err == nil {
		t.Fatal("register accepted an unknown family, want error")
	}
}

func TestLateRegisterReplaysSnapshotWithoutLocalOrigin(t *testing.T) {
	src := &fakeSource{rib: map[bgp.Family][]bgp.RouteEvent{
		bgp.FamilyEVPN: {
			peerEvent(bgp.FamilyEVPN, "2001:db8::1"),
			localEvent(bgp.FamilyEVPN),
			peerEvent(bgp.FamilyEVPN, "2001:db8::2"),
		},
	}}
	d := New(src, src, nil)
	if err := d.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}

	var late collector
	if _, err := d.Register("late", []bgp.Family{bgp.FamilyEVPN}, late.handle); err != nil {
		t.Fatalf("register: %v", err)
	}
	if got := late.len(); got != 2 {
		t.Fatalf("replay delivered %d events, want 2 peer-learned (local-origin dropped)", got)
	}
}

func TestReplayFailureDoesNotBlockRegistration(t *testing.T) {
	src := &fakeSource{listErr: errors.New("session not started")}
	d := New(src, src, nil)
	if err := d.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	var c collector
	cancel, err := d.Register("late", []bgp.Family{bgp.FamilyEVPN}, c.handle)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	// Live delivery still works after a failed snapshot.
	src.emit(peerEvent(bgp.FamilyEVPN, "2001:db8::1"))
	if got := c.len(); got != 1 {
		t.Fatalf("live delivery after failed replay: got %d events, want 1", got)
	}
	cancel()
}

func TestCancelStopsDelivery(t *testing.T) {
	src := &fakeSource{}
	d := New(src, src, nil)
	var c collector
	cancel, err := d.Register("a", nil, c.handle)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := d.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	cancel()
	cancel() // idempotent

	src.emit(peerEvent(bgp.FamilyVPNv4, "192.0.2.1"))
	if got := c.len(); got != 0 {
		t.Fatalf("cancelled consumer still received %d events, want 0", got)
	}
}

func TestStartIsSingleShot(t *testing.T) {
	src := &fakeSource{}
	d := New(src, src, nil)
	if err := d.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := d.Start(); !errors.Is(err, ErrAlreadyStarted) {
		t.Fatalf("second Start returned %v, want ErrAlreadyStarted", err)
	}
	if src.subscribe != 1 {
		t.Fatalf("underlying Subscribe called %d times, want exactly 1", src.subscribe)
	}
}

func TestStopCancelsUnderlyingSubscription(t *testing.T) {
	src := &fakeSource{}
	d := New(src, src, nil)
	if err := d.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	d.Stop()
	if src.cancelled != 1 {
		t.Fatalf("cancel called %d times, want 1", src.cancelled)
	}
	// A later Start resumes on the retained consumers.
	if err := d.Start(); err != nil {
		t.Fatalf("restart: %v", err)
	}
	if src.subscribe != 2 {
		t.Fatalf("Subscribe called %d times after restart, want 2", src.subscribe)
	}
}

func TestStartFailurePermitsRetry(t *testing.T) {
	src := &fakeSource{subErr: errors.New("session not started")}
	d := New(src, src, nil)
	if err := d.Start(); err == nil {
		t.Fatal("Start succeeded despite subscribe failure")
	}
	src.subErr = nil
	if err := d.Start(); err != nil {
		t.Fatalf("retry after failed Start: %v", err)
	}
}
