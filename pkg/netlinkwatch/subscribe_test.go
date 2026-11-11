package netlinkwatch

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/takehaya/vinbero/pkg/netlinksub"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

func shortResubscribe(t *testing.T) {
	t.Helper()
	minD, maxD := netlinksub.MinDelay, netlinksub.MaxDelay
	netlinksub.MinDelay, netlinksub.MaxDelay = 5*time.Millisecond, 20*time.Millisecond
	t.Cleanup(func() { netlinksub.MinDelay, netlinksub.MaxDelay = minD, maxD })
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !cond(); time.Sleep(2 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

// fakeNeighSubs hands out subscriptions whose channels the test closes and
// feeds; the first fails is the number of attempts after the first that
// fail.
type fakeNeighSubs struct {
	mu    sync.Mutex
	chans []chan<- netlink.NeighUpdate
	fails int
	tries int
}

func (f *fakeNeighSubs) subscribe(ch chan<- netlink.NeighUpdate, _ <-chan struct{}, o netlink.NeighSubscribeOptions) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tries++
	if f.tries > 1 && f.tries <= 1+f.fails {
		return errors.New("no buffer space available")
	}
	if o.ListExisting {
		return errors.New("ListExisting sends its request to the group's other subscribers")
	}
	f.chans = append(f.chans, ch)
	return nil
}

func (f *fakeNeighSubs) last() (chan<- netlink.NeighUpdate, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.chans) == 0 {
		return nil, 0
	}
	return f.chans[len(f.chans)-1], len(f.chans)
}

// An FDB subscription that ends is subscribed again, past failed attempts,
// and the FDB is replayed again, so a MAC learned while it was down still
// reaches fdb_map; updates on the new subscription are applied.
func TestFDBWatcherResubscribesAndReplays(t *testing.T) {
	shortResubscribe(t)
	macA := net.HardwareAddr{0x02, 0, 0, 0, 0, 0xa}
	macB := net.HardwareAddr{0x02, 0, 0, 0, 0, 0xb}
	macC := net.HardwareAddr{0x02, 0, 0, 0, 0, 0xc}
	var mu sync.Mutex
	fdb := []netlink.Neigh{{Family: unix.AF_BRIDGE, MasterIndex: 10, LinkIndex: 3, HardwareAddr: macA}}
	ops := &lockedFdbMapOps{fakeFdbMapOps: &fakeFdbMapOps{}}
	subs := &fakeNeighSubs{fails: 2}
	w := &FDBWatcher{
		mapOps:  ops,
		logger:  zap.NewNop(),
		allowed: make(map[int]uint16),
		neighList: func(int, int) ([]netlink.Neigh, error) {
			mu.Lock()
			defer mu.Unlock()
			return slices.Clone(fdb), nil
		},
		subscribe: subs.subscribe,
		done:      make(chan struct{}),
	}
	w.RegisterBridge(10, 100)
	if err := w.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer w.Stop()
	if got := ops.learned(); !slices.Equal(got, []string{macA.String()}) {
		t.Fatalf("Start replayed %v, want %s", got, macA)
	}

	// Learned while the subscription is down.
	mu.Lock()
	fdb = append(fdb, netlink.Neigh{Family: unix.AF_BRIDGE, MasterIndex: 10, LinkIndex: 3, HardwareAddr: macB})
	mu.Unlock()
	first, _ := subs.last()
	close(first)
	eventually(t, "a second subscription", func() bool { _, n := subs.last(); return n == 2 })
	eventually(t, "the replay after the resubscribe", func() bool { return slices.Contains(ops.learned(), macB.String()) })

	second, _ := subs.last()
	second <- netlink.NeighUpdate{Type: unix.RTM_NEWNEIGH, Neigh: netlink.Neigh{Family: unix.AF_BRIDGE, MasterIndex: 10, LinkIndex: 3, HardwareAddr: macC}}
	eventually(t, "an update on the new subscription", func() bool { return slices.Contains(ops.learned(), macC.String()) })
	subs.mu.Lock()
	tries := subs.tries
	subs.mu.Unlock()
	if tries != 4 {
		t.Errorf("subscribe called %d times, want 4 (the first, two failures, the one that came back)", tries)
	}
}

type fakeRouteSubs struct {
	mu    sync.Mutex
	chans []chan<- netlink.RouteUpdate
}

func (f *fakeRouteSubs) subscribe(ch chan<- netlink.RouteUpdate, _ <-chan struct{}, o netlink.RouteSubscribeOptions) error {
	if o.ListExisting {
		return errors.New("ListExisting sends its request to the group's other subscribers")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.chans = append(f.chans, ch)
	return nil
}

func (f *fakeRouteSubs) last() (chan<- netlink.RouteUpdate, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.chans) == 0 {
		return nil, 0
	}
	return f.chans[len(f.chans)-1], len(f.chans)
}

// Start replays the registered tables. After a subscription that ended
// comes back, the tables are resynced: a route added meanwhile is delivered
// as added, and a prefix whose route was deleted meanwhile as removed.
func TestRouteWatcherResyncsAfterResubscribe(t *testing.T) {
	shortResubscribe(t)
	r := func(cidr string) netlink.Route {
		return newRoute(100, unix.RTPROT_STATIC, mustIPNet(t, cidr))
	}
	var mu sync.Mutex
	table := []netlink.Route{r("10.1.0.0/24"), r("10.2.0.0/24")}
	sink := &lockedSink{}
	w := NewRouteWatcher(sink, zap.NewNop())
	subs := &fakeRouteSubs{}
	w.subscribe = subs.subscribe
	w.routeList = func(tb uint32) ([]netlink.Route, error) {
		mu.Lock()
		defer mu.Unlock()
		if tb != 100 {
			return nil, nil
		}
		return slices.Clone(table), nil
	}
	if err := w.RegisterTable(100, []string{"static"}); err != nil {
		t.Fatal(err)
	}
	if err := w.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer w.Stop()
	call := func(cidr string, added bool) sinkCall {
		return sinkCall{table: 100, prefix: netip.MustParsePrefix(cidr), added: added}
	}
	eventually(t, "the replay at Start", func() bool {
		c := sink.get()
		return slices.Contains(c, call("10.1.0.0/24", true)) && slices.Contains(c, call("10.2.0.0/24", true))
	})

	mu.Lock()
	table = []netlink.Route{r("10.1.0.0/24"), r("10.3.0.0/24")} // 10.2 deleted, 10.3 added while down
	mu.Unlock()
	n0 := len(sink.get())
	first, _ := subs.last()
	close(first)
	eventually(t, "the resync after the resubscribe", func() bool {
		c := sink.get()[n0:]
		return slices.Contains(c, call("10.2.0.0/24", false)) && slices.Contains(c, call("10.3.0.0/24", true))
	})
	if slices.Contains(sink.get()[n0:], call("10.1.0.0/24", false)) {
		t.Error("the resync removed a prefix whose route is still there")
	}

	// A removed prefix is not removed again by the next resync.
	n1 := len(sink.get())
	second, _ := subs.last()
	close(second)
	eventually(t, "a third subscription", func() bool { _, n := subs.last(); return n == 3 })
	eventually(t, "the second resync", func() bool { return slices.Contains(sink.get()[n1:], call("10.3.0.0/24", true)) })
	if slices.Contains(sink.get()[n1:], call("10.2.0.0/24", false)) {
		t.Error("a prefix removed by the last resync was removed again")
	}
}
