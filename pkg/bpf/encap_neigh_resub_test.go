package bpf

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/takehaya/vinbero/pkg/netlinksub"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"golang.org/x/sys/unix"
)

// shortResubscribe makes the waits before a subscribe attempt short for the
// test.
func shortResubscribe(t *testing.T) {
	t.Helper()
	minD, maxD := netlinksub.MinDelay, netlinksub.MaxDelay
	netlinksub.MinDelay, netlinksub.MaxDelay = 5*time.Millisecond, 20*time.Millisecond
	t.Cleanup(func() { netlinksub.MinDelay, netlinksub.MaxDelay = minD, maxD })
}

// lockedNeighTable is a fakeNeighTable the watch goroutine and the test
// share.
type lockedNeighTable struct {
	mu sync.Mutex
	nt *fakeNeighTable
}

func (l *lockedNeighTable) ops() neighOps {
	in := l.nt.ops()
	return neighOps{
		list: func(ifindex, family int) ([]netlink.Neigh, error) {
			l.mu.Lock()
			defer l.mu.Unlock()
			return in.list(ifindex, family)
		},
		setManaged: func(ifindex uint32, ip net.IP) error {
			l.mu.Lock()
			defer l.mu.Unlock()
			return in.setManaged(ifindex, ip)
		},
		del: func(n netlink.Neigh) error {
			l.mu.Lock()
			defer l.mu.Unlock()
			return in.del(n)
		},
	}
}

func (l *lockedNeighTable) do(fn func(nt *fakeNeighTable)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fn(l.nt)
}

func waitCond(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !cond(); time.Sleep(2 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

func fakeSubs() (*routeSub, *neighSub, *linkSub) {
	return &routeSub{routes: make(chan netlink.RouteUpdate, 1), nexthops: make(chan struct{}, 1), done: make(chan struct{})},
		&neighSub{updates: make(chan netlink.NeighUpdate, 1), done: make(chan struct{})},
		&linkSub{updates: make(chan netlink.LinkUpdate, 1), done: make(chan struct{})}
}

// While the neighbour subscription is down the rest of the watch goes on: a
// write is still resolved. The subscription is tried again until it comes
// back, then every kept entry is checked, so a managed entry deleted while
// it was down is made again. The end, the failure (the same one twice) and
// the recovery are logged once each, and nothing of it at warning level is
// left for a message the library only skipped.
func TestEncapNeighKeeperNeighbourSubscriptionDown(t *testing.T) {
	shortResubscribe(t)
	core, logs := observer.New(zap.DebugLevel)
	main := []netlink.Route{route("fc00:1::/32", "fe80::1", 2), route("fc00:2::/32", "fe80::2", 2)}
	walk := []netip.Addr{netip.MustParseAddr("fc00:1::1")}
	lt := &lockedNeighTable{nt: &fakeNeighTable{entries: map[string]netlink.Neigh{}}}
	k, _ := newFakeKeeper(t, &main, &walk, lt.nt, zap.New(core))
	k.neigh = lt.ops()
	if _, err := k.Sweep(); err != nil {
		t.Fatal(err)
	}
	gw1 := neighKey(2, net.ParseIP("fe80::1"))
	gw2 := neighKey(2, net.ParseIP("fe80::2"))
	has := func(key string) (ok bool) {
		lt.do(func(nt *fakeNeighTable) { _, ok = nt.entries[key] })
		return ok
	}
	if !has(gw1) {
		t.Fatal("the first sweep did not keep the next hop")
	}

	routes, neighs, links := fakeSubs()
	var mu sync.Mutex
	attempts := 0
	release := make(chan struct{})
	var second *neighSub
	k.subNeighs = func() (*neighSub, error) {
		mu.Lock()
		defer mu.Unlock()
		attempts++
		if attempts <= 2 {
			return nil, errors.New("subscribe to neighbour updates: no buffer space available")
		}
		select {
		case <-release:
		default:
			return nil, errors.New("subscribe to neighbour updates: no buffer space available")
		}
		second = &neighSub{updates: make(chan netlink.NeighUpdate, 1), done: make(chan struct{})}
		return second, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() { defer close(stopped); k.watch(ctx, routes, neighs, links) }()
	t.Cleanup(func() { cancel(); <-stopped })

	// The library reports the error that ends a subscription, then closes
	// its channel.
	k.neighSt.OnError(errors.New("no buffer space available"))
	close(neighs.updates)
	waitCond(t, "two failed attempts", func() bool { mu.Lock(); defer mu.Unlock(); return attempts >= 2 })
	select {
	case <-neighs.done:
	default:
		t.Error("the ended subscription was not closed")
	}

	// Down: a write is resolved all the same.
	k.Notify([]netip.Addr{netip.MustParseAddr("fc00:2::1")})
	waitCond(t, "the write resolved while the subscription is down", func() bool { return has(gw2) })

	// An entry deleted while down is made again once the subscription is
	// back.
	lt.do(func(nt *fakeNeighTable) { delete(nt.entries, gw1) })
	close(release)
	waitCond(t, "the deleted entry made again after the resubscribe", func() bool { return has(gw1) })

	count := func(level zapcore.Level, msg string) int {
		return logs.FilterMessage(msg).FilterLevelExact(level).Len()
	}
	if n := count(zap.WarnLevel, "netlink subscription ended; subscribing again; events until then are recovered by a full resync"); n != 1 {
		t.Errorf("end logged %d times, want 1", n)
	}
	if n := count(zap.WarnLevel, "netlink subscription: cannot subscribe; retrying"); n != 1 {
		t.Errorf("the same failure logged %d times, want 1", n)
	}
	if n := count(zap.InfoLevel, "netlink subscription restored; resyncing"); n != 1 {
		t.Errorf("recovery logged %d times, want 1", n)
	}
	for _, e := range logs.FilterMessage("netlink subscription ended; subscribing again; events until then are recovered by a full resync").All() {
		if got := e.ContextMap()["error"]; got != "no buffer space available" {
			t.Errorf("the end is logged with error %v, want the one that ended it", got)
		}
	}

	// A message the library skips (a userspace sender) is not a warning.
	before := len(logs.FilterLevelExact(zap.WarnLevel).All())
	k.neighSt.OnError(errors.New("Wrong sender portid 2848495606, expected 0"))
	if after := len(logs.FilterLevelExact(zap.WarnLevel).All()); after != before {
		t.Error("a skipped message was logged as a warning")
	}
}

// When the link subscription comes back, every device up with its carrier
// counts as having got it back: an unresolved managed entry on one is marked
// again, as a carrier-up event would have.
func TestEncapNeighKeeperLinkResubscribeResyncsCarrier(t *testing.T) {
	shortResubscribe(t)
	main := []netlink.Route{route("fc00:1::/32", "fe80::1", 2)}
	walk := []netip.Addr{netip.MustParseAddr("fc00:1::1")}
	lt := &lockedNeighTable{nt: &fakeNeighTable{entries: map[string]netlink.Neigh{}}}
	k, _ := newFakeKeeper(t, &main, &walk, lt.nt, zap.NewNop())
	k.neigh = lt.ops()
	if _, err := k.Sweep(); err != nil {
		t.Fatal(err)
	}
	gw := neighKey(2, net.ParseIP("fe80::1"))
	sets := func() (n int) {
		lt.do(func(nt *fakeNeighTable) {
			for _, s := range nt.sets {
				if s == gw {
					n++
				}
			}
		})
		return n
	}
	// The entry failed while the carrier was gone.
	lt.do(func(nt *fakeNeighTable) {
		e := nt.entries[gw]
		e.State = netlink.NUD_FAILED
		nt.entries[gw] = e
	})
	base := sets()
	k.linkList = func() ([]netlink.Link, error) {
		return []netlink.Link{&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 2, RawFlags: unix.IFF_UP | unix.IFF_LOWER_UP}}}, nil
	}
	subs := make(chan *linkSub, 1)
	k.subLinks = func() (*linkSub, error) {
		s := &linkSub{updates: make(chan netlink.LinkUpdate, 1), done: make(chan struct{})}
		subs <- s
		return s, nil
	}
	routes, neighs, links := fakeSubs()
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() { defer close(stopped); k.watch(ctx, routes, neighs, links) }()
	t.Cleanup(func() { cancel(); <-stopped })

	close(links.updates)
	select {
	case <-subs:
	case <-time.After(5 * time.Second):
		t.Fatal("the keeper did not subscribe to link updates again")
	}
	waitCond(t, "the failed entry marked again after the resubscribe", func() bool { return sets() > base })
}
