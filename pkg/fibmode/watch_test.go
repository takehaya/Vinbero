package fibmode

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/takehaya/vinbero/pkg/netlinksub"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"golang.org/x/sys/unix"
)

// fakeMaps records what the watcher writes.
type fakeMaps struct {
	mu       sync.Mutex
	v4, v6   bool
	local4   []netip.Addr
	ops      []string
	failMode bool
}

func (m *fakeMaps) SetFibGlobalMode(v4, v6 bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failMode && (v4 || v6) {
		return errors.New("map write refused")
	}
	m.v4, m.v6 = v4, v6
	m.ops = append(m.ops, fmt.Sprintf("mode %v %v", v4, v6))
	return nil
}

func (m *fakeMaps) SyncFibLocal(v4, v6 []netip.Addr) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.local4 = slices.Clone(v4)
	m.ops = append(m.ops, fmt.Sprintf("local %d %d", len(v4), len(v6)))
	return nil
}

func (m *fakeMaps) mode() (bool, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.v4, m.v6
}

// fakeNS is the namespace the watcher reads and the subscriptions it opens.
type fakeNS struct {
	mu       sync.Mutex
	snap     *Snapshot
	readErr  error
	reads    int
	subs     []chan []syscall.NetlinkMessage
	closed   int
	failSubs int
}

func (f *fakeNS) read() (*Snapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	if f.readErr != nil {
		return nil, f.readErr
	}
	s := *f.snap
	return &s, nil
}

func (f *fakeNS) subscribe(*netlinksub.State) (<-chan []syscall.NetlinkMessage, func(), error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failSubs > 0 {
		f.failSubs--
		return nil, nil, errors.New("subscribe refused")
	}
	ch := make(chan []syscall.NetlinkMessage, 16)
	f.subs = append(f.subs, ch)
	return ch, func() {
		f.mu.Lock()
		f.closed++
		f.mu.Unlock()
	}, nil
}

func (f *fakeNS) readCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reads
}

func (f *fakeNS) current() chan []syscall.NetlinkMessage {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.subs[len(f.subs)-1]
}

func (f *fakeNS) set(s *Snapshot) {
	f.mu.Lock()
	f.snap = s
	f.mu.Unlock()
}

func eligible() *Snapshot { return &Snapshot{Rules: defaultRules(), Routes: baseRoutes()} }

func withCustom(family int) *Snapshot {
	s := eligible()
	s.Rules = append(slices.Clone(s.Rules), Rule{Family: family, Priority: 100, Table: 200})
	return s
}

func fastTimers(t *testing.T) {
	minD, maxD, settle := netlinksub.MinDelay, netlinksub.MaxDelay, Settle
	netlinksub.MinDelay, netlinksub.MaxDelay, Settle = 5*time.Millisecond, 20*time.Millisecond, 10*time.Millisecond
	t.Cleanup(func() { netlinksub.MinDelay, netlinksub.MaxDelay, Settle = minD, maxD, settle })
}

func startWatcher(t *testing.T, f *fakeNS, m *fakeMaps) (*observer.ObservedLogs, func()) {
	t.Helper()
	fastTimers(t)
	core, logs := observer.New(zap.InfoLevel)
	w := New(m, zap.New(core))
	w.read, w.subscribe = f.read, f.subscribe
	if err := w.setMode(false, false); err != nil {
		t.Fatal(err)
	}
	quit := make(chan struct{})
	done := make(chan struct{})
	go func() { defer close(done); w.run(quit) }()
	stop := func() {
		close(quit)
		<-done
	}
	t.Cleanup(func() {
		select {
		case <-done:
		default:
			stop()
		}
	})
	return logs, stop
}

func waitMode(t *testing.T, m *fakeMaps, v4, v6 bool, what string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if a, b := m.mode(); a == v4 && b == v6 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	a, b := m.mode()
	t.Fatalf("%s: mode IPv4=%v IPv6=%v, want %v %v", what, a, b, v4, v6)
}

func ruleEvent(family uint8) []syscall.NetlinkMessage {
	return []syscall.NetlinkMessage{{
		Header: syscall.NlMsghdr{Type: unix.RTM_NEWRULE},
		Data:   kernelRule(family, 100, 200),
	}}
}

func routeEvent(family uint8, table uint8, typ uint8) []syscall.NetlinkMessage {
	b := make([]byte, rtMsgLen)
	b[0], b[4], b[7] = family, table, typ
	return []syscall.NetlinkMessage{{Header: syscall.NlMsghdr{Type: unix.RTM_NEWROUTE}, Data: b}}
}

func TestWatcherFollowsTheNamespace(t *testing.T) {
	f := &fakeNS{snap: eligible()}
	m := &fakeMaps{}
	logs, stop := startWatcher(t, f, m)
	waitMode(t, m, true, true, "eligible namespace")

	// A rule is added: IPv4 leaves the direct mode at once, before the
	// namespace is read again; IPv6 keeps it.
	f.set(withCustom(unix.AF_INET))
	f.current() <- ruleEvent(unix.AF_INET)
	waitMode(t, m, false, true, "custom IPv4 rule")
	// After the read the decision stands.
	time.Sleep(5 * Settle)
	if a, b := m.mode(); a || !b {
		t.Fatalf("after the read: IPv4=%v IPv6=%v, want false true", a, b)
	}
	// The rule is removed: back to the direct mode once read again.
	f.set(eligible())
	f.current() <- ruleEvent(unix.AF_INET)
	waitMode(t, m, true, true, "custom rule removed")

	// A route change in the main table is not relevant.
	reads := f.readCount()
	f.current() <- routeEvent(unix.AF_INET, unix.RT_TABLE_MAIN, unix.RTN_UNICAST)
	time.Sleep(5 * Settle)
	if f.readCount() != reads {
		t.Errorf("a main-table route made the watcher read the namespace again")
	}
	// A route in the local table is: the family leaves the direct mode.
	f.current() <- routeEvent(unix.AF_INET6, unix.RT_TABLE_LOCAL, unix.RTN_LOCAL)
	deadline := time.Now().Add(2 * time.Second)
	for f.readCount() == reads {
		if time.Now().After(deadline) {
			t.Fatal("a local-table route did not make the watcher read again")
		}
		time.Sleep(time.Millisecond)
	}
	waitMode(t, m, true, true, "after a local-table change")

	// The subscription ends: both families take the full lookup until it
	// is back and the namespace is read again.
	f.mu.Lock()
	f.failSubs = 2
	f.mu.Unlock()
	close(f.current())
	waitMode(t, m, false, false, "subscription ended")
	waitMode(t, m, true, true, "subscription back")
	if n := logs.FilterMessage("netlink subscription ended; subscribing again; events until then are recovered by a full resync").Len(); n != 1 {
		t.Errorf("%d warnings for the ended subscription, want 1", n)
	}

	// The namespace cannot be read: full lookup until a read works.
	f.mu.Lock()
	f.readErr = errors.New("dump interrupted")
	f.mu.Unlock()
	f.current() <- ruleEvent(unix.AF_INET6)
	waitMode(t, m, false, false, "read failed")
	f.mu.Lock()
	f.readErr = nil
	f.mu.Unlock()
	waitMode(t, m, true, true, "read retried")

	stop()
	if a, b := m.mode(); a || b {
		t.Errorf("after stop: IPv4=%v IPv6=%v, want the full lookup", a, b)
	}
}

func TestWatcherWithoutSubscriptionStaysFull(t *testing.T) {
	f := &fakeNS{snap: eligible(), failSubs: 1 << 30}
	m := &fakeMaps{}
	startWatcher(t, f, m)
	time.Sleep(20 * Settle)
	if a, b := m.mode(); a || b {
		t.Fatalf("no subscription: IPv4=%v IPv6=%v, want the full lookup", a, b)
	}
	if f.readCount() != 0 {
		t.Errorf("read the namespace %d times without a subscription", f.readCount())
	}
}

func TestWatcherLocalChangeLeavesDirectFirst(t *testing.T) {
	f := &fakeNS{snap: eligible()}
	m := &fakeMaps{}
	startWatcher(t, f, m)
	waitMode(t, m, true, true, "eligible namespace")
	s := eligible()
	s.Routes = append(slices.Clone(s.Routes), host("192.0.2.77"))
	f.set(s)
	m.mu.Lock()
	m.ops = nil
	m.mu.Unlock()
	f.current() <- routeEvent(unix.AF_INET6, unix.RT_TABLE_LOCAL, unix.RTN_LOCAL) // any relevant event
	deadline := time.Now().Add(2 * time.Second)
	for {
		m.mu.Lock()
		n := len(m.local4)
		ops := slices.Clone(m.ops)
		m.mu.Unlock()
		if n == 4 {
			// The IPv4 map changed only while IPv4 was off.
			want := []string{"mode true false", "mode false false", "local 4 2", "mode true true"}
			if !slices.Equal(ops, want) {
				t.Fatalf("writes %v, want %v", ops, want)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the new local address never reached the map; writes %v", ops)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestWatcherMapWriteFails(t *testing.T) {
	f := &fakeNS{snap: eligible()}
	m := &fakeMaps{failMode: true}
	startWatcher(t, f, m)
	time.Sleep(20 * Settle)
	if a, b := m.mode(); a || b {
		t.Fatalf("map refuses the direct mode: IPv4=%v IPv6=%v", a, b)
	}
	m.mu.Lock()
	m.failMode = false
	m.mu.Unlock()
	waitMode(t, m, true, true, "map writable again")
}
