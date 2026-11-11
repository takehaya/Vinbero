package netlinkwatch

import (
	"context"
	"net"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// inTestNetns runs the test on its thread in a fresh network namespace.
// Needs root.
func inTestNetns(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root (network namespace)")
	}
	runtime.LockOSThread()
	orig, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	created, err := netns.New()
	if err != nil {
		_ = orig.Close()
		runtime.UnlockOSThread()
		t.Skipf("cannot create a network namespace: %v", err)
	}
	t.Cleanup(func() {
		_ = netns.Set(orig)
		_ = orig.Close()
		_ = created.Close()
		runtime.UnlockOSThread()
	})
}

// senderErrors records the "Wrong sender portid" errors of a subscription:
// the messages a userspace process sent to its group.
type senderErrors struct {
	mu   sync.Mutex
	errs []string
}

func (s *senderErrors) callback(err error) {
	if strings.Contains(err.Error(), "Wrong sender portid") {
		s.mu.Lock()
		s.errs = append(s.errs, err.Error())
		s.mu.Unlock()
	}
}

func (s *senderErrors) get() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.errs)
}

// lockedFdbMapOps is fakeFdbMapOps for a watcher whose updates arrive on
// another goroutine.
type lockedFdbMapOps struct {
	mu sync.Mutex
	*fakeFdbMapOps
}

func (l *lockedFdbMapOps) LearnFdb(bdID uint16, mac net.HardwareAddr, link uint32) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.fakeFdbMapOps.LearnFdb(bdID, mac, link)
}

func (l *lockedFdbMapOps) DeleteLearnedFdb(bdID uint16, mac net.HardwareAddr, link uint32) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.fakeFdbMapOps.DeleteLearnedFdb(bdID, mac, link)
}

func (l *lockedFdbMapOps) learned() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.created)
}

// The FDB watcher's replay of the existing FDB reaches its bridges, and no
// other subscriber of the neighbour group receives its request. Through the
// library's ListExisting, the dump requests went out from the subscribed
// socket addressed to the group, and the kernel delivered them to every
// other subscriber, which then reported "Wrong sender portid".
func TestFDBWatcherReplayReachesNoOtherSubscriber(t *testing.T) {
	inTestNetns(t)
	br := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: "fdbmc-br"}}
	if err := netlink.LinkAdd(br); err != nil {
		t.Fatalf("add bridge: %v", err)
	}
	port := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "fdbmc-p"}}
	if err := netlink.LinkAdd(port); err != nil {
		t.Fatalf("add port: %v", err)
	}
	if err := netlink.LinkSetMaster(port, br); err != nil {
		t.Fatal(err)
	}
	for _, l := range []netlink.Link{br, port} {
		if err := netlink.LinkSetUp(l); err != nil {
			t.Fatal(err)
		}
	}
	brLink, _ := netlink.LinkByName("fdbmc-br")
	portLink, _ := netlink.LinkByName("fdbmc-p")
	mac := net.HardwareAddr{0x02, 0, 0, 0, 0x77, 0x01}
	if err := netlink.NeighAppend(&netlink.Neigh{
		LinkIndex: portLink.Attrs().Index, Family: unix.AF_BRIDGE,
		State: netlink.NUD_NOARP, Flags: netlink.NTF_MASTER, HardwareAddr: mac,
	}); err != nil {
		t.Fatalf("add the FDB entry: %v", err)
	}

	// Another subscriber of the neighbour group, as the next-hop keeper is.
	other := &senderErrors{}
	ch := make(chan netlink.NeighUpdate, 256)
	done := make(chan struct{})
	if err := netlink.NeighSubscribeWithOptions(ch, done, netlink.NeighSubscribeOptions{ErrorCallback: other.callback}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { close(done); go drain(ch) })
	go drain(ch)

	ops := &lockedFdbMapOps{fakeFdbMapOps: &fakeFdbMapOps{}}
	w := &FDBWatcher{
		mapOps:    ops,
		logger:    zap.NewNop(),
		allowed:   make(map[int]uint16),
		neighList: netlink.NeighList,
		subscribe: netlink.NeighSubscribeWithOptions,
		done:      make(chan struct{}),
	}
	w.RegisterBridge(brLink.Attrs().Index, 100)
	if err := w.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer w.Stop()

	deadline := time.Now().Add(5 * time.Second)
	for !slices.Contains(ops.learned(), mac.String()) {
		if time.Now().After(deadline) {
			t.Fatalf("the replay did not reach the bridge's MAC: learned %v", ops.learned())
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(500 * time.Millisecond) // a request still on its way
	if errs := other.get(); len(errs) != 0 {
		t.Errorf("another subscriber of the neighbour group received the watcher's request: %v", errs)
	}
}

type lockedSink struct {
	mu    sync.Mutex
	calls []sinkCall
}

func (s *lockedSink) OnRoute(table uint32, prefix netip.Prefix, added bool) {
	s.mu.Lock()
	s.calls = append(s.calls, sinkCall{table: table, prefix: prefix, added: added})
	s.mu.Unlock()
}

func (s *lockedSink) get() []sinkCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.calls)
}

// The route watcher's replay of the existing routes reaches its sink, and no
// other subscriber of the route groups receives its request.
func TestRouteWatcherReplayReachesNoOtherSubscriber(t *testing.T) {
	inTestNetns(t)
	dev := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "rtmc0"}}
	if err := netlink.LinkAdd(dev); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(dev); err != nil {
		t.Fatal(err)
	}
	l, _ := netlink.LinkByName("rtmc0")
	_, dst, _ := net.ParseCIDR("10.77.0.0/24")
	if err := netlink.RouteAdd(&netlink.Route{Table: 100, Dst: dst, LinkIndex: l.Attrs().Index, Protocol: unix.RTPROT_STATIC}); err != nil {
		t.Fatalf("add the route: %v", err)
	}

	// Another subscriber of the route groups, as the next-hop keeper is.
	other := &senderErrors{}
	ch := make(chan netlink.RouteUpdate, 256)
	done := make(chan struct{})
	if err := netlink.RouteSubscribeWithOptions(ch, done, netlink.RouteSubscribeOptions{ErrorCallback: other.callback}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { close(done); go drain(ch) })
	go drain(ch)

	sink := &lockedSink{}
	w := NewRouteWatcher(sink, zap.NewNop())
	if err := w.RegisterTable(100, []string{"static"}); err != nil {
		t.Fatal(err)
	}
	if err := w.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer w.Stop()

	want := sinkCall{table: 100, prefix: netip.MustParsePrefix("10.77.0.0/24"), added: true}
	deadline := time.Now().Add(5 * time.Second)
	for !slices.Contains(sink.get(), want) {
		if time.Now().After(deadline) {
			t.Fatalf("the replay did not deliver the table's route: %v", sink.get())
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(500 * time.Millisecond) // a request still on its way
	if errs := other.get(); len(errs) != 0 {
		t.Errorf("another subscriber of the route groups received the watcher's request: %v", errs)
	}
}
