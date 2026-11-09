package netlinkwatch

import (
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// chanFdbEvents is an FdbEventSource fed by the test.
type chanFdbEvents struct {
	ch     chan bpf.FdbEvent
	once   sync.Once
	closed chan struct{}
}

func newChanFdbEvents() *chanFdbEvents {
	return &chanFdbEvents{ch: make(chan bpf.FdbEvent, 8), closed: make(chan struct{})}
}

func (c *chanFdbEvents) Read() (bpf.FdbEvent, error) {
	select {
	case ev := <-c.ch:
		return ev, nil
	case <-c.closed:
		return bpf.FdbEvent{}, bpf.ErrFdbEventsClosed
	}
}

func (c *chanFdbEvents) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

// syncSink is a MACSink safe to read while the event goroutine writes it.
type syncSink struct {
	mu     sync.Mutex
	events []macEvent
}

func (s *syncSink) OnLocalMAC(bdID uint16, mac net.HardwareAddr, added bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, macEvent{bdID: bdID, mac: mac.String(), added: added})
}

func (s *syncSink) snapshot() []macEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]macEvent(nil), s.events...)
}

func xdpBD100(bd uint16) bool { return bd == 100 }

func TestFDBWatcherXDPEventsReachTheSink(t *testing.T) {
	sink := &syncSink{}
	w, ops := newSinkTestWatcher(sink)
	w.SetXDPLearnedBDs(xdpBD100)
	src := newChanFdbEvents()
	w.StartXDPEvents(src)
	defer w.Stop()

	mac := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x01}
	src.ch <- bpf.FdbEvent{BdID: 100, MAC: mac, Oif: 3, Kind: bpf.FdbEventAdd}
	src.ch <- bpf.FdbEvent{BdID: 100, MAC: net.HardwareAddr{0x01, 0, 0x5e, 0, 0, 1}, Oif: 3, Kind: bpf.FdbEventAdd} // multicast: dropped
	src.ch <- bpf.FdbEvent{BdID: 100, MAC: mac, Oif: 4, Kind: bpf.FdbEventMove}

	deadline := time.Now().Add(2 * time.Second)
	for len(sink.snapshot()) < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	got := sink.snapshot()
	want := macEvent{bdID: 100, mac: mac.String(), added: true}
	if len(got) != 2 || got[0] != want || got[1] != want {
		t.Fatalf("sink events = %+v, want two adds of %s", got, mac)
	}
	if len(ops.created) != 0 {
		t.Errorf("XDP events must not write fdb_map (the data plane did), got %v", ops.created)
	}
}

func TestFDBWatcherIgnoresBridgeEventsOfXDPBDs(t *testing.T) {
	sink := &fakeMACSink{}
	w, ops := newSinkTestWatcher(sink) // bridge 10 -> bd 100
	w.SetXDPLearnedBDs(xdpBD100)
	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}
	for _, typ := range []uint16{unix.RTM_NEWNEIGH, unix.RTM_DELNEIGH} {
		w.handleNeighUpdate(netlink.NeighUpdate{
			Type:  typ,
			Neigh: netlink.Neigh{Family: unix.AF_BRIDGE, MasterIndex: 10, LinkIndex: 3, HardwareAddr: mac},
		})
	}
	if len(sink.events) != 0 || len(ops.created) != 0 || len(ops.deleted) != 0 {
		t.Fatalf("bridge FDB events of an xdp-mode BD must be ignored: sink=%v created=%v deleted=%v",
			sink.events, ops.created, ops.deleted)
	}
}

func TestFDBWatcherXDPReplayAndReconcile(t *testing.T) {
	sink := &fakeMACSink{}
	w, ops := newSinkTestWatcher(sink)
	w.SetXDPLearnedBDs(xdpBD100)
	learned := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x01}
	other := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x02}
	ops.local = map[uint16][]net.HardwareAddr{100: {learned}, 200: {other}}
	// The kernel bridge knows nothing for an xdp-mode BD.
	w.neighList = func(int, int) ([]netlink.Neigh, error) {
		t.Fatal("DumpBridge must not read the kernel bridge FDB of an xdp-mode BD")
		return nil, nil
	}

	if err := w.DumpBridge(10); err != nil {
		t.Fatalf("DumpBridge: %v", err)
	}
	want := macEvent{bdID: 100, mac: learned.String(), added: true}
	if len(sink.events) != 1 || sink.events[0] != want {
		t.Fatalf("replay = %+v, want %+v", sink.events, want)
	}

	// The aging tick re-announces XDP-learned MACs of xdp-mode BDs only (a
	// ring buffer overflow may have lost the original event).
	sink.events = nil
	w.ageAndWithdraw(uint64(time.Hour))
	if len(sink.events) != 1 || sink.events[0] != want {
		t.Fatalf("reconcile = %+v, want %+v", sink.events, want)
	}
}

// Without fdb_aging_seconds the xdp-mode BDs still age their local MACs
// (the bridge would have, in tc mode) and reconcile; other BDs and remote
// entries are untouched.
func TestFDBWatcherXDPAgingWithoutAgingSeconds(t *testing.T) {
	sink := &fakeMACSink{}
	w, ops := newSinkTestWatcher(sink)
	w.SetXDPLearnedBDs(xdpBD100)
	stale := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x01}
	kept := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x02}
	ops.aged = []bpf.AgedFdbEntry{
		{BDID: 100, MAC: stale},
		{BDID: 100, MAC: net.HardwareAddr{0x02, 0, 0, 0, 0, 0x03}, IsRemote: true},
		{BDID: 200, MAC: net.HardwareAddr{0x02, 0, 0, 0, 0, 0x04}},
	}
	ops.local = map[uint16][]net.HardwareAddr{100: {kept}}

	w.ageXDPLocal(uint64(xdpAgingDefault))
	want := []macEvent{
		{bdID: 100, mac: stale.String(), added: false},
		{bdID: 100, mac: kept.String(), added: true},
	}
	if !slices.Equal(sink.events, want) {
		t.Fatalf("events = %+v, want %+v", sink.events, want)
	}
}
