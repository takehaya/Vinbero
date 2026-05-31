package netlinkwatch

import (
	"net"
	"testing"

	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// fakeFdbMapOps records FDB writes without a live BPF map (the MAC string of
// each create/delete).
type fakeFdbMapOps struct {
	created []string // mac.String() of each CreateFdb
	deleted []string // mac.String() of each DeleteFdb
}

func (f *fakeFdbMapOps) CreateFdb(bdID uint16, mac net.HardwareAddr, _ *bpf.FdbEntry) error {
	f.created = append(f.created, mac.String())
	return nil
}
func (f *fakeFdbMapOps) DeleteFdb(bdID uint16, mac net.HardwareAddr) error {
	f.deleted = append(f.deleted, mac.String())
	return nil
}
func (f *fakeFdbMapOps) AgeFdbEntries(uint64) (int, error) { return 0, nil }

type macEvent struct {
	bdID  uint16
	mac   string
	added bool
}

type fakeMACSink struct {
	events []macEvent
}

func (f *fakeMACSink) OnLocalMAC(bdID uint16, mac net.HardwareAddr, added bool) {
	f.events = append(f.events, macEvent{bdID: bdID, mac: mac.String(), added: added})
}

func newSinkTestWatcher(sink MACSink) (*FDBWatcher, *fakeFdbMapOps) {
	ops := &fakeFdbMapOps{}
	w := &FDBWatcher{
		mapOps:  ops,
		logger:  zap.NewNop(),
		allowed: make(map[int]uint16),
		done:    make(chan struct{}),
	}
	w.RegisterBridge(10, 100) // bridge ifindex 10 -> bd_id 100
	w.SetMACSink(sink)
	return w, ops
}

// A local MAC add/delete on a registered bridge is forwarded to the MAC sink for
// EVPN RT2 auto-advertise, with the right bd_id and add/delete flag.
func TestFDBWatcherForwardsLocalMACToSink(t *testing.T) {
	sink := &fakeMACSink{}
	w, _ := newSinkTestWatcher(sink)
	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}

	w.handleNeighUpdate(netlink.NeighUpdate{
		Type:  unix.RTM_NEWNEIGH,
		Neigh: netlink.Neigh{Family: unix.AF_BRIDGE, MasterIndex: 10, LinkIndex: 3, HardwareAddr: mac},
	})
	w.handleNeighUpdate(netlink.NeighUpdate{
		Type:  unix.RTM_DELNEIGH,
		Neigh: netlink.Neigh{Family: unix.AF_BRIDGE, MasterIndex: 10, LinkIndex: 3, HardwareAddr: mac},
	})

	if len(sink.events) != 2 {
		t.Fatalf("want 2 sink events (add+del), got %d: %+v", len(sink.events), sink.events)
	}
	if e := sink.events[0]; e.bdID != 100 || e.mac != mac.String() || !e.added {
		t.Errorf("add event = %+v, want {100, %s, true}", e, mac)
	}
	if e := sink.events[1]; e.bdID != 100 || e.mac != mac.String() || e.added {
		t.Errorf("del event = %+v, want {100, %s, false}", e, mac)
	}
}

// A MAC on a bridge that is not registered is dropped before reaching the sink.
func TestFDBWatcherSinkIgnoresUnregisteredBridge(t *testing.T) {
	sink := &fakeMACSink{}
	w, _ := newSinkTestWatcher(sink)
	w.handleNeighUpdate(netlink.NeighUpdate{
		Type:  unix.RTM_NEWNEIGH,
		Neigh: netlink.Neigh{Family: unix.AF_BRIDGE, MasterIndex: 99, LinkIndex: 3, HardwareAddr: net.HardwareAddr{0xaa, 0, 0, 0, 0, 1}},
	})
	if len(sink.events) != 0 {
		t.Errorf("a MAC on an unregistered bridge must not reach the sink, got %+v", sink.events)
	}
}

// A nil sink (EVPN auto-advertise off) must not panic; the BPF sync still runs.
func TestFDBWatcherNilSinkStillSyncsBPF(t *testing.T) {
	w, ops := newSinkTestWatcher(nil)
	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02}
	w.handleNeighUpdate(netlink.NeighUpdate{
		Type:  unix.RTM_NEWNEIGH,
		Neigh: netlink.Neigh{Family: unix.AF_BRIDGE, MasterIndex: 10, LinkIndex: 3, HardwareAddr: mac},
	})
	if len(ops.created) != 1 {
		t.Errorf("BPF sync must still run with a nil sink, got %+v", ops.created)
	}
}
