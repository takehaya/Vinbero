package netlinkwatch

import (
	"errors"
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
	created   []string           // mac.String() of each CreateFdb
	deleted   []string           // mac.String() of each DeleteFdb
	createErr error              // when set, CreateFdb fails (dataplane sync failure)
	aged      []bpf.AgedFdbEntry // returned by AgeFdbEntries (the entries it removed)
}

func (f *fakeFdbMapOps) CreateFdb(bdID uint16, mac net.HardwareAddr, _ *bpf.FdbEntry) error {
	if f.createErr != nil {
		return f.createErr
	}
	f.created = append(f.created, mac.String())
	return nil
}
func (f *fakeFdbMapOps) DeleteFdb(bdID uint16, mac net.HardwareAddr) error {
	f.deleted = append(f.deleted, mac.String())
	return nil
}
func (f *fakeFdbMapOps) AgeFdbEntries(uint64) ([]bpf.AgedFdbEntry, error) { return f.aged, nil }

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
		// Default to an empty bridge FDB; DumpBridge tests override this.
		neighList: func(int, int) ([]netlink.Neigh, error) { return nil, nil },
		done:      make(chan struct{}),
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

// When the BPF fdb_map sync fails, the MAC must NOT reach the sink: advertising
// an RT2 for a MAC the data plane cannot decap to would blackhole remote traffic.
func TestFDBWatcherSinkSkippedWhenBPFSyncFails(t *testing.T) {
	sink := &fakeMACSink{}
	w, ops := newSinkTestWatcher(sink)
	ops.createErr = errors.New("map full")
	w.handleNeighUpdate(netlink.NeighUpdate{
		Type:  unix.RTM_NEWNEIGH,
		Neigh: netlink.Neigh{Family: unix.AF_BRIDGE, MasterIndex: 10, LinkIndex: 3, HardwareAddr: net.HardwareAddr{0xaa, 0, 0, 0, 0, 1}},
	})
	if len(sink.events) != 0 {
		t.Errorf("a failed BPF sync must not notify the sink, got %+v", sink.events)
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

func TestIsUnicastMAC(t *testing.T) {
	cases := []struct {
		name string
		mac  net.HardwareAddr
		want bool
	}{
		{"unicast", net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}, true},
		{"multicast", net.HardwareAddr{0x01, 0x00, 0x5e, 0, 0, 1}, false},
		{"broadcast", net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, false},
		{"too short", net.HardwareAddr{0xaa, 0xbb, 0xcc}, false},
		{"nil", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isUnicastMAC(c.mac); got != c.want {
				t.Errorf("isUnicastMAC(%v) = %v, want %v", c.mac, got, c.want)
			}
		})
	}
}

func TestDumpBridgeUnregisteredReturnsError(t *testing.T) {
	w, _ := newSinkTestWatcher(&fakeMACSink{})
	if err := w.DumpBridge(99); err == nil { // only ifindex 10 is registered
		t.Error("DumpBridge of an unregistered bridge should return an error")
	}
}

func TestDumpBridgeNilSinkIsNoop(t *testing.T) {
	w, _ := newSinkTestWatcher(nil) // registers bridge ifindex 10, no sink
	if err := w.DumpBridge(10); err != nil {
		t.Errorf("DumpBridge with no sink must be a no-op, got %v", err)
	}
}

// DumpBridge replays only the registered bridge's unicast MACs (MasterIndex
// filter), and syncs each into the BPF fdb_map before advertising it (the
// gating that prevents advertising a MAC the data plane cannot decap).
func TestDumpBridgeFiltersAndSyncsBeforeAdvertise(t *testing.T) {
	onBridge := net.HardwareAddr{0xaa, 0, 0, 0, 0, 1}     // ifindex 10 (registered) -> replayed
	otherBridge := net.HardwareAddr{0xaa, 0, 0, 0, 0, 2}  // ifindex 20 -> filtered out
	multicast := net.HardwareAddr{0x01, 0, 0x5e, 0, 0, 9} // ifindex 10 but multicast -> skipped

	sink := &fakeMACSink{}
	w, ops := newSinkTestWatcher(sink)
	w.neighList = func(int, int) ([]netlink.Neigh, error) {
		return []netlink.Neigh{
			{Family: unix.AF_BRIDGE, MasterIndex: 10, LinkIndex: 3, HardwareAddr: onBridge},
			{Family: unix.AF_BRIDGE, MasterIndex: 20, LinkIndex: 4, HardwareAddr: otherBridge},
			{Family: unix.AF_BRIDGE, MasterIndex: 10, LinkIndex: 3, HardwareAddr: multicast},
		}, nil
	}
	if err := w.DumpBridge(10); err != nil {
		t.Fatalf("DumpBridge: %v", err)
	}

	// Only the registered bridge's unicast MAC is synced + advertised.
	if len(ops.created) != 1 || ops.created[0] != onBridge.String() {
		t.Errorf("only the registered bridge's unicast MAC should sync to BPF, got %v", ops.created)
	}
	if len(sink.events) != 1 {
		t.Fatalf("only the registered bridge's unicast MAC should advertise, got %+v", sink.events)
	}
	ev := sink.events[0]
	if ev.bdID != 100 || ev.mac != onBridge.String() || !ev.added {
		t.Errorf("replayed event = %+v, want bd 100 add of %s", ev, onBridge)
	}
}

// DumpBridge must not advertise a MAC whose BPF fdb_map sync fails (the data
// plane cannot decap it), the same gating the live path applies.
func TestDumpBridgeSkipsAdvertiseWhenSyncFails(t *testing.T) {
	sink := &fakeMACSink{}
	w, ops := newSinkTestWatcher(sink)
	ops.createErr = errors.New("map full")
	w.neighList = func(int, int) ([]netlink.Neigh, error) {
		return []netlink.Neigh{
			{Family: unix.AF_BRIDGE, MasterIndex: 10, LinkIndex: 3, HardwareAddr: net.HardwareAddr{0xaa, 0, 0, 0, 0, 1}},
		}, nil
	}
	if err := w.DumpBridge(10); err != nil {
		t.Fatalf("DumpBridge: %v", err)
	}
	if len(sink.events) != 0 {
		t.Errorf("a MAC whose BPF sync fails must not advertise, got %+v", sink.events)
	}
}

// The aging pass withdraws RT2 for each aged locally-learned MAC (so an
// aging-removed entry does not stay advertised with no data-plane entry), but
// not for EVPN-received (remote) entries, which were never advertised.
func TestAgeAndWithdrawWithdrawsLocalNotRemote(t *testing.T) {
	local := net.HardwareAddr{0xaa, 0, 0, 0, 0, 1}
	remote := net.HardwareAddr{0xaa, 0, 0, 0, 0, 2}
	sink := &fakeMACSink{}
	w, ops := newSinkTestWatcher(sink)
	ops.aged = []bpf.AgedFdbEntry{
		{BDID: 100, MAC: local, IsRemote: false},
		{BDID: 100, MAC: remote, IsRemote: true},
	}
	w.ageAndWithdraw(1e9)
	if len(sink.events) != 1 {
		t.Fatalf("only the local aged MAC should be withdrawn, got %+v", sink.events)
	}
	ev := sink.events[0]
	if ev.bdID != 100 || ev.mac != local.String() || ev.added {
		t.Errorf("withdraw event = %+v, want bd 100 delete of %s", ev, local)
	}
}

// A sink added with AddMACSink receives events alongside the primary sink, and
// stops receiving them once its remove func runs.
func TestAddMACSinkFansOutAndRemoves(t *testing.T) {
	primary := &fakeMACSink{}
	w, _ := newSinkTestWatcher(primary)
	extra := &fakeMACSink{}
	remove := w.AddMACSink(extra)

	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02}
	add := netlink.NeighUpdate{
		Type:  unix.RTM_NEWNEIGH,
		Neigh: netlink.Neigh{Family: unix.AF_BRIDGE, MasterIndex: 10, LinkIndex: 3, HardwareAddr: mac},
	}
	w.handleNeighUpdate(add)
	if len(primary.events) != 1 || len(extra.events) != 1 {
		t.Fatalf("fan-out incomplete: primary=%d extra=%d, want 1 each", len(primary.events), len(extra.events))
	}

	remove()
	remove() // idempotent
	w.handleNeighUpdate(add)
	if len(primary.events) != 2 {
		t.Errorf("primary sink stopped receiving after the extra was removed: got %d, want 2", len(primary.events))
	}
	if len(extra.events) != 1 {
		t.Errorf("removed sink still received events: got %d, want 1", len(extra.events))
	}
}

// SetMACSink replaces the primary sink rather than stacking another consumer,
// and clearing it with nil leaves an AddMACSink consumer in place.
func TestSetMACSinkReplacesPrimaryOnly(t *testing.T) {
	first := &fakeMACSink{}
	w, _ := newSinkTestWatcher(first)
	extra := &fakeMACSink{}
	w.AddMACSink(extra)

	second := &fakeMACSink{}
	w.SetMACSink(second)

	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x03}
	add := netlink.NeighUpdate{
		Type:  unix.RTM_NEWNEIGH,
		Neigh: netlink.Neigh{Family: unix.AF_BRIDGE, MasterIndex: 10, LinkIndex: 3, HardwareAddr: mac},
	}
	w.handleNeighUpdate(add)
	if len(first.events) != 0 {
		t.Errorf("replaced primary sink still received events: got %d, want 0", len(first.events))
	}
	if len(second.events) != 1 || len(extra.events) != 1 {
		t.Fatalf("after replace: second=%d extra=%d, want 1 each", len(second.events), len(extra.events))
	}

	w.SetMACSink(nil)
	w.handleNeighUpdate(add)
	if len(second.events) != 1 {
		t.Errorf("cleared primary sink still received events: got %d, want 1", len(second.events))
	}
	if len(extra.events) != 2 {
		t.Errorf("AddMACSink consumer dropped by SetMACSink(nil): got %d, want 2", len(extra.events))
	}
}

// Each sink gets its own copy of the MAC, so one consumer mutating it cannot
// corrupt what the next sees.
func TestMACSinksGetIndependentCopies(t *testing.T) {
	w, _ := newSinkTestWatcher(nil)
	var firstSeen, secondSeen string
	w.AddMACSink(macSinkFunc(func(_ uint16, mac net.HardwareAddr, _ bool) {
		firstSeen = mac.String()
		for i := range mac {
			mac[i] = 0xff // a badly behaved consumer
		}
	}))
	w.AddMACSink(macSinkFunc(func(_ uint16, mac net.HardwareAddr, _ bool) {
		secondSeen = mac.String()
	}))

	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x04}
	w.handleNeighUpdate(netlink.NeighUpdate{
		Type:  unix.RTM_NEWNEIGH,
		Neigh: netlink.Neigh{Family: unix.AF_BRIDGE, MasterIndex: 10, LinkIndex: 3, HardwareAddr: mac},
	})
	if firstSeen != mac.String() || secondSeen != mac.String() {
		t.Fatalf("sinks saw %q and %q, want %q for both", firstSeen, secondSeen, mac)
	}
}

// macSinkFunc adapts a func to the MACSink interface.
type macSinkFunc func(bdID uint16, mac net.HardwareAddr, added bool)

func (f macSinkFunc) OnLocalMAC(bdID uint16, mac net.HardwareAddr, added bool) { f(bdID, mac, added) }
