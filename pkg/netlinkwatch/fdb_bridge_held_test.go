package netlinkwatch

import (
	"errors"
	"net"
	"slices"
	"testing"

	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var (
	ownMAC    = net.HardwareAddr{0xaa, 0, 0, 0, 0, 1} // the address of ifindex 3
	pinnedMAC = net.HardwareAddr{0xaa, 0, 0, 0, 0, 2}
	otherMAC  = net.HardwareAddr{0xaa, 0, 0, 0, 0, 3}
)

func bridgeEntry(mac net.HardwareAddr, state int) netlink.Neigh {
	return netlink.Neigh{Family: unix.AF_BRIDGE, MasterIndex: 10, LinkIndex: 3, HardwareAddr: mac, State: state}
}

func bridgeUpdate(typ uint16, mac net.HardwareAddr, state int) netlink.NeighUpdate {
	return netlink.NeighUpdate{Type: typ, Neigh: bridgeEntry(mac, state)}
}

func newBridgeTestWatcher(t *testing.T, neighs ...netlink.Neigh) (*FDBWatcher, *fakeFdbMapOps, *fakeMACSink) {
	t.Helper()
	sink := &fakeMACSink{}
	w, ops := newSinkTestWatcher(sink)
	w.deviceAddr = func(int) (net.HardwareAddr, error) { return ownMAC, nil }
	w.neighList = func(int, int) ([]netlink.Neigh, error) { return neighs, nil }
	return w, ops, sink
}

func addsOf(sink *fakeMACSink) []string {
	var out []string
	for _, e := range sink.events {
		if e.added {
			out = append(out, e.mac)
		}
	}
	return out
}

// A device's own address is synced to fdb_map but not advertised, on the live
// path and on replay, and a permanent entry an operator pins on a port is
// advertised.
func TestBridgePermanentEntries(t *testing.T) {
	w, ops, sink := newBridgeTestWatcher(t)
	w.handleNeighUpdate(bridgeUpdate(unix.RTM_NEWNEIGH, ownMAC, netlink.NUD_PERMANENT))
	if !slices.Contains(ops.created, ownMAC.String()) {
		t.Errorf("a device address must still reach fdb_map, created = %v", ops.created)
	}
	if got := addsOf(sink); len(got) != 0 {
		t.Errorf("a device address must not be advertised, got %v", got)
	}

	w, ops, sink = newBridgeTestWatcher(t, bridgeEntry(ownMAC, netlink.NUD_PERMANENT))
	if err := w.DumpBridge(10); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(ops.created, ownMAC.String()) || len(addsOf(sink)) != 0 {
		t.Errorf("replay: created = %v, events = %+v", ops.created, sink.events)
	}

	w, _, sink = newBridgeTestWatcher(t)
	w.handleNeighUpdate(bridgeUpdate(unix.RTM_NEWNEIGH, pinnedMAC, netlink.NUD_PERMANENT))
	if got := addsOf(sink); len(got) != 1 || got[0] != pinnedMAC.String() {
		t.Errorf("an operator-pinned MAC should be advertised, got %v", got)
	}

	// A foreign MAC on the bridge device itself goes nowhere the data plane
	// can deliver it, so it is not advertised either.
	w, _, sink = newBridgeTestWatcher(t)
	onBridge := bridgeEntry(pinnedMAC, netlink.NUD_PERMANENT)
	onBridge.LinkIndex = onBridge.MasterIndex
	w.handleNeighUpdate(netlink.NeighUpdate{Type: unix.RTM_NEWNEIGH, Neigh: onBridge})
	if got := addsOf(sink); len(got) != 0 {
		t.Errorf("a MAC on the bridge device must not be advertised, got %v", got)
	}
}

// Only a device that no longer exists counts as a device address; any other
// lookup failure leaves a pinned MAC advertised.
func TestDeviceAddressLookupErrors(t *testing.T) {
	w, _, sink := newBridgeTestWatcher(t)
	w.deviceAddr = func(int) (net.HardwareAddr, error) { return nil, errors.New("boom") }
	w.handleNeighUpdate(bridgeUpdate(unix.RTM_NEWNEIGH, pinnedMAC, netlink.NUD_PERMANENT))
	if got := addsOf(sink); len(got) != 1 {
		t.Errorf("a failed lookup withdrew a pinned MAC: %+v", sink.events)
	}

	w, _, sink = newBridgeTestWatcher(t)
	w.deviceAddr = func(int) (net.HardwareAddr, error) { return nil, netlink.LinkNotFoundError{} }
	w.handleNeighUpdate(bridgeUpdate(unix.RTM_NEWNEIGH, pinnedMAC, netlink.NUD_PERMANENT))
	if got := addsOf(sink); len(got) != 0 {
		t.Errorf("a MAC on a device that is gone was advertised: %v", got)
	}
}

// A MAC that becomes a device's own address is withdrawn if it was advertised.
func TestBridgeDeviceAddressWithdrawsAdvertised(t *testing.T) {
	w, _, sink := newBridgeTestWatcher(t)
	w.handleNeighUpdate(bridgeUpdate(unix.RTM_NEWNEIGH, ownMAC, netlink.NUD_REACHABLE))
	w.handleNeighUpdate(bridgeUpdate(unix.RTM_NEWNEIGH, ownMAC, netlink.NUD_PERMANENT))
	if len(sink.events) != 2 || !sink.events[0].added || sink.events[1].added {
		t.Errorf("events = %+v, want an add then a withdraw", sink.events)
	}
}

// Aging leaves every local MAC the bridge still holds, of whatever kind,
// and ages the ones it does not.
func TestAgingLeavesWhatTheBridgeHolds(t *testing.T) {
	w, ops, sink := newBridgeTestWatcher(t,
		bridgeEntry(pinnedMAC, netlink.NUD_NOARP),    // static
		bridgeEntry(otherMAC, netlink.NUD_REACHABLE), // dynamic
	)
	gone := net.HardwareAddr{0xaa, 0, 0, 0, 0, 9}
	ops.aged = []bpf.AgedFdbEntry{{BDID: 100, MAC: pinnedMAC}, {BDID: 100, MAC: otherMAC}, {BDID: 100, MAC: gone}}
	w.ageAndWithdraw(1e9)
	if len(sink.events) != 1 || sink.events[0].mac != gone.String() || sink.events[0].added {
		t.Errorf("events = %+v, want only the withdraw of %s", sink.events, gone)
	}
}

// With aging off, a tc-mode BD's local MAC the bridge does not hold still
// ages: nothing else would withdraw it.
func TestLocalAgingCoversMACsTheBridgeDropped(t *testing.T) {
	w, ops, sink := newBridgeTestWatcher(t, bridgeEntry(otherMAC, netlink.NUD_REACHABLE))
	gone := net.HardwareAddr{0xaa, 0, 0, 0, 0, 9}
	ops.aged = []bpf.AgedFdbEntry{{BDID: 100, MAC: otherMAC}, {BDID: 100, MAC: gone}}
	w.ageLocal(uint64(localAgingDefault))
	if len(sink.events) != 1 || sink.events[0].mac != gone.String() || sink.events[0].added {
		t.Errorf("events = %+v, want only the withdraw of %s", sink.events, gone)
	}
}

// A failed FDB dump leaves tc-mode local entries alone but does not stop the
// rest of the pass.
func TestAgingDumpFailureKeepsTcLocals(t *testing.T) {
	w, ops, sink := newBridgeTestWatcher(t)
	w.neighList = func(int, int) ([]netlink.Neigh, error) { return nil, errors.New("boom") }
	other := net.HardwareAddr{0xaa, 0, 0, 0, 0, 7}
	ops.aged = []bpf.AgedFdbEntry{{BDID: 100, MAC: otherMAC}, {BDID: 300, MAC: other}}
	w.ageAndWithdraw(1e9)
	if len(sink.events) != 1 || sink.events[0].mac != other.String() {
		t.Errorf("events = %+v, want only the BD without a bridge to age", sink.events)
	}
}

// A bridge expiry of a MAC XDP is seeing keeps the entry and RT2; an expiry of
// a quiet MAC and every other removal do not.
func TestExpiryOfAMACStillSeen(t *testing.T) {
	w, ops, sink := newBridgeTestWatcher(t)
	w.handleNeighUpdate(bridgeUpdate(unix.RTM_DELNEIGH, otherMAC, netlink.NUD_STALE))
	if len(sink.events) != 0 || len(ops.deleted) != 0 {
		t.Errorf("expiry of a fresh MAC: events %+v deleted %v", sink.events, ops.deleted)
	}

	ops.gone = map[string]bool{otherMAC.String(): true}
	w.handleNeighUpdate(bridgeUpdate(unix.RTM_DELNEIGH, otherMAC, netlink.NUD_STALE))
	if len(sink.events) != 1 || sink.events[0].added {
		t.Errorf("expiry of a quiet MAC: events %+v", sink.events)
	}

	ops.gone = nil
	sink.events = nil
	w.handleNeighUpdate(bridgeUpdate(unix.RTM_DELNEIGH, otherMAC, netlink.NUD_REACHABLE))
	if len(sink.events) != 1 {
		t.Errorf("a port removal must withdraw even a fresh MAC: events %+v", sink.events)
	}
}

// A MAC XDP learned back is re-announced in a tc-mode BD, without the
// device addresses that also sit in fdb_map, BDs that have no bridge, or a
// MAC withdrawn since the list was read.
func TestReconcileReannouncesLocalMACsInTcMode(t *testing.T) {
	w, ops, sink := newBridgeTestWatcher(t, bridgeEntry(ownMAC, netlink.NUD_PERMANENT))
	withdrawn := net.HardwareAddr{0xaa, 0, 0, 0, 0, 8}
	ops.local = map[uint16][]net.HardwareAddr{
		100: {ownMAC, otherMAC, withdrawn},
		200: {pinnedMAC}, // no registered bridge
	}
	ops.gone = map[string]bool{withdrawn.String(): true}
	w.reconcileLocalMACs(w.dumpBridgeFDB())
	if got := addsOf(sink); len(got) != 1 || got[0] != otherMAC.String() {
		t.Errorf("re-announced %v, want only %s", got, otherMAC)
	}
}
