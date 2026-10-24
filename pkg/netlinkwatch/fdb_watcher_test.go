package netlinkwatch

import (
	"net"
	"testing"

	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

func newTestFDBWatcher(t *testing.T) (*FDBWatcher, *bpf.MapOperations) {
	t.Helper()
	objs, err := bpf.ReadCollection(nil, nil)
	if err != nil {
		t.Fatalf("Failed to load BPF objects: %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })

	mapOps := bpf.NewMapOperations(objs)
	logger := zap.NewNop()

	w := NewFDBWatcher(mapOps, logger)
	// Dynamically register a test bridge
	w.RegisterBridge(10, 100) // bridge ifindex 10 → bd_id 100

	return w, mapOps
}

func TestFDBWatcherHandleNeighUpdate(t *testing.T) {
	w, mapOps := newTestFDBWatcher(t)

	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}

	t.Run("AF_BRIDGE + allowed MasterIndex + RTM_NEWNEIGH → fdb_map add", func(t *testing.T) {
		w.handleNeighUpdate(netlink.NeighUpdate{
			Type: unix.RTM_NEWNEIGH,
			Neigh: netlink.Neigh{
				Family:       unix.AF_BRIDGE,
				MasterIndex:  10,
				LinkIndex:    3,
				HardwareAddr: mac,
			},
		})

		entry, err := mapOps.GetFdb(100, mac)
		if err != nil {
			t.Fatalf("Expected fdb entry after RTM_NEWNEIGH, got error: %v", err)
		}
		if entry.Oif != 3 {
			t.Errorf("Expected oif=3, got %d", entry.Oif)
		}
		t.Logf("SUCCESS: RTM_NEWNEIGH → fdb_map[(bd_id=100, %s)] = {oif=3}", mac)
	})

	t.Run("RTM_DELNEIGH → fdb_map delete", func(t *testing.T) {
		w.handleNeighUpdate(netlink.NeighUpdate{
			Type: unix.RTM_DELNEIGH,
			Neigh: netlink.Neigh{
				Family:       unix.AF_BRIDGE,
				MasterIndex:  10,
				LinkIndex:    3,
				HardwareAddr: mac,
			},
		})

		_, err := mapOps.GetFdb(100, mac)
		if err == nil {
			t.Errorf("Expected fdb entry to be deleted, but it still exists")
		} else {
			t.Logf("SUCCESS: RTM_DELNEIGH → fdb entry deleted")
		}
	})

	t.Run("disallowed MasterIndex → skip", func(t *testing.T) {
		unknownMAC := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x99}
		w.handleNeighUpdate(netlink.NeighUpdate{
			Type: unix.RTM_NEWNEIGH,
			Neigh: netlink.Neigh{
				Family:       unix.AF_BRIDGE,
				MasterIndex:  99, // not in allowed
				LinkIndex:    5,
				HardwareAddr: unknownMAC,
			},
		})

		_, err := mapOps.GetFdb(100, unknownMAC)
		if err == nil {
			t.Errorf("Expected no fdb entry for disallowed bridge, but entry exists")
		} else {
			t.Logf("SUCCESS: disallowed MasterIndex → skipped")
		}
	})

	t.Run("AF_INET (not bridge) → skip", func(t *testing.T) {
		inetMAC := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x88}
		w.handleNeighUpdate(netlink.NeighUpdate{
			Type: unix.RTM_NEWNEIGH,
			Neigh: netlink.Neigh{
				Family:       unix.AF_INET,
				MasterIndex:  10,
				LinkIndex:    3,
				HardwareAddr: inetMAC,
			},
		})

		_, err := mapOps.GetFdb(100, inetMAC)
		if err == nil {
			t.Errorf("Expected no fdb entry for AF_INET, but entry exists")
		} else {
			t.Logf("SUCCESS: AF_INET → skipped")
		}
	})

	t.Run("multicast MAC → skip", func(t *testing.T) {
		multicastMAC := net.HardwareAddr{0x01, 0x00, 0x5e, 0x00, 0x00, 0x01}
		w.handleNeighUpdate(netlink.NeighUpdate{
			Type: unix.RTM_NEWNEIGH,
			Neigh: netlink.Neigh{
				Family:       unix.AF_BRIDGE,
				MasterIndex:  10,
				LinkIndex:    3,
				HardwareAddr: multicastMAC,
			},
		})

		_, err := mapOps.GetFdb(100, multicastMAC)
		if err == nil {
			t.Errorf("Expected no fdb entry for multicast MAC, but entry exists")
		} else {
			t.Logf("SUCCESS: multicast MAC → skipped")
		}
	})
}

// The real watcher must not reserve rpc:v1 for kernel learning. BGP must
// replace that unowned observation, and later kernel NEW/DEL must preserve it.
func TestFDBWatcherBGPReplacesKernelLearning(t *testing.T) {
	w, maps := newTestFDBWatcher(t)
	sink := &fakeMACSink{}
	w.SetMACSink(sink)
	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0, 0, 0x30}
	update := netlink.NeighUpdate{Type: unix.RTM_NEWNEIGH,
		Neigh: netlink.Neigh{Family: unix.AF_BRIDGE, MasterIndex: 10, LinkIndex: 3, HardwareAddr: mac}}
	w.handleNeighUpdate(update)
	if tag, owned, err := maps.GetFdbOwner(100, mac); err != nil || owned {
		t.Errorf("kernel observation claimed managed owner: %q %v %v", tag, owned, err)
	}
	if len(sink.events) != 1 || !sink.events[0].added {
		t.Fatalf("successful local learning did not advertise: %+v", sink.events)
	}
	owner := bpf.OwnerBGPEVPN(65100)
	if err := maps.CreateFdbOwned(100, mac, &bpf.FdbEntry{IsRemote: 1, PeerIndex: 7}, owner); err != nil {
		t.Fatalf("BGP import blocked after kernel learning: %v", err)
	}
	w.handleNeighUpdate(update)
	if len(sink.events) != 1 {
		t.Fatalf("protected remote route advertised as new local MAC: %+v", sink.events)
	}
	update.Type = unix.RTM_DELNEIGH
	w.handleNeighUpdate(update)
	if entry, err := maps.GetFdb(100, mac); err != nil || entry.IsRemote != 1 || entry.PeerIndex != 7 || entry.IsStatic != 1 {
		t.Fatalf("kernel notification changed managed forwarding: %+v %v", entry, err)
	}
	if tag, owned, err := maps.GetFdbOwner(100, mac); err != nil || !owned || tag != owner {
		t.Fatalf("kernel notification changed BGP owner: %q %v %v", tag, owned, err)
	}
	// The kernel local disappearance must still withdraw any locally
	// originated RT2, even when another producer now owns BPF forwarding.
	if len(sink.events) != 2 || sink.events[1].added {
		t.Fatalf("kernel DEL lost local withdrawal notification: %+v", sink.events)
	}
}
