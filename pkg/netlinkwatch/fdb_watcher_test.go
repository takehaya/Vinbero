package netlinkwatch

import (
	"net"
	"testing"

	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/config"
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

	configs := []config.BridgeDomainConfig{
		{BridgeName: "dummy", BdID: 100},
	}

	w := NewFDBWatcher(mapOps, configs, logger)
	// Manually set allowed map (skip netlink resolution since dummy bridge doesn't exist)
	w.allowed = map[int]uint16{
		10: 100, // bridge ifindex 10 → bd_id 100
	}

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
