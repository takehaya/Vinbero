package netlinkwatch

import (
	"context"
	"net"
	"testing"

	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// A bridge registered after Start missed the dump of the existing FDB that
// Start asked for, so its existing MACs are synced to fdb_map when it is
// registered; registering it again does not resync. Before Start nothing is
// synced at registration: the dump reaches the bridges registered by then.
func TestRegisterBridgeAfterStartSyncsExistingFDB(t *testing.T) {
	mac := net.HardwareAddr{0xaa, 0, 0, 0, 0, 1}
	ops := &fakeFdbMapOps{}
	w := &FDBWatcher{
		mapOps:  ops,
		logger:  zap.NewNop(),
		allowed: make(map[int]uint16),
		neighList: func(int, int) ([]netlink.Neigh, error) {
			return []netlink.Neigh{
				{Family: unix.AF_BRIDGE, MasterIndex: 10, LinkIndex: 3, HardwareAddr: mac},
				{Family: unix.AF_BRIDGE, MasterIndex: 20, LinkIndex: 4, HardwareAddr: net.HardwareAddr{0xaa, 0, 0, 0, 0, 2}},
			}, nil
		},
		subscribe: func(chan<- netlink.NeighUpdate, <-chan struct{}, netlink.NeighSubscribeOptions) error { return nil },
		done:      make(chan struct{}),
	}
	w.RegisterBridge(30, 300)
	if len(ops.created) != 0 {
		t.Fatalf("a registration before Start synced %v", ops.created)
	}
	if err := w.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer w.Stop()
	w.RegisterBridge(10, 100)
	if len(ops.created) != 1 || ops.created[0] != mac.String() {
		t.Errorf("registration after Start synced %v, want %s", ops.created, mac)
	}
	w.RegisterBridge(10, 100)
	if len(ops.created) != 1 {
		t.Errorf("a repeated registration synced again: %v", ops.created)
	}
}
