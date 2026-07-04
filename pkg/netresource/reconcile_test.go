package netresource

import (
	"net"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
)

// Reconcile recreates a state entry whose device vanished (the reboot case)
// and refreshes its ifindex on disk.
func TestReconcile_RecreatesMissingBridge(t *testing.T) {
	withTestNetns(t)
	m := newTestManager(t)
	if _, err := m.CreateBridge("br-rec", 100, nil, "evi-rec"); err != nil {
		t.Fatalf("CreateBridge: %v", err)
	}
	link, err := netlink.LinkByName("br-rec")
	if err != nil {
		t.Fatalf("LinkByName: %v", err)
	}
	if err := netlink.LinkDel(link); err != nil {
		t.Fatalf("LinkDel: %v", err)
	}

	// Fresh manager over the same state file = the post-reboot load.
	m2, err := NewResourceManager(m.statePath, zap.NewNop())
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if err := m2.Reconcile(); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	relink, err := netlink.LinkByName("br-rec")
	if err != nil {
		t.Fatalf("bridge not recreated: %v", err)
	}
	got, ok := m2.GetBridgeByName("br-rec")
	if !ok || got.Ifindex != uint32(relink.Attrs().Index) {
		t.Errorf("state ifindex = %+v, want the recreated device's %d", got, relink.Attrs().Index)
	}
}

// Reconcile is fail-closed: an entry whose name was stolen by a different
// link type, or whose recreation fails, aborts with a repair hint and does
// NOT write a stale ifindex back to disk.
func TestReconcile_FailsClosed(t *testing.T) {
	withTestNetns(t)

	t.Run("name stolen by a non-bridge link", func(t *testing.T) {
		m := newTestManager(t)
		if _, err := m.CreateBridge("br-stolen", 100, nil, ""); err != nil {
			t.Fatalf("CreateBridge: %v", err)
		}
		link, err := netlink.LinkByName("br-stolen")
		if err != nil {
			t.Fatalf("LinkByName: %v", err)
		}
		if err := netlink.LinkDel(link); err != nil {
			t.Fatalf("LinkDel: %v", err)
		}
		if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "br-stolen"}}); err != nil {
			t.Fatalf("dummy add: %v", err)
		}

		before, err := os.ReadFile(m.statePath)
		if err != nil {
			t.Fatalf("read state: %v", err)
		}
		m2, err := NewResourceManager(m.statePath, zap.NewNop())
		if err != nil {
			t.Fatalf("reload: %v", err)
		}
		err = m2.Reconcile()
		if err == nil {
			t.Fatal("Reconcile must refuse a name stolen by a non-bridge link")
		}
		if !strings.Contains(err.Error(), "br-stolen") || !strings.Contains(err.Error(), "remove the entry") {
			t.Errorf("error should name the entry and the repair hint, got: %v", err)
		}
		after, err := os.ReadFile(m.statePath)
		if err != nil {
			t.Fatalf("re-read state: %v", err)
		}
		if string(before) != string(after) {
			t.Error("a failed Reconcile must not rewrite the state file")
		}
	})

	t.Run("recreation fails on a missing member", func(t *testing.T) {
		m := newTestManager(t)
		// Seed a state entry whose recreation cannot succeed: the member NIC
		// does not exist in this netns (a renamed/removed NIC after reboot).
		m.ensureBridgeInState("br-lost", 200, []string{"ghost0"}, 7, "evi-lost")
		if err := m.persist(); err != nil {
			t.Fatalf("persist: %v", err)
		}
		before, err := os.ReadFile(m.statePath)
		if err != nil {
			t.Fatalf("read state: %v", err)
		}

		m2, err := NewResourceManager(m.statePath, zap.NewNop())
		if err != nil {
			t.Fatalf("reload: %v", err)
		}
		err = m2.Reconcile()
		if err == nil {
			t.Fatal("Reconcile must fail when a state entry cannot be recreated")
		}
		if !strings.Contains(err.Error(), "br-lost") || !strings.Contains(err.Error(), m.statePath) {
			t.Errorf("error should carry the entry and the state path, got: %v", err)
		}
		after, err := os.ReadFile(m.statePath)
		if err != nil {
			t.Fatalf("re-read state: %v", err)
		}
		if string(before) != string(after) {
			t.Error("a failed Reconcile must not persist the stale ifindex")
		}
	})
}

// Reconcile adopt converges like Create: an existing device is brought up
// and its missing members enslaved, not just its ifindex read back.
func TestReconcile_AdoptConverges(t *testing.T) {
	withTestNetns(t)
	m := newTestManager(t)
	if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "mem-rec0"}}); err != nil {
		t.Fatalf("dummy add: %v", err)
	}
	if _, err := m.CreateBridge("br-adopt", 300, []string{"mem-rec0"}, ""); err != nil {
		t.Fatalf("CreateBridge: %v", err)
	}
	// Un-enslave and down the bridge out-of-band; Reconcile must converge both.
	mem, err := netlink.LinkByName("mem-rec0")
	if err != nil {
		t.Fatalf("member lookup: %v", err)
	}
	if err := netlink.LinkSetNoMaster(mem); err != nil {
		t.Fatalf("unenslave: %v", err)
	}
	br, err := netlink.LinkByName("br-adopt")
	if err != nil {
		t.Fatalf("bridge lookup: %v", err)
	}
	if err := netlink.LinkSetDown(br); err != nil {
		t.Fatalf("set down: %v", err)
	}

	m2, err := NewResourceManager(m.statePath, zap.NewNop())
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if err := m2.Reconcile(); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	br, err = netlink.LinkByName("br-adopt")
	if err != nil {
		t.Fatalf("bridge lookup: %v", err)
	}
	if br.Attrs().Flags&net.FlagUp == 0 {
		t.Error("Reconcile adopt did not bring the bridge up")
	}
	mem, err = netlink.LinkByName("mem-rec0")
	if err != nil {
		t.Fatalf("member lookup: %v", err)
	}
	if mem.Attrs().MasterIndex != br.Attrs().Index {
		t.Error("Reconcile adopt did not re-enslave the missing member")
	}
}

// A persist failure surfaces to the CreateBridge caller instead of being
// demoted to a warning behind a success return.
func TestCreateBridge_PersistFailurePropagates(t *testing.T) {
	withTestNetns(t)
	m := newTestManager(t)
	if _, err := m.CreateBridge("br-pf", 400, nil, ""); err != nil {
		t.Fatalf("CreateBridge: %v", err)
	}
	// Make the rename step unable to win: the state path becomes a directory.
	if err := os.Remove(m.statePath); err != nil {
		t.Fatalf("remove state: %v", err)
	}
	if err := os.Mkdir(m.statePath, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if _, err := m.CreateBridge("br-pf", 400, nil, ""); err == nil {
		t.Fatal("CreateBridge with a failing persist must return the error")
	}
	if err := m.DeleteBridge("br-pf"); err == nil {
		t.Fatal("DeleteBridge with a failing persist must return the error")
	}
}

// The manager's own locking keeps concurrent mutation and reads race-free
// (run with -race); the RPC layer serializes mutations today, but the
// invariant must hold inside the package that owns the data.
func TestConcurrentBridgeAccess(t *testing.T) {
	withTestNetns(t)
	m := newTestManager(t)
	if _, err := m.CreateBridge("br-race", 500, nil, ""); err != nil {
		t.Fatalf("CreateBridge: %v", err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				_, _ = m.CreateBridge("br-race", 500, nil, "") // idempotent adopt
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				_ = m.ListBridges()
				_, _ = m.GetBridgeByName("br-race")
			}
		}()
	}
	wg.Wait()
}
