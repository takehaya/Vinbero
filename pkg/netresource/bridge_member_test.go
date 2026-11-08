package netresource

import (
	"errors"
	"os"
	"slices"
	"testing"

	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
)

func addDummy(t *testing.T, name string) netlink.Link {
	t.Helper()
	if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}); err != nil {
		t.Fatalf("dummy add %s: %v", name, err)
	}
	l, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatalf("LinkByName %s: %v", name, err)
	}
	return l
}

func masterOf(t *testing.T, name string) int {
	t.Helper()
	l, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatalf("LinkByName %s: %v", name, err)
	}
	return l.Attrs().MasterIndex
}

// AddBridgeMember enslaves and records a runtime member, idempotently, and
// refuses to steal a port enslaved elsewhere; RemoveBridgeMember releases it
// and forgets both kinds of member.
func TestBridgeMember_AddRemove(t *testing.T) {
	withTestNetns(t)
	m := newTestManager(t)
	addDummy(t, "mem-a0")
	addDummy(t, "mem-b0")
	addDummy(t, "mem-c0")
	ifindex, err := m.CreateBridge("br-mem", 600, []string{"mem-a0"}, "evi-mem")
	if err != nil {
		t.Fatalf("CreateBridge: %v", err)
	}
	if _, err := m.CreateBridge("br-other", 601, []string{"mem-c0"}, "evi-other"); err != nil {
		t.Fatalf("CreateBridge: %v", err)
	}

	for range 2 {
		if err := m.AddBridgeMember("br-mem", "mem-b0"); err != nil {
			t.Fatalf("AddBridgeMember: %v", err)
		}
	}
	if masterOf(t, "mem-b0") != int(ifindex) {
		t.Error("mem-b0 not enslaved")
	}
	got, _ := m.GetBridgeByName("br-mem")
	if !slices.Equal(got.Members, []string{"mem-a0"}) || !slices.Equal(got.RuntimeMembers, []string{"mem-b0"}) {
		t.Errorf("state = members %v runtime %v", got.Members, got.RuntimeMembers)
	}
	// A declared member is not duplicated as a runtime member.
	if err := m.AddBridgeMember("br-mem", "mem-a0"); err != nil {
		t.Errorf("AddBridgeMember of a declared member: %v", err)
	}
	if got, _ := m.GetBridgeByName("br-mem"); len(got.RuntimeMembers) != 1 {
		t.Errorf("runtime members = %v", got.RuntimeMembers)
	}
	if err := m.AddBridgeMember("br-mem", "mem-c0"); err == nil {
		t.Error("a port of another bridge must be refused, not moved")
	}
	if err := m.AddBridgeMember("br-mem", "ghost0"); err == nil {
		t.Error("a missing port: want error")
	}
	if err := m.AddBridgeMember("br-nope", "mem-b0"); err == nil {
		t.Error("an unmanaged bridge: want error")
	}

	for _, member := range []string{"mem-a0", "mem-b0"} {
		if err := m.RemoveBridgeMember("br-mem", member); err != nil {
			t.Fatalf("RemoveBridgeMember(%s): %v", member, err)
		}
		if masterOf(t, member) != 0 {
			t.Errorf("%s still enslaved", member)
		}
	}
	got, _ = m.GetBridgeByName("br-mem")
	if len(got.Members) != 0 || len(got.RuntimeMembers) != 0 {
		t.Errorf("state after remove = members %v runtime %v", got.Members, got.RuntimeMembers)
	}
	// Not a member (and enslaved elsewhere): succeeds without touching it.
	if err := m.RemoveBridgeMember("br-mem", "mem-c0"); err != nil {
		t.Errorf("RemoveBridgeMember of a non-member: %v", err)
	}
	if masterOf(t, "mem-c0") == 0 {
		t.Error("removing a non-member released another bridge's port")
	}
	if err := m.RemoveBridgeMember("br-mem", "ghost0"); err != nil {
		t.Errorf("RemoveBridgeMember of a missing port: %v", err)
	}
}

// A member add whose state write failed is written by the retry, even though
// the member is already recorded in memory.
func TestBridgeMember_RetryAfterPersistFailure(t *testing.T) {
	withTestNetns(t)
	m := newTestManager(t)
	addDummy(t, "mem-p0")
	if _, err := m.CreateBridge("br-p", 800, nil, ""); err != nil {
		t.Fatalf("CreateBridge: %v", err)
	}
	// The rename cannot win while the state path is a directory.
	if err := os.Remove(m.statePath); err != nil {
		t.Fatalf("remove state: %v", err)
	}
	if err := os.Mkdir(m.statePath, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := m.AddBridgeMember("br-p", "mem-p0"); !errors.Is(err, ErrPersist) {
		t.Fatalf("AddBridgeMember with a failing persist = %v, want ErrPersist", err)
	}
	if err := os.Remove(m.statePath); err != nil {
		t.Fatalf("rmdir: %v", err)
	}
	if err := m.AddBridgeMember("br-p", "mem-p0"); err != nil {
		t.Fatalf("retry: %v", err)
	}
	m2, err := NewResourceManager(m.statePath, zap.NewNop())
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got, _ := m2.GetBridgeByName("br-p"); !slices.Equal(got.RuntimeMembers, []string{"mem-p0"}) {
		t.Errorf("persisted runtime members = %v", got.RuntimeMembers)
	}
}

// Reconcile re-enslaves runtime members, drops the ones that vanished
// instead of failing the boot, and persists the pruned list.
func TestReconcile_RuntimeMembers(t *testing.T) {
	withTestNetns(t)
	m := newTestManager(t)
	addDummy(t, "rt-keep0")
	gone := addDummy(t, "rt-gone0")
	if _, err := m.CreateBridge("br-rt", 700, nil, ""); err != nil {
		t.Fatalf("CreateBridge: %v", err)
	}
	for _, member := range []string{"rt-keep0", "rt-gone0"} {
		if err := m.AddBridgeMember("br-rt", member); err != nil {
			t.Fatalf("AddBridgeMember(%s): %v", member, err)
		}
	}
	// Simulate a reboot: the bridge and one workload veth are gone, the other
	// port lost its master.
	br, err := netlink.LinkByName("br-rt")
	if err != nil {
		t.Fatalf("LinkByName: %v", err)
	}
	if err := netlink.LinkDel(br); err != nil {
		t.Fatalf("LinkDel bridge: %v", err)
	}
	if err := netlink.LinkDel(gone); err != nil {
		t.Fatalf("LinkDel member: %v", err)
	}

	m2, err := NewResourceManager(m.statePath, zap.NewNop())
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if err := m2.Reconcile(); err != nil {
		t.Fatalf("Reconcile must not fail on a vanished runtime member: %v", err)
	}
	got, _ := m2.GetBridgeByName("br-rt")
	if !slices.Equal(got.RuntimeMembers, []string{"rt-keep0"}) {
		t.Errorf("runtime members = %v, want [rt-keep0]", got.RuntimeMembers)
	}
	if masterOf(t, "rt-keep0") != int(got.Ifindex) {
		t.Error("rt-keep0 not re-enslaved to the recreated bridge")
	}
	m3, err := NewResourceManager(m.statePath, zap.NewNop())
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got, _ := m3.GetBridgeByName("br-rt"); !slices.Equal(got.RuntimeMembers, []string{"rt-keep0"}) {
		t.Errorf("persisted runtime members = %v", got.RuntimeMembers)
	}
}
