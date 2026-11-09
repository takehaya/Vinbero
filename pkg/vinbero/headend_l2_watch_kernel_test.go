package vinbero

import (
	"path/filepath"
	"testing"
	"time"

	vinberov1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/vishvananda/netlink"
)

// The link watcher removes the headend_l2 entries of a deleted interface on
// every VLAN, and on subscribing the entries of an interface that was already
// gone. Entries on a live interface stay, including one that only leaves a
// bridge.
func TestWatchDevices_RemovesHeadendL2_Kernel(t *testing.T) {
	withKernelNetns(t)
	defer func(d time.Duration) { linkSweepInterval = d }(linkSweepInterval)
	linkSweepInterval = 200 * time.Millisecond
	addVeth(t, "khl0", "khl0p")
	addVeth(t, "khl1", "khl1p")
	v := newKernelVinbero(t, filepath.Join(t.TempDir(), "state.json"))
	defer func() { _ = v.Close() }()
	ops := v.GetMapOperations()

	create := func(ifindex uint32, vlan uint16) {
		t.Helper()
		entry := &bpf.HeadendEntry{
			Mode:        uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2),
			NumSegments: 1,
			BdId:        100,
		}
		if err := ops.CreateHeadendL2(ifindex, vlan, entry, [bpf.ESILen]byte{}); err != nil {
			t.Fatalf("CreateHeadendL2(%d, %d): %v", ifindex, vlan, err)
		}
	}
	has := func(ifindex uint32) bool {
		t.Helper()
		entries, err := ops.ListHeadendL2()
		if err != nil {
			t.Fatalf("ListHeadendL2: %v", err)
		}
		for key := range entries {
			if key.Ifindex == ifindex {
				return true
			}
		}
		return false
	}
	waitGone := func(ifindex uint32) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for has(ifindex) && time.Now().Before(deadline) {
			time.Sleep(50 * time.Millisecond)
		}
		if has(ifindex) {
			t.Fatalf("headend_l2 entries of ifindex %d were not removed", ifindex)
		}
	}

	l0, err := netlink.LinkByName("khl0")
	if err != nil {
		t.Fatal(err)
	}
	l1, err := netlink.LinkByName("khl1")
	if err != nil {
		t.Fatal(err)
	}
	if0, if1 := uint32(l0.Attrs().Index), uint32(l1.Attrs().Index)
	const alreadyGone = uint32(0x7ffffff0)
	create(if0, 0)
	create(if0, 7)
	create(if1, 0)
	create(alreadyGone, 0)

	if err := v.WatchDevices(); err != nil {
		t.Fatalf("WatchDevices: %v", err)
	}
	waitGone(alreadyGone)

	br := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: "khlbr"}}
	if err := netlink.LinkAdd(br); err != nil {
		t.Fatalf("bridge add: %v", err)
	}
	if err := netlink.LinkSetMaster(l1, br); err != nil {
		t.Fatalf("enslave: %v", err)
	}
	if err := netlink.LinkSetNoMaster(l1); err != nil {
		t.Fatalf("release: %v", err)
	}

	if err := netlink.LinkDel(l0); err != nil {
		t.Fatalf("LinkDel: %v", err)
	}
	waitGone(if0)
	if !has(if1) {
		t.Error("the entry of a veth released from a bridge was removed")
	}

	// No event announces this one, so only the periodic sweep can remove it.
	create(alreadyGone, 0)
	waitGone(alreadyGone)
}
