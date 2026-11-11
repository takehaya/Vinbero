package vinbero

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/config"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// newKernelVinberoPinned is newKernelVinbero with the control maps pinned
// in pinDir ("" = not pinned).
func newKernelVinberoPinned(t *testing.T, statePath, pinDir string) *Vinbero {
	t.Helper()
	yaml := fmt.Sprintf("internal:\n  bpf:\n    device_mode: generic\nsettings:\n  state_path: %s\n", statePath)
	if pinDir != "" {
		yaml += fmt.Sprintf("  pin_maps:\n    enabled: true\n    path: %s\n", pinDir)
	}
	cfg, err := config.Load(yaml)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	v, err := NewVinbero(cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("NewVinbero: %v", err)
	}
	if err := v.InitResourceManager(); err != nil {
		_ = v.Close()
		t.Fatalf("InitResourceManager: %v", err)
	}
	return v
}

func linkID(t *testing.T, name string) LinkID {
	t.Helper()
	l, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatal(err)
	}
	a := l.Attrs()
	return LinkID{Name: a.Name, Ifindex: uint32(a.Index), MAC: a.HardwareAddr}
}

func delLink(t *testing.T, name string) {
	t.Helper()
	l, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkDel(l); err != nil {
		t.Fatal(err)
	}
}

// The circuits made over the API come back after a restart, ESI included,
// with the maps pinned or not. One whose interface was deleted and made
// again under the same name while the daemon was down does not, and its
// pinned entry goes too.
func TestL2CircuitsRestart_Kernel(t *testing.T) {
	for _, pinned := range []bool{false, true} {
		t.Run(fmt.Sprintf("pinned=%v", pinned), func(t *testing.T) {
			withKernelNetns(t)
			pinDir := ""
			if pinned {
				pinDir = filepath.Join("/sys/fs/bpf", fmt.Sprintf("vinbero-l2c-%d", os.Getpid()))
				t.Cleanup(func() { _ = os.RemoveAll(pinDir) })
			}
			addVeth(t, "klc0", "klc0p")
			addVeth(t, "klc1", "klc1p")
			statePath := filepath.Join(t.TempDir(), "state.json")
			v := newKernelVinberoPinned(t, statePath, pinDir)
			c := v.L2Circuits()
			l0, l1 := linkID(t, "klc0"), linkID(t, "klc1")
			for _, ckt := range []L2Circuit{
				circuitOn(l0, 0, 100, esi1),
				circuitOn(l0, 7, 200, [bpf.ESILen]byte{}),
				circuitOn(l1, 0, 100, [bpf.ESILen]byte{}),
			} {
				if err := c.Create(ckt); err != nil {
					t.Fatalf("Create %+v: %v", ckt.Link, err)
				}
			}
			_ = v.Close()

			delLink(t, "klc1")
			addVeth(t, "klc1", "klc1p")
			l1again := linkID(t, "klc1")

			v = newKernelVinberoPinned(t, statePath, pinDir)
			defer func() { _ = v.Close() }()
			ops := v.GetMapOperations()
			entries, err := ops.ListHeadendL2()
			if err != nil {
				t.Fatal(err)
			}
			got := map[bpf.HeadendL2Key]uint16{}
			for k, e := range entries {
				got[k] = e.BdId
			}
			want := map[bpf.HeadendL2Key]uint16{
				{Ifindex: l0.Ifindex, VlanId: 0}: 100,
				{Ifindex: l0.Ifindex, VlanId: 7}: 200,
			}
			if fmt.Sprint(got) != fmt.Sprint(want) {
				t.Errorf("headend_l2 after the restart = %v, want %v (klc1 was %d, is %d)", got, want, l1.Ifindex, l1again.Ifindex)
			}
			if esi, _ := ops.GetHeadendL2Esi(l0.Ifindex, 0); esi != esi1 {
				t.Errorf("ESI after the restart = %v, want %v", esi, esi1)
			}
			if recs := v.GetResourceManager().L2Circuits(); len(recs) != 2 {
				t.Errorf("saved circuits after the restart = %+v", recs)
			}
		})
	}
}

// A VRF table whose port carries a saved circuit stays open across a
// restart without pinned maps, as it does with them; a table without a
// circuit is closed.
func TestL2CircuitsHoldTableOpenAfterRestart_Kernel(t *testing.T) {
	withKernelNetns(t)
	addVeth(t, "kho0", "kho0p")
	addVeth(t, "kho1", "kho1p")
	statePath := filepath.Join(t.TempDir(), "state.json")
	v := newKernelVinberoPinned(t, statePath, "")
	if !v.FibLookupTBID() {
		_ = v.Close()
		t.Skip("the kernel's bpf_fib_lookup lacks BPF_FIB_LOOKUP_TBID: tables are never closed")
	}
	if err := v.L2Circuits().Create(circuitOn(linkID(t, "kho0"), 0, 100, [bpf.ESILen]byte{})); err != nil {
		t.Fatal(err)
	}
	if _, err := v.GetResourceManager().CreateVrf("vrf-h", 610, []string{"kho0"}, false, false); err != nil {
		t.Skipf("kernel lacks the vrf module: %v", err)
	}
	if _, err := v.GetResourceManager().CreateVrf("vrf-l", 620, []string{"kho1"}, false, false); err != nil {
		t.Fatal(err)
	}
	_ = v.Close()

	v = newKernelVinberoPinned(t, statePath, "")
	defer func() { _ = v.Close() }()
	if n := unreachableDefaults(t, 610); n != 0 {
		t.Errorf("table 610 has %d unreachable defaults under the saved circuit on kho0, want 0", n)
	}
	if c := v.GetResourceManager().TablesHeldOpen()[610]; !strings.Contains(c, "kho0") {
		t.Errorf("TablesHeldOpen()[610] = %q, want the circuit on kho0", c)
	}
	if n := unreachableDefaults(t, 620); n != 2 {
		t.Errorf("table 620 without a circuit has %d unreachable defaults, want 2", n)
	}
}

// The watcher started at boot syncs the FDB a reconciled bridge already
// has into fdb_map.
func TestFDBWatcherSyncsBridgeFDBAtBoot_Kernel(t *testing.T) {
	withKernelNetns(t)
	addVeth(t, "kfb0", "kfb0p")
	statePath := filepath.Join(t.TempDir(), "state.json")
	v := newKernelVinberoPinned(t, statePath, "")
	if _, err := v.GetResourceManager().CreateBridge("kbr0", 100, []string{"kfb0"}, "evi-100"); err != nil {
		t.Fatal(err)
	}
	_ = v.Close()
	port := linkID(t, "kfb0")
	mac := []byte{0x02, 0xaa, 0, 0, 0, 1}
	if err := netlink.NeighSet(&netlink.Neigh{
		LinkIndex: int(port.Ifindex), Family: unix.AF_BRIDGE, State: netlink.NUD_NOARP,
		Flags: netlink.NTF_MASTER, HardwareAddr: mac,
	}); err != nil {
		t.Fatalf("bridge fdb add: %v", err)
	}

	v = newKernelVinberoPinned(t, statePath, "")
	defer func() { _ = v.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := v.StartFDBWatcher(ctx, nil); err != nil {
		t.Fatal(err)
	}
	k := bpf.FdbKey{BdId: 100}
	copy(k.Mac[:], mac)
	deadline := time.Now().Add(3 * time.Second)
	for {
		fdbs, err := v.GetMapOperations().ListFdb()
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := fdbs[k]; ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("fdb_map has no entry for the bridge's existing MAC: %v", fdbs)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
