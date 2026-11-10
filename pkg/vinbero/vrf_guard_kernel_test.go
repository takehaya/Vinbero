package vinbero

import (
	"path/filepath"
	"strings"
	"testing"

	vinberov1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/netresource"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// unreachableDefaults counts the type-unreachable default routes of table,
// both families.
func unreachableDefaults(t *testing.T, table int) int {
	t.Helper()
	n := 0
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
		if err != nil {
			t.Fatalf("RouteListFiltered table %d: %v", table, err)
		}
		for _, r := range routes {
			if r.Type == unix.RTN_UNREACHABLE {
				n++
			}
		}
	}
	return n
}

// The daemon's guard, over the pinned headend_l2 map and the host's links:
// VRF a, which Vinbero does not manage, is on table 600 and its port kvg0
// carries an L2 headend circuit. VRF b shares the table with the opt-out;
// with the opt-out removed, the restart's Reconcile leaves the table open
// and names the circuit. After the boot, a create that would enslave
// kvg1, which carries a circuit too, into a VRF on another table is
// refused. With the circuit gone the next start closes table 600.
func TestTableCloseGuard_Kernel(t *testing.T) {
	withKernelNetns(t)
	addVeth(t, "kvg0", "kvg0p")
	addVeth(t, "kvg1", "kvg1p")
	if err := netlink.LinkAdd(&netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: "vrf-a"}, Table: 600}); err != nil {
		t.Skipf("kernel lacks the vrf module: %v", err)
	}
	vrfA, err := netlink.LinkByName("vrf-a")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(vrfA); err != nil {
		t.Fatal(err)
	}
	kvg0, err := netlink.LinkByName("kvg0")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetMaster(kvg0, vrfA); err != nil {
		t.Fatal(err)
	}
	kvg1, err := netlink.LinkByName("kvg1")
	if err != nil {
		t.Fatal(err)
	}

	statePath := filepath.Join(t.TempDir(), "state.json")
	v := newKernelVinbero(t, statePath)
	defer func() { _ = v.Close() }()
	if _, err := v.GetResourceManager().CreateVrf("vrf-b", 600, nil, false, true); err != nil {
		t.Fatalf("CreateVrf vrf-b: %v", err)
	}
	entry := &bpf.HeadendEntry{
		Mode:        uint8(vinberov1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2),
		NumSegments: 1,
		BdId:        100,
	}
	for _, l := range []netlink.Link{kvg0, kvg1} {
		if err := v.GetMapOperations().CreateHeadendL2(uint32(l.Attrs().Index), 0, entry, [bpf.ESILen]byte{}); err != nil {
			t.Fatalf("CreateHeadendL2: %v", err)
		}
	}

	restart := func(config map[string]bool) *netresource.ResourceManager {
		t.Helper()
		m, err := netresource.NewResourceManager(statePath, zap.NewNop())
		if err != nil {
			t.Fatal(err)
		}
		m.SetConfigUnreachableDefault(config)
		m.SetTableCloseGuard(v.tableCloseGuard)
		if err := m.Reconcile(); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		return m
	}
	m := restart(map[string]bool{"vrf-b": false})
	if n := unreachableDefaults(t, 600); n != 0 {
		t.Errorf("table 600 has %d unreachable defaults under the circuit on kvg0, want 0", n)
	}
	if c := m.TablesHeldOpen()[600]; !strings.Contains(c, "{kvg0, vlan 0}") || !strings.Contains(c, "vrf-a") {
		t.Errorf("TablesHeldOpen()[600] = %q, want the circuit on kvg0 of vrf-a", c)
	}

	m.FinishBoot()
	if _, err := m.CreateVrf("vrf-c", 700, []string{"kvg1"}, false, false); err == nil || !strings.Contains(err.Error(), "{kvg1, vlan 0}") {
		t.Errorf("CreateVrf vrf-c = %v, want the refusal naming the circuit on kvg1", err)
	}
	if n := unreachableDefaults(t, 700); n != 0 {
		t.Errorf("table 700 has %d unreachable defaults after the refusal", n)
	}

	if err := v.GetMapOperations().DeleteHeadendL2(uint32(kvg0.Attrs().Index), 0); err != nil {
		t.Fatalf("DeleteHeadendL2: %v", err)
	}
	restart(nil)
	if n := unreachableDefaults(t, 600); n != 2 {
		t.Errorf("table 600 has %d unreachable defaults once the circuit is gone, want 2", n)
	}
}
