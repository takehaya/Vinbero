package netresource

import (
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"golang.org/x/sys/unix"
)

// circuitGuard is a TableCloseGuard that finds an L2 headend circuit on
// the given tables.
func circuitGuard(tables ...uint32) TableCloseGuard {
	return func(table uint32, _ map[string]string) (*L2CircuitOnTable, error) {
		for _, t := range tables {
			if t == table {
				return &L2CircuitOnTable{Port: "eth6", VLAN: 0, VRF: "vrf-a"}, nil
			}
		}
		return nil, nil
	}
}

// A table with an L2 headend circuit on a port is not closed. At boot,
// where nothing can be refused, it is held open: Reconcile (here for a VRF
// whose opt-out the config removes) adds no route, gives back the routes a
// previous run added, warns once naming the table and the circuit, and
// lists the table in TablesHeldOpen; a boot-time create on it adds nothing
// either. After FinishBoot, a create that would close a table under a
// circuit is refused and leaves nothing behind.
func TestTableHeldOpenForL2Circuit(t *testing.T) {
	withTestNetns(t)
	m := newTestManager(t)
	createVrfOrSkip(t, m, "vrf-b", 600, true)
	wantUnreachable(t, 600, 0)

	// The opt-out removed in the config, with a circuit on the table.
	core, logs := observer.New(zap.WarnLevel)
	m2, err := NewResourceManager(m.statePath, zap.New(core))
	if err != nil {
		t.Fatal(err)
	}
	m2.SetConfigUnreachableDefault(map[string]bool{"vrf-b": false})
	m2.SetTableCloseGuard(circuitGuard(600))
	if err := m2.Reconcile(); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	wantUnreachable(t, 600, 0)
	if c := m2.TablesHeldOpen()[600]; !strings.Contains(c, "{eth6, vlan 0}") {
		t.Errorf("TablesHeldOpen()[600] = %q, want the circuit on eth6", c)
	}
	warned := logs.FilterMessageSnippet("VRF table left open").All()
	if len(warned) != 1 || warned[0].ContextMap()["table_id"] != uint32(600) || warned[0].ContextMap()["port"] != "eth6" {
		t.Errorf("warnings = %v, want one naming table 600 and eth6", logs.All())
	}
	if _, err := m2.CreateVrf("vrf-d", 600, nil, false, false); err != nil {
		t.Fatalf("boot-time create on the held table: %v", err)
	}
	wantUnreachable(t, 600, 0)

	// Without the circuit the next start closes the table; with it back,
	// the start after gives the routes Vinbero added back.
	m3, err := NewResourceManager(m.statePath, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if err := m3.Reconcile(); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	wantUnreachable(t, 600, 1)
	m4, err := NewResourceManager(m.statePath, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	m4.SetTableCloseGuard(circuitGuard(600, 700))
	if err := m4.Reconcile(); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	wantUnreachable(t, 600, 0)
	for _, name := range []string{"vrf-b", "vrf-d"} {
		if got, _ := m4.GetVrfByName(name); len(got.UnreachableDefaultAdded) != 0 {
			t.Errorf("%s still records %v", name, got.UnreachableDefaultAdded)
		}
	}

	// Running: refused, and the failed create leaves no device.
	m4.FinishBoot()
	if _, err := m4.CreateVrf("vrf-c", 700, nil, false, false); err == nil || !strings.Contains(err.Error(), "L2 headend circuit {eth6, vlan 0}") {
		t.Errorf("CreateVrf on table 700 = %v, want the refusal naming the circuit", err)
	}
	if _, err := netlink.LinkByName("vrf-c"); err == nil {
		t.Error("the refused create left vrf-c behind")
	}
	wantUnreachable(t, 700, 0)
	if _, err := m4.CreateVrf("vrf-e", 800, nil, false, false); err != nil {
		t.Fatalf("CreateVrf on a table without a circuit: %v", err)
	}
	wantUnreachable(t, 800, 1)
}

// memberGuard is a TableCloseGuard that finds an L2 headend circuit on the
// given ports when they are among the members it is asked about.
func memberGuard(ports ...string) TableCloseGuard {
	return func(_ uint32, members map[string]string) (*L2CircuitOnTable, error) {
		for _, p := range ports {
			if vrf, ok := members[p]; ok {
				return &L2CircuitOnTable{Port: p, VRF: vrf}, nil
			}
		}
		return nil, nil
	}
}

// A table is checked once, over every port that will be on it, before any
// VRF on it is processed: the member an opted-out VRF records but does not
// hold right now, and the member the config gives a VRF the state does not
// track yet, hold the table open whichever VRF on it comes first. A port
// enslaved into a VRF on a closed table is checked as a close is.
func TestTableCheckedOverEveryMember(t *testing.T) {
	withTestNetns(t)
	m := newTestManager(t)
	for _, name := range []string{"kvh6", "kvh7", "kvh8"} {
		addDummy(t, name)
	}
	createVrfOrSkip(t, m, "vrf-a", 600, false)
	if _, err := m.CreateVrf("vrf-b", 600, []string{"kvh6"}, false, true); err != nil {
		t.Fatal(err)
	}
	kvh6, err := netlink.LinkByName("kvh6")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetNoMaster(kvh6); err != nil {
		t.Fatal(err)
	}
	createVrfOrSkip(t, m, "vrf-c", 610, false)
	wantUnreachable(t, 600, 1)
	wantUnreachable(t, 610, 1)

	m2, err := NewResourceManager(m.statePath, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	m2.SetTableCloseGuard(memberGuard("kvh6", "kvh7", "kvh8"))
	m2.SetConfigVrfDevices([]ConfigVrfDevice{{Name: "vrf-d", TableID: 610, Members: []string{"kvh7"}}})
	if err := m2.Reconcile(); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	wantUnreachable(t, 600, 0)
	wantUnreachable(t, 610, 0)
	held := m2.TablesHeldOpen()
	if !strings.Contains(held[600], "{kvh6, vlan 0}") || !strings.Contains(held[610], "{kvh7, vlan 0}") {
		t.Errorf("TablesHeldOpen = %v, want 600 for kvh6 and 610 for kvh7", held)
	}

	m2.FinishBoot()
	createVrfOrSkip(t, m2, "vrf-e", 620, false)
	_, err = m2.CreateVrf("vrf-f", 620, []string{"kvh8"}, false, true)
	if err == nil || !strings.Contains(err.Error(), "{kvh8, vlan 0}") {
		t.Errorf("an opted-out create enslaving kvh8 on closed table 620 = %v, want the refusal", err)
	}
	if l, err := netlink.LinkByName("kvh8"); err != nil || l.Attrs().MasterIndex != 0 {
		t.Errorf("kvh8 was enslaved (%v)", err)
	}
}

// A table counts as held open only once its unreachable defaults are gone.
// When the removal of the one Vinbero added fails, the table stays closed:
// it is not in TablesHeldOpen, one error is logged, the record keeps the
// route, and the next start removes it and holds the table open.
func TestTableHeldOpenRemovalFails(t *testing.T) {
	withTestNetns(t)
	m := newTestManager(t)
	createVrfOrSkip(t, m, "vrf-h", 630, false)
	wantUnreachable(t, 630, 1)

	routeDel = func(r *netlink.Route) error {
		if r.Dst.IP.To4() == nil {
			return unix.EPERM
		}
		return netlink.RouteDel(r)
	}
	t.Cleanup(func() { routeDel = netlink.RouteDel })
	core, logs := observer.New(zap.WarnLevel)
	m2, err := NewResourceManager(m.statePath, zap.New(core))
	if err != nil {
		t.Fatal(err)
	}
	m2.SetTableCloseGuard(circuitGuard(630))
	if err := m2.Reconcile(); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if n := unreachableCount(t, 630); n[netlink.FAMILY_V4] != 0 || n[netlink.FAMILY_V6] != 1 {
		t.Fatalf("table 630: %v, want only the IPv6 default left", n)
	}
	if c, held := m2.TablesHeldOpen()[630]; held {
		t.Errorf("table 630 reported open (%s) with its IPv6 unreachable default still there", c)
	}
	if errs := logs.FilterMessageSnippet("cannot leave a VRF table open").All(); len(errs) != 1 || errs[0].Level != zap.ErrorLevel {
		t.Errorf("logs = %v, want one error", logs.All())
	}
	if got, _ := m2.GetVrfByName("vrf-h"); len(got.UnreachableDefaultAdded) != 1 || got.UnreachableDefaultAdded[0] != familyIPv6 {
		t.Errorf("vrf-h records %v, want [ipv6] kept", got.UnreachableDefaultAdded)
	}

	routeDel = netlink.RouteDel
	m3, err := NewResourceManager(m.statePath, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	m3.SetTableCloseGuard(circuitGuard(630))
	if err := m3.Reconcile(); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	wantUnreachable(t, 630, 0)
	if _, held := m3.TablesHeldOpen()[630]; !held {
		t.Error("table 630 not held open once the route is removed")
	}
}
