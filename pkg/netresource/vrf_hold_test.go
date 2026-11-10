package netresource

import (
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// circuitGuard is a TableCloseGuard that finds an L2 headend circuit on
// the given tables.
func circuitGuard(tables ...uint32) TableCloseGuard {
	return func(name string, table uint32, _ []string) (*L2CircuitOnTable, error) {
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
