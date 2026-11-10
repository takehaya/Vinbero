package netresource

import (
	"encoding/json"
	"errors"
	"net"
	"testing"

	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// tableDefaults returns the default routes (dst /0) of table, by family.
func tableDefaults(t *testing.T, table uint32) map[int][]netlink.Route {
	t.Helper()
	out := map[int][]netlink.Route{}
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: int(table)}, netlink.RT_FILTER_TABLE)
		if err != nil {
			t.Fatalf("RouteListFiltered table %d: %v", table, err)
		}
		for _, r := range routes {
			if r.Dst == nil {
				out[family] = append(out[family], r)
				continue
			}
			if ones, _ := r.Dst.Mask.Size(); ones == 0 {
				out[family] = append(out[family], r)
			}
		}
	}
	return out
}

// unreachableCount counts the unreachable defaults Vinbero adds (type
// unreachable, the documented metric) in table, by family.
func unreachableCount(t *testing.T, table uint32) map[int]int {
	t.Helper()
	n := map[int]int{}
	for family, routes := range tableDefaults(t, table) {
		for _, r := range routes {
			if r.Type == unix.RTN_UNREACHABLE && r.Priority == unreachableDefaultMetric {
				n[family]++
			}
		}
	}
	return n
}

func wantUnreachable(t *testing.T, table uint32, want int) {
	t.Helper()
	got := unreachableCount(t, table)
	if got[netlink.FAMILY_V4] != want || got[netlink.FAMILY_V6] != want {
		t.Errorf("table %d: unreachable defaults v4=%d v6=%d, want %d each", table, got[netlink.FAMILY_V4], got[netlink.FAMILY_V6], want)
	}
}

// mainRoutes gives the namespace an uplink with routes in the main table
// that no VRF table holds, so a VRF lookup can only find them by falling
// through to main.
func mainRoutes(t *testing.T) {
	t.Helper()
	if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "uplink0"}}); err != nil {
		t.Fatalf("LinkAdd uplink0: %v", err)
	}
	up, err := netlink.LinkByName("uplink0")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(up); err != nil {
		t.Fatal(err)
	}
	for _, cidr := range []string{"198.51.100.0/24", "2001:db8:100::/48"} {
		_, dst, _ := net.ParseCIDR(cidr)
		if err := netlink.RouteAdd(&netlink.Route{Dst: dst, LinkIndex: up.Attrs().Index}); err != nil {
			t.Fatalf("main route %s: %v", cidr, err)
		}
	}
}

// reachesInVrf reports whether a route lookup for dst in the VRF's context
// (`ip route get <dst> vrf <name>`) resolves.
func reachesInVrf(t *testing.T, vrfName, dst string) bool {
	t.Helper()
	routes, err := netlink.RouteGetWithOptions(net.ParseIP(dst), &netlink.RouteGetOptions{VrfName: vrfName})
	return err == nil && len(routes) > 0
}

func createVrfOrSkip(t *testing.T, m *ResourceManager, name string, table uint32, noUnreachable bool) uint32 {
	t.Helper()
	ifindex, err := m.CreateVrf(name, table, nil, false, noUnreachable)
	if err != nil {
		if errors.Is(err, unix.EOPNOTSUPP) {
			t.Skipf("kernel lacks the vrf module: %v", err)
		}
		t.Fatalf("CreateVrf %s: %v", name, err)
	}
	return ifindex
}

// A created VRF's table ends in an unreachable default for both families, so
// a destination that only the main table has does not resolve in the VRF.
// The opt-out leaves the table as the kernel makes it, and the lookup goes
// on to main. Delete removes the routes again.
func TestCreateVrfUnreachableDefault(t *testing.T) {
	withTestNetns(t)
	mainRoutes(t)
	m := newTestManager(t)

	createVrfOrSkip(t, m, "vrf-u", 100, false)
	wantUnreachable(t, 100, 1)
	for _, dst := range []string{"198.51.100.1", "2001:db8:100::1"} {
		if reachesInVrf(t, "vrf-u", dst) {
			t.Errorf("%s resolves in vrf-u: the lookup reached the main table", dst)
		}
	}

	createVrfOrSkip(t, m, "vrf-open", 200, true)
	wantUnreachable(t, 200, 0)
	for _, dst := range []string{"198.51.100.1", "2001:db8:100::1"} {
		if !reachesInVrf(t, "vrf-open", dst) {
			t.Errorf("%s does not resolve in the opted-out vrf-open, want the main table's route", dst)
		}
	}
	if got, _ := m.GetVrfByName("vrf-open"); !got.NoUnreachableDefault {
		t.Errorf("state = %+v, want no_unreachable_default recorded", got)
	}

	// A second create of the same VRF (the adopt path) adds nothing.
	createVrfOrSkip(t, m, "vrf-u", 100, false)
	wantUnreachable(t, 100, 1)

	if err := m.DeleteVrf("vrf-u"); err != nil {
		t.Fatalf("DeleteVrf: %v", err)
	}
	wantUnreachable(t, 100, 0)
	if err := m.DeleteVrf("vrf-open"); err != nil {
		t.Fatalf("DeleteVrf: %v", err)
	}
}

// Adopting a device the operator made adds the unreachable default, and
// keeps the table's own default route: a unicast default at a better metric
// stays the route lookups use, and an unreachable default already at the
// same metric is kept, not duplicated or refused.
func TestAdoptVrfKeepsExistingDefault(t *testing.T) {
	withTestNetns(t)
	mainRoutes(t)
	m := newTestManager(t)

	for _, v := range []struct {
		name  string
		table uint32
	}{{"vrf-own", 300}, {"vrf-same", 400}} {
		if err := netlink.LinkAdd(&netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: v.name}, Table: v.table}); err != nil {
			if errors.Is(err, unix.EOPNOTSUPP) {
				t.Skipf("kernel lacks the vrf module: %v", err)
			}
			t.Fatalf("LinkAdd %s: %v", v.name, err)
		}
	}
	// vrf-own: the operator's default goes out of a port in the VRF.
	if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "own0"}}); err != nil {
		t.Fatal(err)
	}
	own0, _ := netlink.LinkByName("own0")
	vrfOwn, _ := netlink.LinkByName("vrf-own")
	if err := netlink.LinkSetMaster(own0, vrfOwn); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(own0); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(vrfOwn); err != nil {
		t.Fatal(err)
	}
	for _, cidr := range []string{"0.0.0.0/0", "::/0"} {
		_, dst, _ := net.ParseCIDR(cidr)
		if err := netlink.RouteAdd(&netlink.Route{Dst: dst, LinkIndex: own0.Attrs().Index, Table: 300}); err != nil {
			t.Fatalf("operator default %s: %v", cidr, err)
		}
	}
	// vrf-same: the operator already put the unreachable default there.
	if err := ensureUnreachableDefault(400); err != nil {
		t.Fatal(err)
	}

	createVrfOrSkip(t, m, "vrf-own", 300, false)
	createVrfOrSkip(t, m, "vrf-same", 400, false)
	wantUnreachable(t, 300, 1)
	wantUnreachable(t, 400, 1)
	for family, routes := range tableDefaults(t, 300) {
		if len(routes) != 2 {
			t.Errorf("table 300 family %d: %d defaults, want the operator's and the unreachable one", family, len(routes))
		}
	}
	for _, dst := range []string{"198.51.100.1", "2001:db8:100::1"} {
		routes, err := netlink.RouteGetWithOptions(net.ParseIP(dst), &netlink.RouteGetOptions{VrfName: "vrf-own"})
		if err != nil || len(routes) == 0 || routes[0].LinkIndex != own0.Attrs().Index {
			t.Errorf("%s in vrf-own: %+v, %v; want the operator's default out of own0", dst, routes, err)
		}
	}
}

// Delete removes the routes when the device is already gone, keeps them
// while another tracked VRF uses the same table, and leaves an opted-out
// VRF's table alone.
func TestDeleteVrfRemovesUnreachableDefault(t *testing.T) {
	withTestNetns(t)
	m := newTestManager(t)

	createVrfOrSkip(t, m, "vrf-gone", 100, false)
	link, err := netlink.LinkByName("vrf-gone")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkDel(link); err != nil {
		t.Fatal(err)
	}
	wantUnreachable(t, 100, 1) // the routes outlive the device
	if err := m.DeleteVrf("vrf-gone"); err != nil {
		t.Fatalf("DeleteVrf after out-of-band removal: %v", err)
	}
	wantUnreachable(t, 100, 0)

	createVrfOrSkip(t, m, "vrf-s1", 500, false)
	createVrfOrSkip(t, m, "vrf-s2", 500, false)
	if err := m.DeleteVrf("vrf-s1"); err != nil {
		t.Fatalf("DeleteVrf vrf-s1: %v", err)
	}
	wantUnreachable(t, 500, 1)
	if err := m.DeleteVrf("vrf-s2"); err != nil {
		t.Fatalf("DeleteVrf vrf-s2: %v", err)
	}
	wantUnreachable(t, 500, 0)

	// The opt-out VRF's table holds an unreachable default someone else put
	// there: deleting the VRF does not take it.
	if err := ensureUnreachableDefault(600); err != nil {
		t.Fatal(err)
	}
	createVrfOrSkip(t, m, "vrf-open", 600, true)
	if err := m.DeleteVrf("vrf-open"); err != nil {
		t.Fatalf("DeleteVrf vrf-open: %v", err)
	}
	wantUnreachable(t, 600, 1)
}

// After a reboot (device and routes gone) Reconcile recreates the device with
// its unreachable default; an adopt of a surviving device adds them too, and
// an opted-out entry gets none.
func TestReconcileUnreachableDefault(t *testing.T) {
	withTestNetns(t)
	m := newTestManager(t)
	createVrfOrSkip(t, m, "vrf-boot", 100, false)
	createVrfOrSkip(t, m, "vrf-kept", 200, false)
	createVrfOrSkip(t, m, "vrf-open", 300, true)
	for _, name := range []string{"vrf-boot", "vrf-open"} {
		link, err := netlink.LinkByName(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := netlink.LinkDel(link); err != nil {
			t.Fatal(err)
		}
	}
	for _, table := range []uint32{100, 200} {
		if err := removeUnreachableDefault(table); err != nil {
			t.Fatal(err)
		}
	}

	m2, err := NewResourceManager(m.statePath, zap.NewNop())
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if err := m2.Reconcile(); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	wantUnreachable(t, 100, 1)
	wantUnreachable(t, 200, 1)
	wantUnreachable(t, 300, 0)
}

// The state records the opt-out under no_unreachable_default and drops the
// key when unset, so a record written before the field existed reads as
// "add the routes". An adopt merges like the other device fields: the
// opt-out stays only while every request asks for it.
func TestManagedVrfNoUnreachableDefaultState(t *testing.T) {
	var old ManagedVrf
	if err := json.Unmarshal([]byte(`{"name":"v","table_id":100,"members":[],"enable_l3mdev_rule":false,"ifindex":3}`), &old); err != nil {
		t.Fatal(err)
	}
	if old.NoUnreachableDefault {
		t.Error("a record without the field reads as opted out")
	}
	b, _ := json.Marshal(ManagedVrf{Name: "v", TableID: 100})
	var keys map[string]any
	_ = json.Unmarshal(b, &keys)
	if _, ok := keys["no_unreachable_default"]; ok {
		t.Errorf("unset opt-out is written: %s", b)
	}

	m := &ResourceManager{state: &ManagedState{}, logger: zap.NewNop()}
	m.ensureVrfInState("v", 100, nil, false, true, 3)
	m.ensureVrfInState("v", 100, nil, false, true, 3)
	if got, _ := m.GetVrfByName("v"); !got.NoUnreachableDefault {
		t.Errorf("opt-out adopt of an opted-out VRF: %+v, want it kept", got)
	}
	m.ensureVrfInState("v", 100, nil, false, false, 3)
	if got, _ := m.GetVrfByName("v"); got.NoUnreachableDefault {
		t.Errorf("default adopt of an opted-out VRF: %+v, want the routes recorded", got)
	}
	m.ensureVrfInState("v", 100, nil, false, true, 3)
	if got, _ := m.GetVrfByName("v"); got.NoUnreachableDefault {
		t.Errorf("opt-out adopt after the routes were added: %+v, want them still recorded", got)
	}
}
