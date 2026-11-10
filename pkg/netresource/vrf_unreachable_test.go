package netresource

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
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
	if got, _ := m.GetVrfByName("vrf-u"); got.OptedOut() || len(got.UnreachableDefaultAdded) != 2 {
		t.Errorf("state = %+v, want both families recorded as added", got)
	}

	createVrfOrSkip(t, m, "vrf-open", 200, true)
	wantUnreachable(t, 200, 0)
	for _, dst := range []string{"198.51.100.1", "2001:db8:100::1"} {
		if !reachesInVrf(t, "vrf-open", dst) {
			t.Errorf("%s does not resolve in the opted-out vrf-open, want the main table's route", dst)
		}
	}
	if got, _ := m.GetVrfByName("vrf-open"); !got.OptedOut() {
		t.Errorf("state = %+v, want no_unreachable_default recorded", got)
	}

	// A second create of the same VRF (the adopt path) adds nothing, and one
	// that asks for the other setting is refused.
	createVrfOrSkip(t, m, "vrf-u", 100, false)
	wantUnreachable(t, 100, 1)
	if _, err := m.CreateVrf("vrf-u", 100, nil, false, true); err == nil {
		t.Error("changing the setting of vrf-u at runtime: want an error")
	}
	if _, err := m.CreateVrf("vrf-open", 200, nil, false, false); err == nil {
		t.Error("changing the setting of vrf-open at runtime: want an error")
	}
	wantUnreachable(t, 100, 1)
	wantUnreachable(t, 200, 0)

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
// same metric is kept, not duplicated or refused, and is not removed by the
// VRF's delete because Vinbero did not add it.
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
	addOperatorUnreachable(t, 400)

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
	if got, _ := m.GetVrfByName("vrf-same"); len(got.UnreachableDefaultAdded) != 0 {
		t.Errorf("vrf-same records %v as added, want none (the operator's routes were there)", got.UnreachableDefaultAdded)
	}
	if err := m.DeleteVrf("vrf-same"); err != nil {
		t.Fatalf("DeleteVrf vrf-same: %v", err)
	}
	wantUnreachable(t, 400, 1) // the operator's, left alone
}

// addOperatorUnreachable puts an unreachable default into table the way an
// operator would, outside the resource manager.
func addOperatorUnreachable(t *testing.T, table uint32) {
	t.Helper()
	for _, f := range []string{familyIPv4, familyIPv6} {
		if err := netlink.RouteAdd(unreachableDefault(table, f)); err != nil {
			t.Fatalf("operator unreachable %s: %v", f, err)
		}
	}
}

// Delete removes the routes when the device is already gone. On a table
// another VRF uses, they stay while a tracked VRF that did not opt out uses
// it (that VRF takes them over) or a VRF device Vinbero does not track uses
// it; a tracked VRF that opted out does not keep them.
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

	// Two tracked VRFs that want the routes: the second takes them over.
	createVrfOrSkip(t, m, "vrf-s1", 500, false)
	createVrfOrSkip(t, m, "vrf-s2", 500, false)
	if err := m.DeleteVrf("vrf-s1"); err != nil {
		t.Fatalf("DeleteVrf vrf-s1: %v", err)
	}
	wantUnreachable(t, 500, 1)
	if got, _ := m.GetVrfByName("vrf-s2"); len(got.UnreachableDefaultAdded) != 2 {
		t.Errorf("vrf-s2 = %+v, want it to have taken the routes over", got)
	}
	if err := m.DeleteVrf("vrf-s2"); err != nil {
		t.Fatalf("DeleteVrf vrf-s2: %v", err)
	}
	wantUnreachable(t, 500, 0)

	// A VRF with the routes and one that opted out on the same table:
	// deleting the first removes them, whichever goes first.
	createVrfOrSkip(t, m, "vrf-m1", 600, false)
	createVrfOrSkip(t, m, "vrf-m2", 600, true)
	if err := m.DeleteVrf("vrf-m2"); err != nil {
		t.Fatalf("DeleteVrf vrf-m2: %v", err)
	}
	wantUnreachable(t, 600, 1)
	createVrfOrSkip(t, m, "vrf-m2", 600, true)
	if err := m.DeleteVrf("vrf-m1"); err != nil {
		t.Fatalf("DeleteVrf vrf-m1: %v", err)
	}
	wantUnreachable(t, 600, 0)
	if err := m.DeleteVrf("vrf-m2"); err != nil {
		t.Fatalf("DeleteVrf vrf-m2: %v", err)
	}

	// An untracked VRF device on the table keeps the routes.
	createVrfOrSkip(t, m, "vrf-t1", 700, false)
	if err := netlink.LinkAdd(&netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: "vrf-raw"}, Table: 700}); err != nil {
		t.Fatalf("LinkAdd vrf-raw: %v", err)
	}
	if err := m.DeleteVrf("vrf-t1"); err != nil {
		t.Fatalf("DeleteVrf vrf-t1: %v", err)
	}
	wantUnreachable(t, 700, 1)
}

// A create that fails after the routes went in (a member that does not
// exist) leaves no device, no route and no record behind.
func TestCreateVrfFailureRollsBack(t *testing.T) {
	withTestNetns(t)
	m := newTestManager(t)
	if _, err := m.CreateVrf("vrf-bad", 100, []string{"nosuchif0"}, false, false); err == nil {
		t.Fatal("CreateVrf with a missing member: want an error")
	} else if errors.Is(err, unix.EOPNOTSUPP) {
		t.Skipf("kernel lacks the vrf module: %v", err)
	}
	if _, err := netlink.LinkByName("vrf-bad"); err == nil {
		t.Error("the device of the failed create is still there")
	}
	wantUnreachable(t, 100, 0)
	if _, ok := m.GetVrfByName("vrf-bad"); ok {
		t.Error("the failed create left a record")
	}

	// The same for an adopt: the operator's device stays, the routes the
	// adopt added go.
	if err := netlink.LinkAdd(&netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: "vrf-op"}, Table: 200}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.CreateVrf("vrf-op", 200, []string{"nosuchif0"}, false, false); err == nil {
		t.Fatal("adopt with a missing member: want an error")
	}
	wantUnreachable(t, 200, 0)
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
		if err := m.removeUnreachableFamilies(table, []string{familyIPv4, familyIPv6}); err != nil {
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

// writeLegacyState writes a state file whose VRF record predates the
// unreachable-default fields.
func writeLegacyState(t *testing.T, path, name string, table uint32) {
	t.Helper()
	data := []byte(`{"vrfs":[{"name":"` + name + `","table_id":` + strconv.Itoa(int(table)) +
		`,"members":[],"enable_l3mdev_rule":false,"ifindex":0}],"bridges":[]}`)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// On the first start with a state record from before the setting existed,
// the config's opt-out wins: Reconcile adds no route to that table. A record
// the config does not mention gets the routes. The decision is recorded.
func TestReconcileLegacyRecordFollowsConfig(t *testing.T) {
	withTestNetns(t)
	path := filepath.Join(t.TempDir(), "state.json")
	writeLegacyState(t, path, "vrf-legacy", 100)
	m, err := NewResourceManager(path, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	m.SetConfigUnreachableDefault(map[string]bool{"vrf-legacy": true})
	if err := m.Reconcile(); err != nil {
		if errors.Is(err, unix.EOPNOTSUPP) {
			t.Skipf("kernel lacks the vrf module: %v", err)
		}
		t.Fatalf("Reconcile: %v", err)
	}
	wantUnreachable(t, 100, 0)
	if got, _ := m.GetVrfByName("vrf-legacy"); got.NoUnreachableDefault == nil || !*got.NoUnreachableDefault {
		t.Errorf("state = %+v, want the config's opt-out recorded", got)
	}

	path2 := filepath.Join(t.TempDir(), "state.json")
	writeLegacyState(t, path2, "vrf-plain", 200)
	m2, err := NewResourceManager(path2, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if err := m2.Reconcile(); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	wantUnreachable(t, 200, 1)
	if got, _ := m2.GetVrfByName("vrf-plain"); got.NoUnreachableDefault == nil || *got.NoUnreachableDefault {
		t.Errorf("state = %+v, want the default (routes added) recorded", got)
	}
}

// A config that opts a VRF out after it had the routes takes effect at the
// next start: Reconcile removes the routes Vinbero added. Turning the opt-out
// off again adds them back.
func TestReconcileConfigChangesOptOut(t *testing.T) {
	withTestNetns(t)
	m := newTestManager(t)
	createVrfOrSkip(t, m, "vrf-c", 100, false)
	wantUnreachable(t, 100, 1)

	m2, err := NewResourceManager(m.statePath, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	m2.SetConfigUnreachableDefault(map[string]bool{"vrf-c": true})
	if err := m2.Reconcile(); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	wantUnreachable(t, 100, 0)
	if got, _ := m2.GetVrfByName("vrf-c"); !got.OptedOut() || len(got.UnreachableDefaultAdded) != 0 {
		t.Errorf("state = %+v, want opted out with nothing added", got)
	}

	m3, err := NewResourceManager(m.statePath, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	m3.SetConfigUnreachableDefault(map[string]bool{"vrf-c": false})
	if err := m3.Reconcile(); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	wantUnreachable(t, 100, 1)
}

// The state records the setting under no_unreachable_default and leaves it
// out while undecided; the added families round-trip. Unprivileged.
func TestManagedVrfUnreachableDefaultState(t *testing.T) {
	var old ManagedVrf
	if err := json.Unmarshal([]byte(`{"name":"v","table_id":100,"members":[],"enable_l3mdev_rule":false,"ifindex":3}`), &old); err != nil {
		t.Fatal(err)
	}
	if old.NoUnreachableDefault != nil || old.OptedOut() {
		t.Errorf("a record without the field = %+v, want undecided", old)
	}
	b, _ := json.Marshal(ManagedVrf{Name: "v", TableID: 100})
	var keys map[string]any
	_ = json.Unmarshal(b, &keys)
	if _, ok := keys["no_unreachable_default"]; ok {
		t.Errorf("an undecided setting is written: %s", b)
	}
	v := ManagedVrf{Name: "v", TableID: 100}
	v.setNoUnreachableDefault(false)
	v.addUnreachableFamilies([]string{familyIPv4, familyIPv6, familyIPv4})
	b, _ = json.Marshal(v)
	var back ManagedVrf
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.NoUnreachableDefault == nil || *back.NoUnreachableDefault || len(back.UnreachableDefaultAdded) != 2 {
		t.Errorf("round trip = %+v from %s", back, b)
	}
}

// With IPv6 disabled on the host (the route add fails with EAFNOSUPPORT),
// the IPv4 route still goes in and the create does not fail; the condition
// is logged once. Unprivileged: the route calls are replaced.
func TestEnsureUnreachableDefaultWithoutIPv6(t *testing.T) {
	var added []string
	routeAdd = func(r *netlink.Route) error {
		if r.Dst.IP.To4() == nil {
			return unix.EAFNOSUPPORT
		}
		added = append(added, r.Dst.String())
		return nil
	}
	t.Cleanup(func() { routeAdd = netlink.RouteAdd })
	core, logs := observer.New(zap.InfoLevel)
	m := &ResourceManager{state: &ManagedState{}, logger: zap.New(core)}
	for range 2 {
		got, err := m.ensureUnreachableDefault(100)
		if err != nil {
			t.Fatalf("ensureUnreachableDefault: %v", err)
		}
		if len(got) != 1 || got[0] != familyIPv4 {
			t.Errorf("added families = %v, want [ipv4]", got)
		}
	}
	if len(added) != 2 {
		t.Errorf("IPv4 routes added = %v, want one per call", added)
	}
	if n := logs.FilterMessageSnippet("IPv6 is not available").Len(); n != 1 {
		t.Errorf("logged the missing IPv6 %d times, want once", n)
	}

	// Any other failure is an error, and the IPv4 route the call added is
	// taken back.
	var removed []string
	routeAdd = func(r *netlink.Route) error {
		if r.Dst.IP.To4() == nil {
			return unix.EPERM
		}
		return nil
	}
	routeDel = func(r *netlink.Route) error { removed = append(removed, r.Dst.String()); return nil }
	t.Cleanup(func() { routeDel = netlink.RouteDel })
	if _, err := m.ensureUnreachableDefault(100); err == nil {
		t.Error("an IPv6 failure other than EAFNOSUPPORT: want an error")
	}
	if len(removed) != 1 || removed[0] != "0.0.0.0/0" {
		t.Errorf("removed = %v, want the IPv4 route taken back", removed)
	}
}
