package netresource

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// withTestNetns runs the test in a fresh network namespace (same pattern as
// pkg/fib): netlink calls are namespace-scoped, so device/rule churn cannot
// touch the host. Requires root / CAP_NET_ADMIN.
func withTestNetns(t *testing.T) {
	t.Helper()
	runtime.LockOSThread()
	orig, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatalf("netns.Get: %v", err)
	}
	ns, err := netns.New()
	if err != nil {
		_ = orig.Close()
		runtime.UnlockOSThread()
		t.Fatalf("netns.New (needs root / CAP_NET_ADMIN): %v", err)
	}
	t.Cleanup(func() {
		_ = netns.Set(orig)
		_ = orig.Close()
		_ = ns.Close()
		runtime.UnlockOSThread()
	})
}

func newTestManager(t *testing.T) *ResourceManager {
	t.Helper()
	statePath := filepath.Join(t.TempDir(), "state.json")
	m, err := NewResourceManager(statePath, zap.NewNop())
	if err != nil {
		t.Fatalf("NewResourceManager: %v", err)
	}
	return m
}

// hasL3mdevRule reports whether a rule at l3mdevRulePriority with no table
// exists (how a FRA_L3MDEV rule parses back through RuleList).
func hasL3mdevRule(t *testing.T, family int) bool {
	t.Helper()
	rules, err := netlink.RuleList(family)
	if err != nil {
		t.Fatalf("RuleList: %v", err)
	}
	for _, r := range rules {
		if r.IifName == "" && r.Table == 0 && r.Priority == l3mdevRulePriority {
			return true
		}
	}
	return false
}

// The l3mdev rule installs for both families and is idempotent. The released
// netlink Rule API cannot express FRA_L3MDEV (its plain-rule fallback was a
// wrong `lookup <n>` rule for v4 and an EINVAL for v6), so this pins the raw
// message path.
func TestEnsureL3mdevRule(t *testing.T) {
	withTestNetns(t)
	if err := ensureL3mdevRule(); err != nil {
		t.Fatalf("ensureL3mdevRule: %v", err)
	}
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		if !hasL3mdevRule(t, family) {
			t.Errorf("family %d: l3mdev rule missing", family)
		}
	}
	// Idempotent: a second call must not error or double-install.
	if err := ensureL3mdevRule(); err != nil {
		t.Fatalf("ensureL3mdevRule (second): %v", err)
	}
}

// CreateVrf creates the device, enslaves members, and persists; the adopt
// path refuses a non-VRF link and a table mismatch, and converges members on
// a legitimate re-create. DeleteVrf is idempotent when the device was removed
// out-of-band.
func TestCreateDeleteVrf(t *testing.T) {
	withTestNetns(t)
	m := newTestManager(t)

	// A member interface to enslave.
	if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "vrftest0"}}); err != nil {
		t.Fatalf("LinkAdd dummy: %v", err)
	}

	ifindex, err := m.CreateVrf("vrf-t", 100, []string{"vrftest0"}, true)
	if err != nil {
		t.Fatalf("CreateVrf: %v", err)
	}
	if ifindex == 0 {
		t.Fatal("CreateVrf returned ifindex 0")
	}
	link, err := netlink.LinkByName("vrf-t")
	if err != nil {
		t.Fatalf("LinkByName: %v", err)
	}
	if _, ok := link.(*netlink.Vrf); !ok {
		t.Fatalf("created link is %s, want vrf", link.Type())
	}
	member, _ := netlink.LinkByName("vrftest0")
	if member.Attrs().MasterIndex != int(ifindex) {
		t.Errorf("member not enslaved: master %d, want %d", member.Attrs().MasterIndex, ifindex)
	}
	if !hasL3mdevRule(t, unix.AF_INET) || !hasL3mdevRule(t, unix.AF_INET6) {
		t.Error("l3mdev rule missing after CreateVrf with enableL3mdevRule")
	}

	// Idempotent re-create adopts (same ifindex); a table mismatch refuses.
	if again, err := m.CreateVrf("vrf-t", 100, nil, false); err != nil || again != ifindex {
		t.Errorf("adopt = (%d, %v), want (%d, nil)", again, err, ifindex)
	}
	if _, err := m.CreateVrf("vrf-t", 200, nil, false); err == nil ||
		!strings.Contains(err.Error(), "table") {
		t.Errorf("table-mismatch adopt: err = %v, want table error", err)
	}
	// Adopting a non-VRF link by name refuses.
	if _, err := m.CreateVrf("vrftest0", 100, nil, false); err == nil {
		t.Error("adopting a dummy link as VRF: want error")
	}

	// Out-of-band removal: DeleteVrf still clears the state entry.
	if err := netlink.LinkDel(link); err != nil {
		t.Fatalf("LinkDel: %v", err)
	}
	if err := m.DeleteVrf("vrf-t"); err != nil {
		t.Fatalf("DeleteVrf after out-of-band removal: %v", err)
	}
	if len(m.ListVrfs()) != 0 {
		t.Errorf("state still holds VRFs after delete: %+v", m.ListVrfs())
	}
	// State survived on disk without the deleted entry.
	if _, err := os.Stat(m.statePath); err != nil {
		t.Errorf("state file missing: %v", err)
	}
}
