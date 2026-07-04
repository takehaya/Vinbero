package netresource

import (
	"errors"
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
		// EOPNOTSUPP = the kernel has no vrf module (CI loads it via
		// modprobe; a minimal dev kernel may not ship it at all).
		if errors.Is(err, unix.EOPNOTSUPP) {
			t.Skipf("kernel lacks the vrf module: %v", err)
		}
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
	// An adopt with unspecified members/l3mdev (the CLI defaults) must MERGE
	// into the tracked entry, not weaken it: the recorded members and l3mdev
	// flag survive so a post-reboot Reconcile recreates the full device.
	if again, err := m.CreateVrf("vrf-t", 100, nil, false); err != nil || again != ifindex {
		t.Errorf("adopt = (%d, %v), want (%d, nil)", again, err, ifindex)
	}
	if vrfs := m.ListVrfs(); len(vrfs) != 1 ||
		len(vrfs[0].Members) != 1 || vrfs[0].Members[0] != "vrftest0" || !vrfs[0].EnableL3mdevRule {
		t.Errorf("adopt weakened the state entry: %+v", vrfs)
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

// CreateBridge creates the device up with members enslaved and persists the
// owning VRF; the adopt path refuses a non-bridge link, a tracked bd_id
// mismatch and a foreign owner, and converges (UP + missing members) on a
// legitimate re-attach without weakening the state record. DeleteBridge is
// idempotent when the device was removed out-of-band.
func TestCreateDeleteBridge(t *testing.T) {
	withTestNetns(t)
	m := newTestManager(t)

	if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "brtest0"}}); err != nil {
		t.Fatalf("LinkAdd dummy: %v", err)
	}

	ifindex, err := m.CreateBridge("br-t", 100, []string{"brtest0"}, "evi-100")
	if err != nil {
		t.Fatalf("CreateBridge: %v", err)
	}
	link, err := netlink.LinkByName("br-t")
	if err != nil {
		t.Fatalf("LinkByName: %v", err)
	}
	if _, ok := link.(*netlink.Bridge); !ok {
		t.Fatalf("created link is %s, want bridge", link.Type())
	}
	member, _ := netlink.LinkByName("brtest0")
	if member.Attrs().MasterIndex != int(ifindex) {
		t.Errorf("member not enslaved: master %d, want %d", member.Attrs().MasterIndex, ifindex)
	}
	if got, ok := m.GetBridgeByName("br-t"); !ok || got.VRF != "evi-100" || got.BdID != 100 {
		t.Errorf("state = %+v, want owner evi-100 bd 100", got)
	}

	// Owner round-trips through the state file.
	m2, err := NewResourceManager(m.statePath, zap.NewNop())
	if err != nil {
		t.Fatalf("NewResourceManager reload: %v", err)
	}
	if got, ok := m2.GetBridgeByName("br-t"); !ok || got.VRF != "evi-100" {
		t.Errorf("reloaded state = %+v, want owner evi-100", got)
	}

	// Adopt refusals: bd_id mismatch, foreign owner, non-bridge link.
	if _, err := m.CreateBridge("br-t", 200, nil, "evi-100"); err == nil ||
		!strings.Contains(err.Error(), "bd_id") {
		t.Errorf("bd_id-mismatch adopt: err = %v, want bd_id error", err)
	}
	if _, err := m.CreateBridge("br-t", 100, nil, "other-vrf"); err == nil ||
		!strings.Contains(err.Error(), "owned") {
		t.Errorf("foreign-owner adopt: err = %v, want owner error", err)
	}
	if _, err := m.CreateBridge("brtest0", 100, nil, "evi-100"); err == nil {
		t.Error("adopting a dummy link as bridge: want error")
	}

	// Legitimate adopt converges: same owner/bd, no weakening of members.
	if again, err := m.CreateBridge("br-t", 100, nil, "evi-100"); err != nil || again != ifindex {
		t.Errorf("adopt = (%d, %v), want (%d, nil)", again, err, ifindex)
	}
	if got, _ := m.GetBridgeByName("br-t"); len(got.Members) != 1 || got.Members[0] != "brtest0" {
		t.Errorf("adopt weakened the state entry: %+v", got)
	}

	// Out-of-band removal: DeleteBridge still clears the state entry.
	if err := netlink.LinkDel(link); err != nil {
		t.Fatalf("LinkDel: %v", err)
	}
	if err := m.DeleteBridge("br-t"); err != nil {
		t.Fatalf("DeleteBridge after out-of-band removal: %v", err)
	}
	if len(m.ListBridges()) != 0 {
		t.Errorf("state still holds bridges after delete: %+v", m.ListBridges())
	}
}
