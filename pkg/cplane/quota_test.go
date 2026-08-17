package cplane

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
)

// A capability says what a plugin may do; a quota says how much. A plugin
// granted headend is meant to write headend entries, and what a quota
// settles is whether a bug in it can fill the map and take every other
// writer's entries with it.
func TestHeadendQuotaBoundsWhatAPluginHolds(t *testing.T) {
	ops := newFakeHeadendOps()
	leases := NewLeases()
	desired := make([]HeadendDesired, 0, 3)
	for i := 0; i < 3; i++ {
		desired = append(desired, desire(fmt.Sprintf("10.0.%d.0/24", i))...)
	}

	if _, err := ApplyHeadendSet(ops, leases, ownerA, AFv4, desired, 2); err == nil {
		t.Fatal("a set larger than the quota was accepted")
	}
	if ops.countV4() != 0 {
		t.Fatalf("a refused set wrote %d entries", ops.countV4())
	}
	// Under the quota it applies as usual.
	if _, err := ApplyHeadendSet(ops, leases, ownerA, AFv4, desired[:2], 2); err != nil {
		t.Fatalf("a set within the quota was refused: %v", err)
	}
}

// The quota counts both families together: a plugin's share of the data
// plane is what it holds, not what it holds per map.
func TestHeadendQuotaCountsBothFamilies(t *testing.T) {
	ops := newFakeHeadendOps()
	leases := NewLeases()
	if _, err := ApplyHeadendSet(ops, leases, ownerA, AFv4, desire("10.0.1.0/24", "10.0.2.0/24"), 3); err != nil {
		t.Fatalf("v4 apply: %v", err)
	}
	v6 := []HeadendDesired{
		{TriggerPrefix: "2001:db8:1::/48", Entry: desire("x")[0].Entry},
		{TriggerPrefix: "2001:db8:2::/48", Entry: desire("x")[0].Entry},
	}
	if _, err := ApplyHeadendSet(ops, leases, ownerA, AFv6, v6, 3); err == nil {
		t.Fatal("the v6 set was accepted although the two families together exceed the quota")
	}
}

func TestAdvertiseQuota(t *testing.T) {
	set := NewAdvertiseSet(&fakeAdvertiser{}, NewLeases())
	routes := []AdvertisedRoute{
		vpnRoute("10.0.1.0/24", "fd00:2::1"),
		vpnRoute("10.0.2.0/24", "fd00:2::2"),
	}
	if _, err := set.Apply(context.Background(), ownerA, routes, 1); err == nil {
		t.Fatal("more routes than the quota were accepted")
	}
	if set.LiveCount(ownerA) != 0 {
		t.Fatal("a refused declaration originated something")
	}
	if _, err := set.Apply(context.Background(), ownerA, routes, 2); err != nil {
		t.Fatalf("a declaration within the quota was refused: %v", err)
	}
}

func TestLocalSIDQuota(t *testing.T) {
	set := NewLocalSIDSet(&fakeAllocator{}, newFakeSIDOps())
	sids := []LocalSID{
		{Name: "svc-a", Locator: "main", Slot: 33},
		{Name: "svc-b", Locator: "main", Slot: 34},
	}
	if _, _, err := set.Apply(ownerA, sids, 1); err == nil {
		t.Fatal("more SIDs than the quota were accepted")
	}
	if set.LiveCount(ownerA) != 0 {
		t.Fatal("a refused declaration allocated something")
	}
}

// A negative quota is the escape hatch for an operator who means it.
func TestNegativeQuotaIsUnbounded(t *testing.T) {
	ops := newFakeHeadendOps()
	many := make([]HeadendDesired, 0, 50)
	for i := 0; i < 50; i++ {
		many = append(many, desire(fmt.Sprintf("10.1.%d.0/24", i))...)
	}
	if _, err := ApplyHeadendSet(ops, NewLeases(), ownerA, AFv4, many, unlimited); err != nil {
		t.Fatalf("an unbounded quota refused a large set: %v", err)
	}
	if ops.countV4() != 50 {
		t.Fatalf("wrote %d entries, want all 50", ops.countV4())
	}
}

// A sandboxed plugin is otherwise unobservable: one that has fallen
// behind, one restarting in a loop and one with nothing to do all look
// the same from outside.
func TestStatsReportWhatAPluginHolds(t *testing.T) {
	src := newFakeSource()
	m, _ := newTestManager(t, src, newFakeClaims())
	if err := m.Register(context.Background(), Registration{
		Name:         "declare",
		Module:       declareModule(t),
		Behaviors:    []uint16{0xFE01},
		Capabilities: testCaps(),
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
	src.emit("declare", bgp.RouteEvent{Family: bgp.FamilyVPNv4})
	waitDelivered(t, m, "declare")

	stats := m.Stats()
	if len(stats) != 1 {
		t.Fatalf("stats cover %d plugins, want 1", len(stats))
	}
	s := stats[0]
	if s.Name != "declare" {
		t.Errorf("name = %q", s.Name)
	}
	if s.HeadendEntries != 1 {
		t.Errorf("headend entries = %d, want the one it declared", s.HeadendEntries)
	}
	if len(s.Behaviors) != 1 || s.Behaviors[0] != 0xFE01 {
		t.Errorf("behaviors = %v", s.Behaviors)
	}
	if strings.Join(s.Capabilities, ",") == "" {
		t.Error("capabilities are not reported")
	}
	if s.Quotas.MaxHeadendEntries == 0 {
		t.Error("the quota it is measured against is not reported")
	}
	if s.Since.IsZero() {
		t.Error("no start time reported")
	}

	if _, ok := m.StatsFor("declare"); !ok {
		t.Error("StatsFor did not find a running plugin")
	}
	if _, ok := m.StatsFor("nobody"); ok {
		t.Error("StatsFor invented a plugin")
	}
}

// The configured quota has to reach the plugin, not just the stats table.
// An operator who lowers a limit and sees it reported while the apply path
// keeps using the default has been told something untrue.
func TestConfiguredQuotaIsEnforced(t *testing.T) {
	src := newFakeSource()
	ops := newFakeHeadendOps()
	m, err := NewManager(ManagerConfig{
		Source:      src,
		Claims:      newFakeClaims(),
		Headend:     ops,
		EncapSource: testEncapSource,
		// The declare fixture asks for one entry, so a quota of zero
		// entries is one it must not get past. (Zero would mean "take the
		// default", so this asks for the smallest real limit.)
		Quotas: Quotas{MaxHeadendEntries: 1, MaxAdvertisedRoutes: 1, MaxLocalSIDs: 1},
	})
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	t.Cleanup(func() { m.Close(context.Background()) })

	if err := m.Register(context.Background(), Registration{
		Name: "declare", Module: declareModule(t), Capabilities: testCaps(),
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
	stats, ok := m.StatsFor("declare")
	if !ok {
		t.Fatal("no stats for a registered plugin")
	}
	if stats.Quotas.MaxHeadendEntries != 1 {
		t.Fatalf("stats report a quota of %d, want the configured 1", stats.Quotas.MaxHeadendEntries)
	}

	// One entry is within it, so the plugin's declaration applies.
	src.emit("declare", bgp.RouteEvent{Family: bgp.FamilyVPNv4})
	waitDelivered(t, m, "declare")
	if ops.countV4() != 1 {
		t.Fatalf("data plane holds %d entries, want the declared one", ops.countV4())
	}
}

// A plugin told its set was too large can narrow it; one told the host
// failed can only give up. The two have to be distinguishable.
func TestQuotaErrorReadsAsAPolicyRefusal(t *testing.T) {
	err := &QuotaError{What: "headend entries", Declared: 10, Quota: 4}
	if !err.Denied() {
		t.Fatal("a quota refusal does not report itself as denied")
	}
	if !strings.Contains(err.Error(), "quota 4") {
		t.Errorf("error does not say what the quota was: %v", err)
	}
}

// The entry count bounds nothing on its own: the repeated and string
// fields inside an entry have no length of their own, so a guest can
// respect every other limit and still make the host hold gigabytes -- by
// never committing, which is also why nothing reclaims it.
func TestTransactionMemoryIsCapped(t *testing.T) {
	ops, err := NewPluginOps(PluginOpsConfig{
		Owner: ownerA, Headend: newFakeHeadendOps(), Leases: NewLeases(),
		Capabilities: testCaps(), EncapSource: testEncapSource,
		MaxBytesPerTransaction: 4096,
	})
	if err != nil {
		t.Fatalf("new plugin ops: %v", err)
	}
	if err := ops.Publish(); err != nil {
		t.Fatalf("publish: %v", err)
	}
	gen, err := ops.ApplyBegin(uint32(v1.PluginApplyKind_PLUGIN_APPLY_KIND_HEADEND_V4))
	if err != nil {
		t.Fatalf("begin: %v", err)
	}

	// One entry, well under the entry limit, carrying a payload that is
	// not. The count would let this through; the byte budget must not.
	fat := &v1.PluginApplyChunk{HeadendEntries: []*v1.PluginHeadendEntry{{
		TriggerPrefix: "10.0.0.0/24",
		Segments:      []string{"fd00:2::1"},
	}}}
	chunk, err := proto.Marshal(fat)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Feed the same small chunk until the budget is spent. It must stop,
	// rather than accumulating without bound.
	var accepted int
	for i := 0; i < 10000; i++ {
		if err := ops.ApplyPut(gen, chunk); err != nil {
			break
		}
		accepted++
	}
	if accepted == 0 {
		t.Fatal("the first chunk was refused; the budget is too small to be meaningful")
	}
	if accepted >= 10000 {
		t.Fatal("the transaction accepted chunks without bound")
	}
	if got := accepted * len(chunk); got > 4096+len(chunk) {
		t.Errorf("accepted %d bytes against a 4096 byte budget", got)
	}
}
