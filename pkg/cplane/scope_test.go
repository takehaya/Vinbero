package cplane

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

// narrowScope is a scope with one of everything, for the tests about what
// falls outside it.
func narrowScope(t *testing.T) Scope {
	t.Helper()
	scope, err := ParseScope(ScopeSpec{
		Locators:        []string{"main"},
		VRFs:            []string{testVRF},
		HeadendPrefixes: []string{"10.7.0.0/16"},
		HeadendV4Slots:  []uint32{16},
		HeadendV6Slots:  []uint32{16},
		EndpointSlots:   []uint32{33},
	})
	if err != nil {
		t.Fatalf("parse scope: %v", err)
	}
	return scope
}

func TestParseScopeCanonicalizes(t *testing.T) {
	scope, err := ParseScope(ScopeSpec{
		Locators: []string{"b", "a", "a"},
		// Unmasked, and out of order. The trigger prefixes it is compared
		// against are masked, so a scope holding the unmasked spelling
		// would compare against something the map never contains.
		HeadendPrefixes: []string{"fd00::/16", "10.7.0.1/16"},
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if strings.Join(scope.Locators, ",") != "a,b" {
		t.Errorf("locators = %v, want them sorted and deduplicated", scope.Locators)
	}
	if got := strings.Join(scope.HeadendPrefixStrings(), ","); got != "10.7.0.0/16,fd00::/16" {
		t.Errorf("headend prefixes = %q, want them masked and sorted", got)
	}
}

// A scope written with a 4-in-6 spelling compares false against every IPv4
// trigger prefix, so it would silently permit nothing.
func TestParseScopeRefusesFourInSix(t *testing.T) {
	if _, err := ParseScope(ScopeSpec{HeadendPrefixes: []string{"::ffff:10.7.0.0/112"}}); err == nil {
		t.Fatal("an IPv4 prefix in IPv6 form was accepted")
	}
}

func TestParseScopeRefusesASlotOutsideThePluginRange(t *testing.T) {
	if _, err := ParseScope(ScopeSpec{HeadendV4Slots: []uint32{1}}); err == nil {
		t.Error("a headend v4 slot outside the plugin range was accepted")
	}
	if _, err := ParseScope(ScopeSpec{HeadendV6Slots: []uint32{1}}); err == nil {
		t.Error("a headend v6 slot outside the plugin range was accepted")
	}
	if _, err := ParseScope(ScopeSpec{EndpointSlots: []uint32{1}}); err == nil {
		t.Error("an endpoint slot outside the plugin range was accepted")
	}
}

// The zero scope is what a registration that named none produces, and it
// has to deny rather than permit: a capability alone must not be enough to
// write anything.
func TestTheZeroScopePermitsNothing(t *testing.T) {
	var scope Scope
	if !scope.Empty() {
		t.Fatal("the zero scope reports itself as holding something")
	}
	if err := scope.CheckHeadend(AFv4, "10.7.0.0/24", 1); err == nil {
		t.Error("a headend entry was allowed with no scope")
	}
	if err := scope.CheckLocalSID(LocalSID{Name: "svc", Locator: "main", Slot: 33}); err == nil {
		t.Error("a local SID was allowed with no scope")
	}
	if err := scope.CheckAdvertised(AdvertisedRoute{
		Family: bgp.FamilyVPNv4, VRF: testVRF, Prefix: "10.7.0.0/24",
	}); err == nil {
		t.Error("a VPN route was allowed with no scope")
	}
}

// The headend maps are LPM tries keyed on the destination alone, so a
// longer prefix wins the lookup without ever touching the entry it
// shadows. Containment is the only thing holding a plugin off another
// writer's traffic.
func TestHeadendScopeContains(t *testing.T) {
	scope := narrowScope(t)
	if err := scope.CheckHeadend(AFv4, "10.7.1.0/24", 1); err != nil {
		t.Errorf("a prefix inside the scope was refused: %v", err)
	}
	// The scope's own prefix is inside itself.
	if err := scope.CheckHeadend(AFv4, "10.7.0.0/16", 1); err != nil {
		t.Errorf("the scope's own prefix was refused: %v", err)
	}
	for _, outside := range []string{"10.8.0.0/24", "0.0.0.0/0", "10.0.0.0/8", "fd00::/64"} {
		if err := scope.CheckHeadend(AFv4, outside, 1); err == nil {
			t.Errorf("%s was allowed, and it is outside the scope", outside)
		}
	}
}

// A plugin pointing an entry at another plugin's slot would have its aux
// bytes read under a layout that does not describe them.
func TestHeadendScopeChecksThePluginSlot(t *testing.T) {
	scope := narrowScope(t)
	if err := scope.CheckHeadend(AFv4, "10.7.1.0/24", 16); err != nil {
		t.Errorf("the plugin's own slot was refused: %v", err)
	}
	if err := scope.CheckHeadend(AFv4, "10.7.1.0/24", 17); err == nil {
		t.Error("another plugin's headend slot was allowed")
	}
	// A mode naming one of vinbero's own behaviors is ordinary
	// encapsulation, which a control-plane-only plugin uses and which
	// belongs to nobody.
	if err := scope.CheckHeadend(AFv4, "10.7.1.0/24", 1); err != nil {
		t.Errorf("ordinary encapsulation was refused: %v", err)
	}
}

func TestLocalSIDScope(t *testing.T) {
	scope := narrowScope(t)
	if err := scope.CheckLocalSID(LocalSID{Name: "svc", Locator: "main", Slot: 33}); err != nil {
		t.Errorf("a SID inside the scope was refused: %v", err)
	}
	if err := scope.CheckLocalSID(LocalSID{Name: "svc", Locator: "second", Slot: 33}); err == nil {
		t.Error("a locator outside the scope was allowed")
	}
	if err := scope.CheckLocalSID(LocalSID{Name: "svc", Locator: "main", Slot: 34}); err == nil {
		t.Error("another plugin's endpoint slot was allowed")
	}
}

// The route targets decide which VRF a peer imports the route into, so a
// plugin able to spell them could put a route in a VPN it was never given.
// They are derived from the binding instead.
func TestAdvertiseDerivesTheVPNFromTheBinding(t *testing.T) {
	g := NewGuard(narrowScope(t), testLocators(), testBindings())
	got, err := g.resolveAdvertised(AdvertisedRoute{
		Family: bgp.FamilyVPNv4, VRF: testVRF, Prefix: "10.7.0.0/24", NextHop: "2001:db8::1",
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got.RD != testRD {
		t.Errorf("RD = %q, want the binding's %q", got.RD, testRD)
	}
	if len(got.RouteTargets) != 1 || got.RouteTargets[0] != testRD {
		t.Errorf("route targets = %v, want the binding's export set", got.RouteTargets)
	}
}

func TestAdvertiseRefusesAVRFOutsideTheScope(t *testing.T) {
	g := NewGuard(narrowScope(t), testLocators(), testBindings())
	_, err := g.resolveAdvertised(AdvertisedRoute{
		Family: bgp.FamilyVPNv4, VRF: "someone-elses", Prefix: "10.7.0.0/24", NextHop: "2001:db8::1",
	})
	if err == nil {
		t.Fatal("a VRF outside the scope was accepted")
	}
	if !strings.Contains(err.Error(), "someone-elses") {
		t.Errorf("error does not name the VRF: %v", err)
	}
}

// A binding with no RD is receive-only: it imports routes and originates
// none, so originating into it would put routes on the wire under an RD
// the operator never chose.
func TestAdvertiseRefusesAReceiveOnlyBinding(t *testing.T) {
	bindings := &fakeBindingSource{byName: map[string]vrfbgp.Binding{
		testVRF: vrfbgp.Binding{VRFName: testVRF, ImportRTs: []string{testRD}}.Normalize(),
	}}
	g := NewGuard(narrowScope(t), testLocators(), bindings)
	if _, err := g.resolveAdvertised(AdvertisedRoute{
		Family: bgp.FamilyVPNv4, VRF: testVRF, Prefix: "10.7.0.0/24", NextHop: "2001:db8::1",
	}); err == nil {
		t.Fatal("a receive-only binding was originated into")
	}
}

// What a plugin legitimately advertises in IPv6 unicast is its own SID
// space, so the locators it was given are what bound it.
func TestUnicastAdvertiseIsHeldInsideALocator(t *testing.T) {
	g := NewGuard(narrowScope(t), testLocators(), testBindings())
	if _, err := g.resolveAdvertised(AdvertisedRoute{
		Family: bgp.FamilyIPv6Unicast, Prefix: "fd00:1:0:7::/64", NextHop: "2001:db8::1",
	}); err != nil {
		t.Errorf("a prefix inside the plugin's locator was refused: %v", err)
	}
	// Outside the locator, and a less specific covering it: both are
	// address space the plugin was not given.
	for _, outside := range []string{"fd00:9::/48", "fd00::/16"} {
		if _, err := g.resolveAdvertised(AdvertisedRoute{
			Family: bgp.FamilyIPv6Unicast, Prefix: outside, NextHop: "2001:db8::1",
		}); err == nil {
			t.Errorf("%s was allowed, and it is not inside the plugin's locator", outside)
		}
	}
}

// A locator an operator has not registered yet is the ordinary case for a
// plugin restored while the daemon is still coming up. The declaration has
// to fail in a way the retry machinery repairs, and the message has to say
// what is missing.
func TestUnicastAdvertiseSaysWhichLocatorIsMissing(t *testing.T) {
	g := NewGuard(narrowScope(t), &fakeLocatorSource{}, testBindings())
	_, err := g.resolveAdvertised(AdvertisedRoute{
		Family: bgp.FamilyIPv6Unicast, Prefix: "fd00:1:0:7::/64", NextHop: "2001:db8::1",
	})
	if err == nil {
		t.Fatal("a prefix was accepted against a locator that does not exist")
	}
	if !strings.Contains(err.Error(), "main") {
		t.Errorf("error does not name the missing locator: %v", err)
	}
}

// The cap is the operator's statement about how much of a VPN one writer
// may fill, and it already governs the auto-advertise path.
func TestAdvertiseSetIsCappedByTheBinding(t *testing.T) {
	bindings := &fakeBindingSource{byName: map[string]vrfbgp.Binding{
		testVRF: vrfbgp.Binding{
			VRFName: testVRF, RD: testRD, ExportRTs: []string{testRD}, MaxPrefixes: 1,
		}.Normalize(),
	}}
	g := NewGuard(narrowScope(t), testLocators(), bindings)
	routes := []AdvertisedRoute{
		{Family: bgp.FamilyVPNv4, VRF: testVRF, Prefix: "10.7.0.0/24"},
		{Family: bgp.FamilyVPNv4, VRF: testVRF, Prefix: "10.7.1.0/24"},
	}
	if err := g.checkAdvertiseSet(routes[:1]); err != nil {
		t.Errorf("a set within the cap was refused: %v", err)
	}
	if err := g.checkAdvertiseSet(routes); err == nil {
		t.Error("a set over the VRF's cap was accepted")
	}
}

// The whole set is refused rather than the offending member dropped:
// applying the rest would install something the plugin did not ask for,
// and a plugin narrowed in silence ends up believing it holds state it
// does not.
func TestAnOutOfScopeDeclarationRefusesTheWholeSet(t *testing.T) {
	headend := newFakeHeadendOps()
	ops, err := NewPluginOps(PluginOpsConfig{
		Owner:        ownerA,
		Headend:      headend,
		Leases:       NewLeases(),
		Capabilities: testCaps(),
		Guard:        NewGuard(narrowScope(t), testLocators(), testBindings()),
		EncapSource:  testEncapSource,
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
	chunk, err := proto.Marshal(&v1.PluginApplyChunk{HeadendEntries: []*v1.PluginHeadendEntry{
		{TriggerPrefix: "10.7.1.0/24", Segments: []string{"fd00:2::1"}},
		{TriggerPrefix: "10.9.1.0/24", Segments: []string{"fd00:2::1"}},
	}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// The chunk itself is well formed, so it is accepted; the scope is
	// checked when the set is applied, which is where a declaration
	// naming something registered a moment later can be retried.
	if err := ops.ApplyPut(gen, chunk); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := ops.ApplyCommit(gen); err == nil {
		t.Fatal("a set holding a prefix outside the scope was applied")
	}
	if got := headend.countV4(); got != 0 {
		t.Fatalf("%d entries were installed from a refused set, want none", got)
	}
}

// Narrowing a scope is the one case the desired-set model cannot repair on
// its own: the plugin's own declaration of the state it wrote is now
// refused, and refused whole, so nothing would prune it.
func TestPruneRemovesWhatANarrowedScopeNoLongerCovers(t *testing.T) {
	ops := newFakeHeadendOps()
	leases := NewLeases()
	owner := bpf.OwnerTag("plugin:v1:bundle=wide")
	entry := func(prefix string) HeadendDesired {
		return HeadendDesired{
			TriggerPrefix: prefix,
			Entry:         &bpf.HeadendEntry{Mode: 1, NumSegments: 1},
		}
	}
	if _, err := ApplyHeadendSet(ops, leases, owner, AFv4, []HeadendDesired{
		entry("10.7.0.0/24"),
		entry("10.9.0.0/24"),
	}, unlimited); err != nil {
		t.Fatalf("setup: %v", err)
	}

	// Re-registered with a scope that covers only one of them.
	pluginOps, err := NewPluginOps(PluginOpsConfig{
		Owner:   owner,
		Headend: ops,
		Leases:  leases,
		Guard:   NewGuard(narrowScope(t), testLocators(), testBindings()),
	})
	if err != nil {
		t.Fatalf("ops: %v", err)
	}
	removed, err := pluginOps.PruneOutOfScope(context.Background())
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if removed != 1 {
		t.Fatalf("removed %d entries, want the one outside the new scope", removed)
	}
	held, err := OwnedHeadendEntries(ops, owner, AFv4)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if len(held) != 1 || held[0].TriggerPrefix != "10.7.0.0/24" {
		t.Fatalf("held %+v, want only the prefix still inside the scope", held)
	}
	// The lease on the pruned key is free, so another plugin may take it.
	if err := leases.Acquire(LeaseHeadendV4, "10.9.0.0/24", ownerB); err != nil {
		t.Errorf("the pruned key is still leased: %v", err)
	}
}

// A binding is a thing an operator edits while plugins are running. The
// route distinguisher, the route targets and the cap all come from it, and
// they are stamped when the declaration is applied -- so without a
// re-derivation the paths on the wire keep carrying what the binding used
// to say until the plugin next happens to redeclare.
func TestChangedBindingRedrivesWhatAPluginAdvertises(t *testing.T) {
	adv := &fakeAdvertiser{}
	set := NewAdvertiseSet(adv, NewLeases())
	bindings := testBindings()
	ops, err := NewPluginOps(PluginOpsConfig{
		Owner:        ownerA,
		Headend:      newFakeHeadendOps(),
		Leases:       NewLeases(),
		Advertise:    set,
		Capabilities: testCaps(),
		Guard:        NewGuard(narrowScope(t), testLocators(), bindings),
	})
	if err != nil {
		t.Fatalf("ops: %v", err)
	}
	if _, err := set.Apply(context.Background(), ownerA, []AdvertisedRoute{{
		Family: bgp.FamilyVPNv4, VRF: testVRF, RD: testRD, Prefix: "10.7.0.0/24",
		NextHop: "2001:db8::1", RouteTargets: []string{testRD},
	}}, unlimited); err != nil {
		t.Fatalf("setup: %v", err)
	}

	// The operator re-targets the VPN.
	bindings.set(testVRF, vrfbgp.Binding{
		VRFName: testVRF, RD: testRD, ExportRTs: []string{"65000:999"},
	}.Normalize())
	if _, err := ops.ReconcileAdvertised(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	adv.mu.Lock()
	last := adv.advertise[len(adv.advertise)-1]
	adv.mu.Unlock()
	if len(last.RTs) != 1 || last.RTs[0] != "65000:999" {
		t.Fatalf("re-advertised with route targets %v, want the binding's new set", last.RTs)
	}
}

// Lowering the cap has to take effect on what is already originated.
// Refusing the set would leave every route in place, which is the opposite
// of what the operator asked for, so the overflow is withdrawn instead.
func TestLoweredCapWithdrawsWhatNoLongerFits(t *testing.T) {
	adv := &fakeAdvertiser{}
	set := NewAdvertiseSet(adv, NewLeases())
	bindings := testBindings()
	ops, err := NewPluginOps(PluginOpsConfig{
		Owner:        ownerA,
		Headend:      newFakeHeadendOps(),
		Leases:       NewLeases(),
		Advertise:    set,
		Capabilities: testCaps(),
		Guard:        NewGuard(narrowScope(t), testLocators(), bindings),
	})
	if err != nil {
		t.Fatalf("ops: %v", err)
	}
	desired := []AdvertisedRoute{
		{Family: bgp.FamilyVPNv4, VRF: testVRF, RD: testRD, Prefix: "10.7.0.0/24", NextHop: "2001:db8::1"},
		{Family: bgp.FamilyVPNv4, VRF: testVRF, RD: testRD, Prefix: "10.7.1.0/24", NextHop: "2001:db8::1"},
	}
	if _, err := set.Apply(context.Background(), ownerA, desired, unlimited); err != nil {
		t.Fatalf("setup: %v", err)
	}

	bindings.set(testVRF, vrfbgp.Binding{
		VRFName: testVRF, RD: testRD, ExportRTs: []string{testRD}, MaxPrefixes: 1,
	}.Normalize())
	withdrawn, err := ops.ReconcileAdvertised(context.Background())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if withdrawn != 1 {
		t.Fatalf("withdrew %d routes, want the one over the new cap", withdrawn)
	}
	if set.LiveCount(ownerA) != 1 {
		t.Fatalf("owner still originates %d routes, want the cap", set.LiveCount(ownerA))
	}
}

// A binding the operator removed leaves nothing for the plugin's routes to
// derive from, so they come off the wire rather than staying under an RD
// that no longer describes anything.
func TestRemovedBindingWithdrawsThePluginsRoutes(t *testing.T) {
	adv := &fakeAdvertiser{}
	set := NewAdvertiseSet(adv, NewLeases())
	bindings := testBindings()
	ops, err := NewPluginOps(PluginOpsConfig{
		Owner:        ownerA,
		Headend:      newFakeHeadendOps(),
		Leases:       NewLeases(),
		Advertise:    set,
		Capabilities: testCaps(),
		Guard:        NewGuard(narrowScope(t), testLocators(), bindings),
	})
	if err != nil {
		t.Fatalf("ops: %v", err)
	}
	if _, err := set.Apply(context.Background(), ownerA, []AdvertisedRoute{{
		Family: bgp.FamilyVPNv4, VRF: testVRF, RD: testRD, Prefix: "10.7.0.0/24",
		NextHop: "2001:db8::1",
	}}, unlimited); err != nil {
		t.Fatalf("setup: %v", err)
	}

	bindings.remove(testVRF)
	if _, err := ops.ReconcileAdvertised(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if set.LiveCount(ownerA) != 0 {
		t.Fatal("the plugin still originates a route into a VRF with no binding")
	}
}

// If the narrowing does not take, saying the registration succeeded would
// claim an authorization boundary is in force when what the old scope
// allowed is still installed -- and the plugin cannot clear it itself,
// because its own declaration of that state is refused now.
func TestARegistrationIsRefusedWhenTheNarrowingCannotBeApplied(t *testing.T) {
	ops := newFakeHeadendOps()
	leases := NewLeases()
	owner := bpf.OwnerTag("plugin:v1:bundle=wide")
	entry := func(prefix string) HeadendDesired {
		return HeadendDesired{
			TriggerPrefix: prefix,
			Entry:         &bpf.HeadendEntry{Mode: 1, NumSegments: 1},
		}
	}
	if _, err := ApplyHeadendSet(ops, leases, owner, AFv4, []HeadendDesired{
		entry("10.7.0.0/24"),
		entry("10.9.0.0/24"),
	}, unlimited); err != nil {
		t.Fatalf("setup: %v", err)
	}
	// The entry the new scope excludes is the one the map will not remove.
	ops.failDelete("10.9.0.0/24")

	pluginOps, err := NewPluginOps(PluginOpsConfig{
		Owner:   owner,
		Headend: ops,
		Leases:  leases,
		Guard:   NewGuard(narrowScope(t), testLocators(), testBindings()),
	})
	if err != nil {
		t.Fatalf("ops: %v", err)
	}
	if _, err := pluginOps.PruneOutOfScope(context.Background()); err == nil {
		t.Fatal("a prune that could not remove the out-of-scope entry reported success")
	}
	held, err := OwnedHeadendEntries(ops, owner, AFv4)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if len(held) != 2 {
		t.Fatalf("held %+v, want both entries still installed", held)
	}
}

// A changed route distinguisher moves the NLRI. Apply takes every declared
// key before it withdraws anything, so a new key another producer holds
// would fail with the old route still on the wire under an RD the binding
// no longer says.
func TestARDChangeRetiresTheOldKeyEvenWhenTheNewOneIsTaken(t *testing.T) {
	adv := &fakeAdvertiser{}
	leases := NewLeases()
	set := NewAdvertiseSet(adv, leases)
	bindings := testBindings()
	ops, err := NewPluginOps(PluginOpsConfig{
		Owner:        ownerA,
		Headend:      newFakeHeadendOps(),
		Leases:       NewLeases(),
		Advertise:    set,
		Capabilities: testCaps(),
		Guard:        NewGuard(narrowScope(t), testLocators(), bindings),
	})
	if err != nil {
		t.Fatalf("ops: %v", err)
	}
	route := AdvertisedRoute{
		Family: bgp.FamilyVPNv4, VRF: testVRF, RD: testRD, Prefix: "10.7.0.0/24",
		NextHop: "2001:db8::1",
	}
	if _, err := set.Apply(context.Background(), ownerA, []AdvertisedRoute{route}, unlimited); err != nil {
		t.Fatalf("setup: %v", err)
	}

	// The operator moves the VPN to another RD, and someone else already
	// originates the NLRI it moves onto.
	moved := route
	moved.RD = "65000:2"
	if err := leases.Acquire(LeaseAdvertise, moved.key(), ownerB); err != nil {
		t.Fatalf("taking the new key: %v", err)
	}
	bindings.set(testVRF, vrfbgp.Binding{
		VRFName: testVRF, RD: "65000:2", ExportRTs: []string{testRD},
	}.Normalize())

	if _, err := ops.ReconcileAdvertised(context.Background()); err == nil {
		t.Fatal("a reconcile onto a key another producer holds reported success")
	}
	if set.LiveCount(ownerA) != 0 {
		t.Fatal("the route is still originated under the RD the binding no longer says")
	}
	adv.mu.Lock()
	withdrawn := len(adv.withdrawn)
	adv.mu.Unlock()
	if withdrawn != 1 {
		t.Fatalf("withdrew %d routes, want the one whose RD moved", withdrawn)
	}
}

// The apply-path scope check must reach ApplyCommit for every declaration
// kind, not only headend. This is the local-SID arm.
func TestOutOfScopeLocalSIDRefusesAtCommit(t *testing.T) {
	alloc := &fakeAllocator{}
	sids := newFakeSIDOps()
	ops, err := NewPluginOps(PluginOpsConfig{
		Owner:        ownerA,
		Headend:      newFakeHeadendOps(),
		Leases:       NewLeases(),
		LocalSIDs:    NewLocalSIDSet(alloc, sids),
		Capabilities: testCaps(),
		Guard:        NewGuard(narrowScope(t), testLocators(), testBindings()),
	})
	if err != nil {
		t.Fatalf("ops: %v", err)
	}
	if err := ops.Publish(); err != nil {
		t.Fatalf("publish: %v", err)
	}
	gen, err := ops.ApplyBegin(uint32(v1.PluginApplyKind_PLUGIN_APPLY_KIND_LOCAL_SID))
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	// narrowScope allows locator "main" slot 33; "second" is out of scope.
	chunk, err := proto.Marshal(&v1.PluginApplyChunk{LocalSids: []*v1.PluginLocalSid{
		{Name: "ok", Locator: "main", Slot: 33},
		{Name: "bad", Locator: "second", Slot: 33},
	}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := ops.ApplyPut(gen, chunk); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := ops.ApplyCommit(gen); err == nil {
		t.Fatal("a set holding a local SID outside the scope was applied")
	}
	if got := sids.installs; got != 0 {
		t.Fatalf("%d dispatch entries installed from a refused set, want none", got)
	}
}

// The advertise arm of the apply-path check, and the assertion that the
// derived RD and route targets are what actually reach the advertiser.
func TestOutOfScopeAdvertiseRefusesAtCommitAndDerivesOnSuccess(t *testing.T) {
	adv := &fakeAdvertiser{}
	set := NewAdvertiseSet(adv, NewLeases())
	ops, err := NewPluginOps(PluginOpsConfig{
		Owner:        ownerA,
		Headend:      newFakeHeadendOps(),
		Leases:       NewLeases(),
		Advertise:    set,
		Capabilities: testCaps(),
		Guard:        NewGuard(narrowScope(t), testLocators(), testBindings()),
	})
	if err != nil {
		t.Fatalf("ops: %v", err)
	}
	if err := ops.Publish(); err != nil {
		t.Fatalf("publish: %v", err)
	}

	// A set with one in-scope and one out-of-scope VRF is refused whole.
	badGen, _ := ops.ApplyBegin(uint32(v1.PluginApplyKind_PLUGIN_APPLY_KIND_ADVERTISE))
	badChunk, _ := proto.Marshal(&v1.PluginApplyChunk{AdvertisedRoutes: []*v1.PluginAdvertisedRoute{
		{Family: "vpnv4", Vrf: testVRF, Prefix: "10.7.0.0/24", Srv6Sid: "fd00:1::1", NextHop: "2001:db8::1"},
		{Family: "vpnv4", Vrf: "someone-elses", Prefix: "10.7.1.0/24", Srv6Sid: "fd00:1::2", NextHop: "2001:db8::1"},
	}})
	if err := ops.ApplyPut(badGen, badChunk); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := ops.ApplyCommit(badGen); err == nil {
		t.Fatal("a set naming a VRF outside the scope was applied")
	}
	if set.LiveCount(ownerA) != 0 {
		t.Fatal("a refused advertise set left routes live")
	}

	// An in-scope route is applied, and the RD and RTs the advertiser sees
	// are the binding's -- which is what pins txn.routes = resolved.
	okGen, _ := ops.ApplyBegin(uint32(v1.PluginApplyKind_PLUGIN_APPLY_KIND_ADVERTISE))
	okChunk, _ := proto.Marshal(&v1.PluginApplyChunk{AdvertisedRoutes: []*v1.PluginAdvertisedRoute{
		{Family: "vpnv4", Vrf: testVRF, Prefix: "10.7.0.0/24", Srv6Sid: "fd00:1::1", NextHop: "2001:db8::1"},
	}})
	if err := ops.ApplyPut(okGen, okChunk); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := ops.ApplyCommit(okGen); err != nil {
		t.Fatalf("an in-scope route was refused: %v", err)
	}
	adv.mu.Lock()
	defer adv.mu.Unlock()
	if len(adv.advertise) != 1 {
		t.Fatalf("advertiser saw %d routes, want 1", len(adv.advertise))
	}
	if adv.advertise[0].RD != testRD {
		t.Errorf("advertised RD %q, want the binding's %q", adv.advertise[0].RD, testRD)
	}
	if len(adv.advertise[0].RTs) != 1 || adv.advertise[0].RTs[0] != testRD {
		t.Errorf("advertised RTs %v, want the binding's export set", adv.advertise[0].RTs)
	}
}

// A VPN route whose SRv6 SID is not inside one of the plugin's locators is
// refused: deriving the route targets fixes who imports the route, and this
// fixes where the traffic goes.
func TestAdvertiseRefusesASIDOutsideTheLocators(t *testing.T) {
	g := NewGuard(narrowScope(t), testLocators(), testBindings())
	// narrowScope's locator "main" is fd00:1::/48. A SID in it passes.
	if _, err := g.resolveAdvertised(AdvertisedRoute{
		Family: bgp.FamilyVPNv4, VRF: testVRF, Prefix: "10.7.0.0/24",
		SRv6SID: "fd00:1::100", NextHop: "2001:db8::1",
	}); err != nil {
		t.Errorf("a SID inside the plugin's locator was refused: %v", err)
	}
	// A SID in another VRF's locator space is refused even though the VRF
	// name is in scope.
	if _, err := g.resolveAdvertised(AdvertisedRoute{
		Family: bgp.FamilyVPNv4, VRF: testVRF, Prefix: "10.7.0.0/24",
		SRv6SID: "fd00:9::100", NextHop: "2001:db8::1",
	}); err == nil {
		t.Fatal("a SID outside every scoped locator was accepted")
	}
}

// A binding that declares no export route targets for the route's family
// yields none, and the route would be unimportable. resolveVPN refuses it
// rather than originating a route no peer takes.
func TestAdvertiseRefusesWhenTheBindingHasNoRTForTheFamily(t *testing.T) {
	// A binding family-scoped to vpnv6 only: ExportRTsForFamily(vpnv4) is nil.
	bindings := &fakeBindingSource{byName: map[string]vrfbgp.Binding{
		testVRF: {
			VRFName: testVRF, RD: testRD,
			Families: map[bgp.Family]vrfbgp.FamilyPolicy{
				bgp.FamilyVPNv6: {RouteTargets: []vrfbgp.RouteTarget{
					{RT: testRD, Direction: vrfbgp.DirectionBoth},
				}},
			},
		},
	}}
	g := NewGuard(narrowScope(t), testLocators(), bindings)
	if _, err := g.resolveAdvertised(AdvertisedRoute{
		Family: bgp.FamilyVPNv4, VRF: testVRF, Prefix: "10.7.0.0/24",
		SRv6SID: "fd00:1::1", NextHop: "2001:db8::1",
	}); err == nil {
		t.Fatal("a vpnv4 route into a vpnv6-only binding was originated with no route targets")
	}
}

// PruneOutOfScope must reach the local-SID branch, and a surviving SID must
// keep the exact address it already holds rather than being reallocated.
func TestPruneRemovesLocalSIDsOutsideANarrowedScope(t *testing.T) {
	alloc := &fakeAllocator{}
	sids := newFakeSIDOps()
	set := NewLocalSIDSet(alloc, sids)
	owner := ownerA

	// Two SIDs under a wide scope: one in "main" slot 33, one in "second"
	// slot 34.
	allocated, _, err := set.Apply(owner, []LocalSID{
		{Name: "keep", Locator: "main", Slot: 33},
		{Name: "drop", Locator: "second", Slot: 34},
	}, unlimited)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	var keepAddr netip.Addr
	for _, a := range allocated {
		if a.Name == "keep" {
			keepAddr = a.SID
		}
	}

	ops, err := NewPluginOps(PluginOpsConfig{
		Owner:     owner,
		Headend:   newFakeHeadendOps(),
		Leases:    NewLeases(),
		LocalSIDs: set,
		// narrowScope: locator "main", endpoint slot 33 only.
		Guard: NewGuard(narrowScope(t), testLocators(), testBindings()),
	})
	if err != nil {
		t.Fatalf("ops: %v", err)
	}
	before := alloc.releasedCount()
	removed, err := ops.PruneOutOfScope(context.Background())
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if removed != 1 {
		t.Fatalf("removed %d SIDs, want the one outside the new scope", removed)
	}
	live := set.LiveSIDs(owner)
	if len(live) != 1 || live[0].Name != "keep" {
		t.Fatalf("live SIDs = %+v, want only the in-scope one", live)
	}
	// The surviving SID kept its address: its dispatch entry is still
	// installed at the address it was first given, and it was not released.
	// A broken LiveSIDs that lost Slot or AuxRaw would have released and
	// reallocated it -- releasing keepAddr and installing a new one.
	if _, ok := sids.entries[keepAddr.String()+"/128"]; !ok {
		t.Fatalf("the kept SID's dispatch entry at %v is gone; it was reallocated", keepAddr)
	}
	if alloc.releasedCount() != before+1 {
		t.Fatalf("released %d SIDs, want exactly the pruned one", alloc.releasedCount()-before)
	}
}

// B3: a declaration that fails must not raise the applied-sequence mark, or
// an older declaration of the same kind still waiting to be retried is
// silently dropped as stale.
func TestAFailedApplyDoesNotVoidAPendingOne(t *testing.T) {
	alloc := &fakeAllocator{failOn: "late"}
	sids := newFakeSIDOps()
	set := NewLocalSIDSet(alloc, sids)
	ops, err := NewPluginOps(PluginOpsConfig{
		Owner:        ownerA,
		Headend:      newFakeHeadendOps(),
		Leases:       NewLeases(),
		LocalSIDs:    set,
		Capabilities: testCaps(),
		Guard:        NewGuard(testScope(), testLocators(), testBindings()),
	})
	if err != nil {
		t.Fatalf("ops: %v", err)
	}

	// A declaration staged before publication, naming a locator whose
	// allocation fails, is held for retry.
	gen1, _ := ops.ApplyBegin(uint32(v1.PluginApplyKind_PLUGIN_APPLY_KIND_LOCAL_SID))
	chunk1, _ := proto.Marshal(&v1.PluginApplyChunk{LocalSids: []*v1.PluginLocalSid{
		{Name: "svc", Locator: "late", Slot: 33},
	}})
	if err := ops.ApplyPut(gen1, chunk1); err != nil {
		t.Fatalf("put 1: %v", err)
	}
	if err := ops.ApplyCommit(gen1); err != nil {
		t.Fatalf("commit before publication should be held: %v", err)
	}
	if err := ops.Publish(); err == nil {
		t.Fatal("publishing a declaration naming a failing locator succeeded")
	}
	if ops.PendingDeclarations() != 1 {
		t.Fatalf("pending = %d, want the held declaration", ops.PendingDeclarations())
	}

	// A later declaration of the same kind fails too (its allocation also
	// names the failing locator). Before the fix this stamped the sequence
	// mark and voided the pending one.
	gen2, _ := ops.ApplyBegin(uint32(v1.PluginApplyKind_PLUGIN_APPLY_KIND_LOCAL_SID))
	chunk2, _ := proto.Marshal(&v1.PluginApplyChunk{LocalSids: []*v1.PluginLocalSid{
		{Name: "svc", Locator: "late", Slot: 34},
	}})
	if err := ops.ApplyPut(gen2, chunk2); err != nil {
		t.Fatalf("put 2: %v", err)
	}
	if err := ops.ApplyCommit(gen2); err == nil {
		t.Fatal("a second failing declaration reported success")
	}

	// The locator starts working; the retry must now apply the pending
	// declaration rather than treat it as stale.
	alloc.mu.Lock()
	alloc.failOn = ""
	alloc.mu.Unlock()
	ops.RetryPending()
	if got := sids.installs; got == 0 {
		t.Fatal("the pending declaration was lost: nothing installed after the locator recovered")
	}
}

// The headend slot grant is per family: the v4 and v6 PROG_ARRAYs share slot
// numbers but are separate programs, so a v4 grant must not authorize a v6
// slot of the same number.
func TestHeadendSlotGrantIsPerFamily(t *testing.T) {
	scope, err := ParseScope(ScopeSpec{
		HeadendPrefixes: []string{"10.7.0.0/16"},
		HeadendV4Slots:  []uint32{16},
		HeadendV6Slots:  []uint32{17},
	})
	if err != nil {
		t.Fatalf("scope: %v", err)
	}
	// v4 slot 16 is granted for v4, refused for v6.
	if err := scope.CheckHeadend(AFv4, "10.7.1.0/24", 16); err != nil {
		t.Errorf("v4 slot 16 refused on the v4 map: %v", err)
	}
	if err := scope.CheckHeadend(AFv6, "10.7.1.0/24", 16); err == nil {
		t.Error("v4 slot 16 was accepted on the v6 map")
	}
	// v6 slot 17 is granted for v6, refused for v4.
	if err := scope.CheckHeadend(AFv6, "10.7.1.0/24", 17); err != nil {
		t.Errorf("v6 slot 17 refused on the v6 map: %v", err)
	}
	if err := scope.CheckHeadend(AFv4, "10.7.1.0/24", 17); err == nil {
		t.Error("v6 slot 17 was accepted on the v4 map")
	}
}

// A binding whose RD is spelled non-canonically must not make every route
// flap withdraw/re-advertise on each reconcile: the resolved RD is
// canonicalized to match the live keys, so a reconcile with nothing changed
// withdraws nothing.
func TestANonCanonicalBindingRDDoesNotFlapOnReconcile(t *testing.T) {
	adv := &fakeAdvertiser{}
	set := NewAdvertiseSet(adv, NewLeases())
	bindings := testBindings()
	ops, err := NewPluginOps(PluginOpsConfig{
		Owner:        ownerA,
		Headend:      newFakeHeadendOps(),
		Leases:       NewLeases(),
		Advertise:    set,
		Capabilities: testCaps(),
		Guard:        NewGuard(narrowScope(t), testLocators(), bindings),
	})
	if err != nil {
		t.Fatalf("ops: %v", err)
	}
	if _, err := set.Apply(context.Background(), ownerA, []AdvertisedRoute{{
		Family: bgp.FamilyVPNv4, VRF: testVRF, RD: testRD, Prefix: "10.7.0.0/24",
		SRv6SID: "fd00:1::1", NextHop: "2001:db8::1",
	}}, unlimited); err != nil {
		t.Fatalf("setup: %v", err)
	}
	adv.mu.Lock()
	withdrawnBefore := len(adv.withdrawn)
	adv.mu.Unlock()

	// The operator re-states the binding with the RD spelled non-canonically
	// (the fake's CanonicalRD collapses leading zeros, as the real one does).
	bindings.set(testVRF, vrfbgp.Binding{
		VRFName: testVRF, RD: "065000:0001", ImportRTs: []string{testRD}, ExportRTs: []string{testRD},
	}.Normalize())

	withdrawn, err := ops.ReconcileAdvertised(context.Background())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if withdrawn != 0 {
		t.Fatalf("reconcile reported %d withdrawn for an RD that only changed spelling", withdrawn)
	}
	adv.mu.Lock()
	defer adv.mu.Unlock()
	if len(adv.withdrawn) != withdrawnBefore {
		t.Fatalf("a non-canonical RD flapped the route: %d withdrawals", len(adv.withdrawn)-withdrawnBefore)
	}
}

// The VPN advertise path, like the unicast one, must say which locator is
// missing when a plugin names a SID in a locator the operator has not
// registered yet, so the retry machinery repairs it rather than failing
// permanently.
func TestVPNAdvertiseSaysWhichLocatorIsMissing(t *testing.T) {
	g := NewGuard(narrowScope(t), &fakeLocatorSource{}, testBindings())
	_, err := g.resolveAdvertised(AdvertisedRoute{
		Family: bgp.FamilyVPNv4, VRF: testVRF, Prefix: "10.7.0.0/24",
		SRv6SID: "fd00:1::1", NextHop: "2001:db8::1",
	})
	if err == nil {
		t.Fatal("a SID was accepted against a locator that does not exist")
	}
	if !strings.Contains(err.Error(), "main") {
		t.Errorf("error does not name the missing locator: %v", err)
	}
}

// A malformed SID is refused with a parse error, not passed through.
func TestVPNAdvertiseRefusesAMalformedSID(t *testing.T) {
	g := NewGuard(narrowScope(t), testLocators(), testBindings())
	if _, err := g.resolveAdvertised(AdvertisedRoute{
		Family: bgp.FamilyVPNv4, VRF: testVRF, Prefix: "10.7.0.0/24",
		SRv6SID: "not-an-address", NextHop: "2001:db8::1",
	}); err == nil {
		t.Fatal("a malformed SID was accepted")
	}
}

// The reconcile claims it runs under applyMu so a resolved route cannot be
// overtaken by a concurrent binding edit. Run a worker reconciling while
// another goroutine flips the binding, under -race, and assert the final
// route always carries one of the two RT sets, never a mix or an empty one.
func TestReconcileIsConsistentUnderAConcurrentBindingEdit(t *testing.T) {
	adv := &fakeAdvertiser{}
	set := NewAdvertiseSet(adv, NewLeases())
	bindings := testBindings()
	ops, err := NewPluginOps(PluginOpsConfig{
		Owner:        ownerA,
		Headend:      newFakeHeadendOps(),
		Leases:       NewLeases(),
		Advertise:    set,
		Capabilities: testCaps(),
		Guard:        NewGuard(narrowScope(t), testLocators(), bindings),
	})
	if err != nil {
		t.Fatalf("ops: %v", err)
	}
	if _, err := set.Apply(context.Background(), ownerA, []AdvertisedRoute{{
		Family: bgp.FamilyVPNv4, VRF: testVRF, RD: testRD, Prefix: "10.7.0.0/24",
		SRv6SID: "fd00:1::1", NextHop: "2001:db8::1",
	}}, unlimited); err != nil {
		t.Fatalf("setup: %v", err)
	}
	rtA, rtB := "65000:1", "65000:2"
	mk := func(rt string) vrfbgp.Binding {
		return vrfbgp.Binding{VRFName: testVRF, RD: testRD, ImportRTs: []string{rt}, ExportRTs: []string{rt}}.Normalize()
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			if i%2 == 0 {
				bindings.set(testVRF, mk(rtA))
			} else {
				bindings.set(testVRF, mk(rtB))
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			if _, err := ops.ReconcileAdvertised(context.Background()); err != nil {
				t.Errorf("reconcile: %v", err)
				return
			}
		}
	}()
	wg.Wait()

	// One final reconcile against a known binding pins the end state.
	bindings.set(testVRF, mk(rtA))
	if _, err := ops.ReconcileAdvertised(context.Background()); err != nil {
		t.Fatalf("final reconcile: %v", err)
	}
	for _, r := range set.LiveRoutes(ownerA) {
		if len(r.RouteTargets) != 1 || r.RouteTargets[0] != rtA {
			t.Fatalf("route RTs = %v, want the last binding's %q; a mix or empty means the reconcile was overtaken", r.RouteTargets, rtA)
		}
	}
}
