package cplane

import (
	"context"
	"strings"
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
	scope, err := ParseScope(
		[]string{"main"},
		[]string{testVRF},
		[]string{"10.7.0.0/16"},
		[]uint32{16},
		[]uint32{33},
	)
	if err != nil {
		t.Fatalf("parse scope: %v", err)
	}
	return scope
}

func TestParseScopeCanonicalizes(t *testing.T) {
	scope, err := ParseScope(
		[]string{"b", "a", "a"},
		nil,
		// Unmasked, and out of order. The trigger prefixes it is compared
		// against are masked, so a scope holding the unmasked spelling
		// would compare against something the map never contains.
		[]string{"fd00::/16", "10.7.0.1/16"},
		nil, nil,
	)
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
	if _, err := ParseScope(nil, nil, []string{"::ffff:10.7.0.0/112"}, nil, nil); err == nil {
		t.Fatal("an IPv4 prefix in IPv6 form was accepted")
	}
}

func TestParseScopeRefusesASlotOutsideThePluginRange(t *testing.T) {
	if _, err := ParseScope(nil, nil, nil, []uint32{1}, nil); err == nil {
		t.Error("a headend slot outside the plugin range was accepted")
	}
	if _, err := ParseScope(nil, nil, nil, nil, []uint32{1}); err == nil {
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
	if err := scope.CheckHeadend("10.7.0.0/24", 1); err == nil {
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
	if err := scope.CheckHeadend("10.7.1.0/24", 1); err != nil {
		t.Errorf("a prefix inside the scope was refused: %v", err)
	}
	// The scope's own prefix is inside itself.
	if err := scope.CheckHeadend("10.7.0.0/16", 1); err != nil {
		t.Errorf("the scope's own prefix was refused: %v", err)
	}
	for _, outside := range []string{"10.8.0.0/24", "0.0.0.0/0", "10.0.0.0/8", "fd00::/64"} {
		if err := scope.CheckHeadend(outside, 1); err == nil {
			t.Errorf("%s was allowed, and it is outside the scope", outside)
		}
	}
}

// A plugin pointing an entry at another plugin's slot would have its aux
// bytes read under a layout that does not describe them.
func TestHeadendScopeChecksThePluginSlot(t *testing.T) {
	scope := narrowScope(t)
	if err := scope.CheckHeadend("10.7.1.0/24", 16); err != nil {
		t.Errorf("the plugin's own slot was refused: %v", err)
	}
	if err := scope.CheckHeadend("10.7.1.0/24", 17); err == nil {
		t.Error("another plugin's headend slot was allowed")
	}
	// A mode naming one of vinbero's own behaviors is ordinary
	// encapsulation, which a control-plane-only plugin uses and which
	// belongs to nobody.
	if err := scope.CheckHeadend("10.7.1.0/24", 1); err != nil {
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
	bindings.byName[testVRF] = vrfbgp.Binding{
		VRFName: testVRF, RD: testRD, ExportRTs: []string{"65000:999"},
	}.Normalize()
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

	bindings.byName[testVRF] = vrfbgp.Binding{
		VRFName: testVRF, RD: testRD, ExportRTs: []string{testRD}, MaxPrefixes: 1,
	}.Normalize()
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

	delete(bindings.byName, testVRF)
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
	bindings.byName[testVRF] = vrfbgp.Binding{
		VRFName: testVRF, RD: "65000:2", ExportRTs: []string{testRD},
	}.Normalize()

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
