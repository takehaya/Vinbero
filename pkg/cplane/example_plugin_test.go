package cplane

import (
	"context"
	"net/netip"
	"os"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/cplane/wasm"
)

// examplePlugin is the TinyGo plugin under sdk/examples. Unlike the
// hand-written .wat fixtures, it is a plugin as an operator would actually
// write one -- a real language runtime, a real allocator, a real reactor
// initializer -- which is what makes it worth testing against the host.
// Building it needs TinyGo (make cplane-example), so the test skips when
// the artifact is not there rather than failing on a missing toolchain.
func examplePlugin(t *testing.T) []byte {
	t.Helper()
	mod, err := os.ReadFile("../../sdk/examples/cplane-custom-behavior/plugin.wasm")
	if err != nil {
		t.Skip("sdk/examples/cplane-custom-behavior not built (make cplane-example)")
	}
	return mod
}

// customBehaviorRoute builds a VPNv4 advertisement carrying the example's
// claimed behavior.
func customBehaviorRoute(prefix, sid string) bgp.RouteEvent {
	return bgp.RouteEvent{
		Family:           bgp.FamilyVPNv4,
		Source:           bgp.PathSource{Peer: netip.MustParseAddr("192.0.2.1")},
		EndpointBehavior: 0xFE01,
		VPN:              &bgp.VPNRoute{RD: "65000:1", Prefix: prefix, SRv6SID: sid},
	}
}

func exampleManager(t *testing.T) (*Manager, *fakeSource, *fakeHeadendOps) {
	t.Helper()
	src := newFakeSource()
	ops := newFakeHeadendOps()
	m, err := NewManager(ManagerConfig{
		Source:      src,
		Claims:      newFakeClaims(),
		Headend:     ops,
		EncapSource: testEncapSource,
		LocatorInfo: testLocators(),
		VRFBindings: testBindings(),
	})
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	t.Cleanup(func() { m.Close(context.Background()) })
	if err := m.Register(context.Background(), Registration{
		Name:         "custom-behavior",
		Module:       examplePlugin(t),
		Behaviors:    []uint16{0xFE01},
		Capabilities: testCaps(), Scope: testScope(),
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
	return m, src, ops
}

// The whole point of the mechanism, end to end: a route carrying an
// operator's own behavior reaches the plugin, and the plugin's declaration
// becomes a headend entry.
func TestExamplePluginSteersItsOwnBehavior(t *testing.T) {
	m, src, ops := exampleManager(t)
	src.emit("custom-behavior", customBehaviorRoute("10.0.0.0/24", "fd00:2::100"))
	waitDelivered(t, m, "custom-behavior")

	if ops.countV4() != 1 {
		t.Fatalf("data plane holds %d entries, want the one the plugin declared", ops.countV4())
	}
	entry, ok := ops.getV4("10.0.0.0/24")
	if !ok {
		t.Fatalf("entries are keyed %v, want the advertised prefix", sortedV4(ops))
	}
	if entry.NumSegments != 1 {
		t.Fatalf("entry has %d segments, want the advertised SID", entry.NumSegments)
	}
	if got := netip.AddrFrom16(entry.Segments[0]); got != netip.MustParseAddr("fd00:2::100") {
		t.Errorf("segment = %v, want the SID the route advertised", got)
	}
	// The source it never named falls back to the daemon's.
	if got := netip.AddrFrom16(entry.SrcAddr); got != netip.MustParseAddr("fd00:1::1") {
		t.Errorf("source = %v, want the daemon default", got)
	}
}

// A withdrawal carries no attributes, so the plugin cannot recognize it by
// behavior. It has to match on the prefix it is holding, and this is the
// test that says so.
func TestExamplePluginHandlesWithdrawWithoutAttributes(t *testing.T) {
	m, src, ops := exampleManager(t)
	src.emit("custom-behavior", customBehaviorRoute("10.0.0.0/24", "fd00:2::100"))
	waitDelivered(t, m, "custom-behavior")
	if ops.countV4() != 1 {
		t.Fatalf("setup: %d entries, want 1", ops.countV4())
	}

	withdraw := customBehaviorRoute("10.0.0.0/24", "")
	withdraw.IsWithdraw = true
	withdraw.EndpointBehavior = 0 // as it arrives on the wire
	src.emit("custom-behavior", withdraw)
	waitDelivered(t, m, "custom-behavior")

	if ops.countV4() != 0 {
		t.Fatalf("withdraw left %d entries behind", ops.countV4())
	}
}

// A route naming a behavior this plugin did not claim is not its business.
func TestExamplePluginIgnoresOtherBehaviors(t *testing.T) {
	m, src, ops := exampleManager(t)
	other := customBehaviorRoute("10.0.0.0/24", "fd00:2::100")
	other.EndpointBehavior = 0x0013 // End.DT4
	src.emit("custom-behavior", other)
	waitDelivered(t, m, "custom-behavior")
	if ops.countV4() != 0 {
		t.Fatalf("the plugin acted on a behavior it does not own: %v", sortedV4(ops))
	}
}

// The plugin declares the whole set every time, so several prefixes
// accumulate and removing one leaves the others alone.
func TestExamplePluginDeclaresTheWholeSet(t *testing.T) {
	m, src, ops := exampleManager(t)
	src.emit("custom-behavior", customBehaviorRoute("10.0.1.0/24", "fd00:2::1"))
	waitDelivered(t, m, "custom-behavior")
	src.emit("custom-behavior", customBehaviorRoute("10.0.2.0/24", "fd00:2::2"))
	waitDelivered(t, m, "custom-behavior")
	if ops.countV4() != 2 {
		t.Fatalf("data plane holds %v, want both prefixes", sortedV4(ops))
	}

	withdraw := customBehaviorRoute("10.0.1.0/24", "")
	withdraw.IsWithdraw = true
	withdraw.EndpointBehavior = 0
	src.emit("custom-behavior", withdraw)
	waitDelivered(t, m, "custom-behavior")

	got := sortedV4(ops)
	if len(got) != 1 || got[0] != "10.0.2.0/24" {
		t.Fatalf("data plane holds %v, want only the prefix that was not withdrawn", got)
	}
}

// A restart is the plugin's ordinary recovery path: it comes back with no
// memory of anything, the host replays the routes, and the same
// declaration converges on the same state.
func TestExamplePluginConvergesAfterRestart(t *testing.T) {
	m, src, ops := exampleManager(t)
	src.emit("custom-behavior", customBehaviorRoute("10.0.0.0/24", "fd00:2::100"))
	waitDelivered(t, m, "custom-behavior")
	if ops.countV4() != 1 {
		t.Fatalf("setup: %d entries, want 1", ops.countV4())
	}

	// Re-registering is the upgrade path and stands in for a restart: a
	// fresh instance over the same owner tag.
	if err := m.Register(context.Background(), Registration{
		Name:         "custom-behavior",
		Module:       examplePlugin(t),
		Behaviors:    []uint16{0xFE01},
		Capabilities: testCaps(), Scope: testScope(),
	}); err != nil {
		t.Fatalf("re-register: %v", err)
	}
	// The state is still there across the swap.
	if ops.countV4() != 1 {
		t.Fatalf("the restart disturbed the data plane: %v", sortedV4(ops))
	}
	// The new instance knows nothing yet; the replay is what tells it.
	src.emit("custom-behavior", customBehaviorRoute("10.0.0.0/24", "fd00:2::100"))
	waitDelivered(t, m, "custom-behavior")
	if ops.countV4() != 1 {
		t.Fatalf("after replay the data plane holds %v, want the same single entry", sortedV4(ops))
	}
}

// The config blob retunes the plugin without rebuilding it: the same
// module claims a different codepoint.
func TestExamplePluginHonoursConfiguredBehavior(t *testing.T) {
	src := newFakeSource()
	ops := newFakeHeadendOps()
	m, err := NewManager(ManagerConfig{
		Source:      src,
		Claims:      newFakeClaims(),
		Headend:     ops,
		EncapSource: testEncapSource,
		LocatorInfo: testLocators(),
		VRFBindings: testBindings(),
	})
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	defer m.Close(context.Background())

	// The example's own config message, asking it to claim a different
	// codepoint than the one it was built with.
	config := exampleConfig(0xFE02, "", "", "", 0, "")
	if err := m.Register(context.Background(), Registration{
		Name:         "custom-behavior",
		Module:       examplePlugin(t),
		Config:       config,
		Behaviors:    []uint16{0xFE02},
		Capabilities: testCaps(), Scope: testScope(),
	}); err != nil {
		t.Fatalf("register: %v", err)
	}

	// The codepoint it was built with is no longer the one it claims.
	src.emit("custom-behavior", customBehaviorRoute("10.0.0.0/24", "fd00:2::100"))
	waitDelivered(t, m, "custom-behavior")
	if ops.countV4() != 0 {
		t.Fatalf("the plugin acted on its compiled-in behavior after being reconfigured: %v", sortedV4(ops))
	}

	configured := customBehaviorRoute("10.0.1.0/24", "fd00:2::200")
	configured.EndpointBehavior = 0xFE02
	src.emit("custom-behavior", configured)
	waitDelivered(t, m, "custom-behavior")
	if ops.countV4() != 1 {
		t.Fatalf("the plugin ignored its configured behavior: %v", sortedV4(ops))
	}
}

// exampleConfig encodes the example plugin's own config message: the
// behavior codepoint to claim, the locator to take a SID from, the prefix
// to advertise behind it, the VRF to advertise it into, and the data-plane
// slot the SID dispatches to.
func exampleConfig(behavior uint64, locator, prefix, vrf string, slot uint64, nextHop string) []byte {
	var w exampleWriter
	w.varintField(1, behavior)
	w.stringField(2, locator)
	w.stringField(3, prefix)
	w.stringField(4, vrf)
	w.varintField(5, slot)
	w.stringField(7, nextHop)
	return w.buf
}

// exampleWriter is a minimal protobuf encoder for building that config.
type exampleWriter struct{ buf []byte }

func (w *exampleWriter) varint(v uint64) {
	for v >= 0x80 {
		w.buf = append(w.buf, byte(v)|0x80)
		v >>= 7
	}
	w.buf = append(w.buf, byte(v))
}

// wireVarint and wireBytes are the protobuf wire types these fields use.
const (
	wireVarint = 0
	wireBytes  = 2
)

func (w *exampleWriter) varintField(field int, v uint64) {
	w.varint(uint64(field)<<3 | wireVarint)
	w.varint(v)
}

func (w *exampleWriter) stringField(field int, s string) {
	w.varint(uint64(field)<<3 | wireBytes)
	w.varint(uint64(len(s)))
	w.buf = append(w.buf, s...)
}

// The whole point of the mechanism, driven end to end by a real plugin:
// it asks for a SID of its own, is told the address, points it at its
// data-plane slot, and advertises a prefix behind it naming its own
// behavior codepoint.
//
// A far-end vinbero receiving that advertisement hands it to the plugin
// that claimed the codepoint rather than to its own appliers, which is the
// receive half this same example implements.
func TestExamplePluginCompletesTheLoop(t *testing.T) {
	src := newFakeSource()
	headend := newFakeHeadendOps()
	alloc := &fakeAllocator{}
	sids := newFakeSIDOps()
	adv := &fakeAdvertiser{}

	m, err := NewManager(ManagerConfig{
		Source:       src,
		Claims:       newFakeClaims(),
		Headend:      headend,
		Advertiser:   adv,
		Locators:     alloc,
		SIDFunctions: sids,
		EncapSource:  testEncapSource,
		LocatorInfo:  testLocators(),
		VRFBindings:  testBindings(),
	})
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	defer m.Close(context.Background())

	if err := m.Register(context.Background(), Registration{
		Name:         "custom-behavior",
		Module:       examplePlugin(t),
		Config:       exampleConfig(0xFE01, "main", "10.7.0.0/24", testVRF, 33, "2001:db8::1"),
		Behaviors:    []uint16{0xFE01},
		Capabilities: testCaps(), Scope: testScope(),
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
	waitDelivered(t, m, "custom-behavior")

	// It asked for a SID and the host installed the dispatch entry.
	if sids.count() != 1 {
		t.Fatalf("%d dispatch entries installed, want the plugin's own", sids.count())
	}
	for prefix, entry := range mustEntries(t, sids) {
		if entry.Action != 33 {
			t.Errorf("SID %s dispatches to slot %d, want the plugin's 33", prefix, entry.Action)
		}
	}

	// Being told the address is what let it advertise.
	adv.mu.Lock()
	advertised := append([]bgp.VPNRoute(nil), adv.advertise...)
	adv.mu.Unlock()
	if len(advertised) != 1 {
		t.Fatalf("advertised %d routes, want the configured prefix", len(advertised))
	}
	got := advertised[0]
	// The RD is the binding's, not the plugin's: it named the VRF and the
	// host filled the rest in.
	if got.Prefix != "10.7.0.0/24" || got.RD != testRD {
		t.Errorf("advertised %+v, want the configured prefix and the VRF's RD", got)
	}
	if got.EndpointBehavior != 0xFE01 {
		t.Errorf("advertised behavior = %#x, want the plugin's own", got.EndpointBehavior)
	}
	if got.SRv6SID == "" {
		t.Error("advertised no SID")
	}
	// The SID it advertised is the one the dispatch entry was installed
	// for, not some other address.
	if _, ok := sids.entryFor(got.SRv6SID + "/128"); !ok {
		t.Errorf("advertised SID %s has no dispatch entry", got.SRv6SID)
	}

	// The receive half still works alongside all of that.
	src.emit("custom-behavior", customBehaviorRoute("10.0.0.0/24", "fd00:2::100"))
	waitDelivered(t, m, "custom-behavior")
	if headend.countV4() != 1 {
		t.Fatalf("the receive half stopped working: %v", sortedV4(headend))
	}
}

// mustEntries reads the installed dispatch entries.
func mustEntries(t *testing.T, sids *fakeSIDOps) map[string]*bpf.SidFunctionEntry {
	t.Helper()
	got, err := sids.ListSidFunctions()
	if err != nil {
		t.Fatalf("list sid functions: %v", err)
	}
	return got
}

// Unregistering takes the plugin's advertisement and its SID with it: an
// address nobody dispatches on, still advertised, is a blackhole.
func TestExamplePluginUnregisterRetractsEverything(t *testing.T) {
	src := newFakeSource()
	headend := newFakeHeadendOps()
	alloc := &fakeAllocator{}
	sids := newFakeSIDOps()
	adv := &fakeAdvertiser{}

	m, err := NewManager(ManagerConfig{
		Source: src, Claims: newFakeClaims(), Headend: headend,
		Advertiser: adv, Locators: alloc, SIDFunctions: sids,
		EncapSource: testEncapSource,
		LocatorInfo: testLocators(), VRFBindings: testBindings(),
	})
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	defer m.Close(context.Background())

	if err := m.Register(context.Background(), Registration{
		Name:         "custom-behavior",
		Module:       examplePlugin(t),
		Config:       exampleConfig(0xFE01, "main", "10.7.0.0/24", testVRF, 33, "2001:db8::1"),
		Behaviors:    []uint16{0xFE01},
		Capabilities: testCaps(), Scope: testScope(),
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
	waitDelivered(t, m, "custom-behavior")

	if err := m.Unregister(context.Background(), "custom-behavior"); err != nil {
		t.Fatalf("unregister: %v", err)
	}
	if _, withdrawn := adv.counts(); withdrawn != 1 {
		t.Errorf("withdrew %d routes, want the plugin's advertisement", withdrawn)
	}
	if sids.count() != 0 {
		t.Errorf("%d dispatch entries left behind", sids.count())
	}
	if alloc.releasedCount() != 1 {
		t.Errorf("released %d addresses, want the plugin's SID back", alloc.releasedCount())
	}
}

// Two route reflectors advertise the same prefix, so it arrives as two
// paths and is withdrawn twice. The first withdrawal must not take the
// prefix down while the other path still offers it -- traffic would stop
// with nothing left in the plugin's state to explain why.
func TestExamplePluginKeepsAPrefixWhileAnyPathRemains(t *testing.T) {
	m, src, ops := exampleManager(t)

	viaA := customBehaviorRoute("10.0.0.0/24", "fd00:2::100")
	viaB := customBehaviorRoute("10.0.0.0/24", "fd00:2::200")
	viaB.Source = bgp.PathSource{Peer: netip.MustParseAddr("192.0.2.2")}
	src.emit("custom-behavior", viaA)
	waitDelivered(t, m, "custom-behavior")
	src.emit("custom-behavior", viaB)
	waitDelivered(t, m, "custom-behavior")
	if ops.countV4() != 1 {
		t.Fatalf("two paths for one prefix produced %d entries, want 1", ops.countV4())
	}

	// The first reflector withdraws. The prefix is still reachable.
	withdrawA := customBehaviorRoute("10.0.0.0/24", "")
	withdrawA.IsWithdraw = true
	withdrawA.EndpointBehavior = 0 // as it arrives on the wire
	src.emit("custom-behavior", withdrawA)
	waitDelivered(t, m, "custom-behavior")
	if ops.countV4() != 1 {
		t.Fatalf("withdrawing one of two paths removed the prefix: %v", sortedV4(ops))
	}

	// The second withdraws too, and now there is nothing left.
	withdrawB := withdrawA
	withdrawB.Source = viaB.Source
	src.emit("custom-behavior", withdrawB)
	waitDelivered(t, m, "custom-behavior")
	if ops.countV4() != 0 {
		t.Fatalf("the last path went away but %v is still steered", sortedV4(ops))
	}
}

// A replay says what exists and cannot say what stopped existing. A plugin
// whose view outlives one would keep declaring a route withdrawn while it
// was not listening, and no later event would remove it -- so the host
// tells it to drop that view first.
func TestExamplePluginDropsItsViewOnReplay(t *testing.T) {
	m, src, ops := exampleManager(t)
	src.emit("custom-behavior", customBehaviorRoute("10.0.0.0/24", "fd00:2::100"))
	src.emit("custom-behavior", customBehaviorRoute("10.0.1.0/24", "fd00:2::200"))
	waitDelivered(t, m, "custom-behavior")
	if ops.countV4() != 2 {
		t.Fatalf("setup: %v, want two entries", sortedV4(ops))
	}

	// One of them is withdrawn behind the plugin's back: the rib now holds
	// only the other, which is exactly what a route withdrawn during a
	// disconnect looks like.
	src.setRib(customBehaviorRoute("10.0.1.0/24", "fd00:2::200"))
	if err := m.snapshotFor("custom-behavior"); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	waitDelivered(t, m, "custom-behavior")

	got := sortedV4(ops)
	if len(got) != 1 || got[0] != "10.0.1.0/24" {
		t.Fatalf("after the replay the data plane holds %v, want only the route the rib still has", got)
	}
}

func TestExamplePluginDisablingSendingRetractsPreviousOwnerState(t *testing.T) {
	for _, tt := range []struct {
		name     string
		config   []byte
		wantSIDs int
	}{
		{"receive only", nil, 0},
		{"keep SID without advertising", exampleConfig(0xFE01, "main", "", "", 33, ""), 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			sids, adv := newFakeSIDOps(), &fakeAdvertiser{}
			m, err := NewManager(ManagerConfig{
				Source: newFakeSource(), Claims: newFakeClaims(), Headend: newFakeHeadendOps(),
				Advertiser: adv, Locators: &fakeAllocator{}, SIDFunctions: sids,
				EncapSource: testEncapSource, LocatorInfo: testLocators(), VRFBindings: testBindings(),
			})
			if err != nil {
				t.Fatal(err)
			}
			defer m.Close(context.Background())
			reg := Registration{
				Name: "custom-behavior", Module: examplePlugin(t),
				Config:    exampleConfig(0xFE01, "main", "10.7.0.0/24", testVRF, 33, "2001:db8::1"),
				Behaviors: []uint16{0xFE01}, Capabilities: testCaps(), Scope: testScope(),
			}
			if err := m.Register(context.Background(), reg); err != nil {
				t.Fatal(err)
			}
			waitDelivered(t, m, reg.Name)
			if got, _ := adv.counts(); got != 1 || sids.count() != 1 {
				t.Fatal("sender setup did not allocate and advertise")
			}
			reg.Config = tt.config
			if err := m.Register(context.Background(), reg); err != nil {
				t.Fatal(err)
			}
			waitDelivered(t, m, reg.Name)
			if got := sids.count(); got != tt.wantSIDs {
				t.Fatalf("SID count after upgrade=%d, want %d", got, tt.wantSIDs)
			}
			if live := m.advertise.LiveRoutes(bpf.OwnerPluginBundle(reg.Name)); len(live) != 0 {
				t.Fatalf("advertisements survived disabling sending: %+v", live)
			}
			if _, withdrawn := adv.counts(); withdrawn != 1 {
				t.Fatalf("withdrawn=%d, want the previous advertisement retracted", withdrawn)
			}
		})
	}
}

func TestExamplePluginRetriesDroppedSIDNotification(t *testing.T) {
	owner := bpf.OwnerPluginBundle("custom-behavior")
	sids, adv := newFakeSIDOps(), &fakeAdvertiser{}
	localSIDs := NewLocalSIDSet(&fakeAllocator{}, sids, nil, nil)
	advertise := NewAdvertiseSet(adv, NewLeases())
	dropNotifications, attempts := true, 0
	var notifications []AllocatedSID
	ops, err := NewPluginOps(PluginOpsConfig{
		Owner: owner, Headend: newFakeHeadendOps(), Capabilities: testCaps(),
		Guard:     NewGuard(testScope(), testLocators(), testBindings()),
		LocalSIDs: localSIDs, Advertise: advertise,
		OnLocalSIDs: func(allocated []AllocatedSID) bool {
			attempts++
			if dropNotifications {
				return false // The same result as a full manager delivery queue.
			}
			notifications = append(notifications, allocated...)
			return true
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	inst, err := wasm.Instantiate(context.Background(), wasm.Config{
		Name: "custom-behavior", Module: examplePlugin(t), Ops: ops, Capabilities: testCaps(),
		ConfigBlob: exampleConfig(0xFE01, "main", "10.7.0.0/24", testVRF, 33, "2001:db8::1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = inst.Close(context.Background()) }()
	if err := ops.Publish(); err != nil {
		t.Fatal(err)
	}
	if err := inst.Tick(context.Background(), int64(time.Second)); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 || sids.count() != 1 || advertise.LiveCount(owner) != 0 {
		t.Fatalf("missing notification: attempts=%d, SIDs=%d, advertisements=%d", attempts, sids.count(), advertise.LiveCount(owner))
	}
	dropNotifications = false
	if err := inst.Tick(context.Background(), int64(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if len(notifications) != 1 {
		t.Fatalf("retry delivered %d notifications, want 1", len(notifications))
	}
	sid := notifications[0]
	raw, err := proto.Marshal(&v1.PluginEventBatch{Events: []*v1.PluginEvent{{
		Kind: v1.PluginEventKind_PLUGIN_EVENT_KIND_LOCAL_SID, Sequence: 1,
		LocalSid: &v1.PluginLocalSidAllocated{Name: sid.Name, Sid: sid.SID.String(), Locator: sid.Locator},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inst.HandleEvents(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	if advertise.LiveCount(owner) != 1 || sids.count() != 1 {
		t.Fatal("notification recovery did not advertise the existing SID")
	}
	gen := ops.nextGen
	if err := inst.Tick(context.Background(), int64(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if ops.nextGen != gen {
		t.Fatal("allocation kept retrying after the SID event arrived")
	}
}

func TestExamplePluginCapabilityReductionPrunesStateWithinUnchangedScope(t *testing.T) {
	for _, tt := range []struct {
		name                                      string
		capabilities                              []string
		wantHeadend, wantSIDs, wantAdvertisements int
	}{
		{"revoke headend", []string{"advertise", "local_sid"}, 0, 1, 1},
		{"revoke advertise", []string{"headend", "local_sid"}, 1, 1, 0},
		{"revoke local SID", []string{"headend", "advertise"}, 1, 0, 0},
		{"revoke sender capabilities", []string{"headend"}, 1, 0, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			src, headend := newFakeSource(), newFakeHeadendOps()
			sids, adv := newFakeSIDOps(), &fakeAdvertiser{}
			m, err := NewManager(ManagerConfig{
				Source: src, Claims: newFakeClaims(), Headend: headend,
				Advertiser: adv, Locators: &fakeAllocator{}, SIDFunctions: sids,
				EncapSource: testEncapSource, LocatorInfo: testLocators(), VRFBindings: testBindings(),
			})
			if err != nil {
				t.Fatal(err)
			}
			defer m.Close(context.Background())
			reg := Registration{
				Name: "custom-behavior", Module: examplePlugin(t),
				Config:    exampleConfig(0xFE01, "main", "10.7.0.0/24", testVRF, 33, "2001:db8::1"),
				Behaviors: []uint16{0xFE01}, Capabilities: testCaps(), Scope: testScope(),
			}
			if err := m.Register(context.Background(), reg); err != nil {
				t.Fatal(err)
			}
			route := customBehaviorRoute("10.0.0.0/24", "fd00:2::100")
			src.setRib(route)
			src.emit(reg.Name, route)
			waitDelivered(t, m, reg.Name)
			if headend.countV4() != 1 || sids.count() != 1 {
				t.Fatal("setup did not install forwarding state")
			}
			// Keep both config and scope. The guest still wants these entries,
			// but can no longer declare or clear a kind whose grant was removed.
			reg.Capabilities, err = wasm.ParseCapabilities(tt.capabilities)
			if err != nil {
				t.Fatal(err)
			}
			if err := m.Register(context.Background(), reg); err != nil {
				t.Fatal(err)
			}
			waitDelivered(t, m, reg.Name)
			owner := bpf.OwnerPluginBundle(reg.Name)
			if got := headend.countV4(); got != tt.wantHeadend {
				t.Fatalf("headend=%d, want %d", got, tt.wantHeadend)
			}
			if got := sids.count(); got != tt.wantSIDs {
				t.Fatalf("SID count=%d, want %d", got, tt.wantSIDs)
			}
			if got := len(m.advertise.LiveRoutes(owner)); got != tt.wantAdvertisements {
				t.Fatalf("live advertisements=%d, want %d", got, tt.wantAdvertisements)
			}
		})
	}
}
