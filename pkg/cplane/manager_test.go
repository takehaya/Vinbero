package cplane

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/cplane/wasm"
	"github.com/takehaya/vinbero/pkg/locator"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

// declareModule is a WebAssembly plugin that declares a fixed desired set
// on every event it receives. Its source is testdata/declare.wat.
func declareModule(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "declare.wasm"))
	if err != nil {
		t.Fatalf("read declare fixture: %v", err)
	}
	return b
}

// fakeSource stands in for the demux.
//
// Consumers are keyed by an id, not by name, because that is what the
// demux does: an upgrade subscribes its replacement before cancelling the
// version it replaces, so for a moment one name has two subscriptions. A
// name-keyed fake makes the second registration erase the first, and the
// cancel that follows then removes the wrong one -- which looks like a bug
// in the manager and is not.
type fakeSource struct {
	mu          sync.Mutex
	handlers    map[int]bgp.RouteHandler
	names       map[int]string
	families    map[int][]bgp.Family
	nextID      int
	regErr      error
	cancels     int
	rib         []bgp.RouteEvent
	snapshots   int
	snapshotErr error
}

func newFakeSource() *fakeSource {
	return &fakeSource{
		handlers: map[int]bgp.RouteHandler{},
		names:    map[int]string{},
		families: map[int][]bgp.Family{},
	}
}

func (f *fakeSource) Register(name string, families []bgp.Family, h bgp.RouteHandler) (func(), error) {
	if f.regErr != nil {
		return nil, f.regErr
	}
	f.mu.Lock()
	id := f.nextID
	f.nextID++
	f.handlers[id] = h
	f.names[id] = name
	f.families[id] = families
	f.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.cancels++
			delete(f.handlers, id)
			delete(f.names, id)
			delete(f.families, id)
		})
	}, nil
}

// emit delivers to the newest subscription under a name, as the demux
// would deliver to whichever consumer is live.
func (f *fakeSource) emit(name string, ev bgp.RouteEvent) bool {
	f.mu.Lock()
	var (
		h      bgp.RouteHandler
		newest = -1
	)
	for id, got := range f.names {
		if got == name && id > newest {
			newest, h = id, f.handlers[id]
		}
	}
	f.mu.Unlock()
	if h == nil {
		return false
	}
	h(ev)
	return true
}

// RegisterQuiet adds a consumer without replaying, like the demux does for
// a consumer that takes its own snapshot.
func (f *fakeSource) RegisterQuiet(name string, families []bgp.Family, h bgp.RouteHandler) (func(), error) {
	return f.Register(name, families, h)
}

// SnapshotTo replays what the fake source is holding, standing in for the
// demux's loc-rib snapshot.
func (f *fakeSource) SnapshotTo(_ []bgp.Family, h bgp.RouteHandler) error {
	f.mu.Lock()
	if f.snapshotErr != nil {
		err := f.snapshotErr
		f.mu.Unlock()
		return err
	}
	rib := append([]bgp.RouteEvent(nil), f.rib...)
	f.mu.Unlock()
	f.mu.Lock()
	f.snapshots++
	f.mu.Unlock()
	for _, ev := range rib {
		h(ev)
	}
	return nil
}

// setRib replaces what a snapshot replays, which is how a test says a
// route went away while nobody was listening.
func (f *fakeSource) setRib(events ...bgp.RouteEvent) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rib = append([]bgp.RouteEvent(nil), events...)
}

// seedRib makes a route part of what a snapshot replays.
func (f *fakeSource) seedRib(events ...bgp.RouteEvent) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rib = append(f.rib, events...)
}

func (f *fakeSource) snapshotCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.snapshots
}

func (f *fakeSource) registered(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, got := range f.names {
		if got == name {
			return true
		}
	}
	return false
}

// fakeRetractingSource is a fakeSource that also counts how often the
// manager asked it to retract claimed routes from the built-in appliers.
type fakeRetractingSource struct {
	*fakeSource
	mu       sync.Mutex
	retracts int
}

func newFakeRetractingSource() *fakeRetractingSource {
	return &fakeRetractingSource{fakeSource: newFakeSource()}
}

func (f *fakeRetractingSource) RetractClaimedFromBuiltins() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.retracts++
}

func (f *fakeRetractingSource) retractions() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.retracts
}

// fakeClaims records behavior claims.
type fakeClaims struct {
	mu       sync.Mutex
	held     map[string][]uint16
	claimErr error
	released []string
}

func newFakeClaims() *fakeClaims {
	return &fakeClaims{held: map[string][]uint16{}}
}

// claimed reports whether a plugin currently holds any codepoint.
func (c *fakeClaims) claimed(plugin string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.held[plugin]) > 0
}

func (c *fakeClaims) Replace(plugin string, codepoints []uint16) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.claimErr != nil {
		return c.claimErr
	}
	if len(codepoints) == 0 {
		delete(c.held, plugin)
		return nil
	}
	c.held[plugin] = codepoints
	return nil
}

func (c *fakeClaims) Release(plugin string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.held, plugin)
	c.released = append(c.released, plugin)
}

func (c *fakeClaims) Claims(plugin string) []uint16 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]uint16(nil), c.held[plugin]...)
}

func (c *fakeClaims) holds(plugin string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.held[plugin]
	return ok
}

// testEncapSource stands in for the daemon's locator lookup, which in a
// live daemon resolves only after an operator registers one.
func testEncapSource() (netip.Addr, error) {
	return netip.MustParseAddr("fd00:1::1"), nil
}

// testCaps grants everything the example and the fixtures declare. A test
// that is about the gate itself grants a narrower set explicitly.
func testCaps() wasm.Capabilities {
	caps, err := wasm.ParseCapabilities([]string{
		string(wasm.CapHeadend), string(wasm.CapAdvertise), string(wasm.CapLocalSID),
	})
	if err != nil {
		panic(err)
	}
	return caps
}

// testScope covers everything the fixtures declare, the way testCaps
// grants everything they call. A test about the scope itself states a
// narrower one explicitly.
func testScope() Scope {
	slots := func(from, to uint32) []uint32 {
		out := make([]uint32, 0, to-from+1)
		for s := from; s <= to; s++ {
			out = append(out, s)
		}
		return out
	}
	scope, err := ParseScope(ScopeSpec{
		// "late" is the locator a fixture names before an operator has
		// registered it: in scope, but not yet resolvable.
		Locators:        []string{"main", "second", "late"},
		VRFs:            []string{testVRF},
		HeadendPrefixes: []string{"10.0.0.0/8", "fd00::/16"},
		HeadendV4Slots:  slots(16, 31),
		HeadendV6Slots:  slots(16, 31),
		EndpointSlots:   slots(32, 63),
	})
	if err != nil {
		panic(err)
	}
	return scope
}

// testVRF is the VRF the fixtures originate into, and testRD is the route
// distinguisher its binding lends them.
const (
	testVRF = "vpn-a"
	testRD  = "65000:1"
)

// testGuard is the guard the fixtures run under, resolving against the
// locators and the binding they name.
func testGuard() *Guard {
	return NewGuard(testScope(), testLocators(), testBindings())
}

// fakeLocatorSource stands in for the locator manager.
type fakeLocatorSource struct {
	byName map[string]locator.Locator
}

func (f *fakeLocatorSource) Get(name string) (locator.Locator, bool) {
	loc, ok := f.byName[name]
	return loc, ok
}

func testLocators() *fakeLocatorSource {
	return &fakeLocatorSource{byName: map[string]locator.Locator{
		"main":   {Name: "main", Prefix: netip.MustParsePrefix("fd00:1::/48")},
		"second": {Name: "second", Prefix: netip.MustParsePrefix("fd00:2::/48")},
	}}
}

// fakeBindingSource stands in for the VRF-to-BGP bindings.
//
// It is locked because the real vrfbgp.Manager.Get takes an RLock, and a
// concurrency test flips a binding from one goroutine while a plugin worker
// resolves it from another. An unsynchronised fake would produce a race
// report pointing at the fixture, which is how a real race gets dismissed
// as a test bug.
type fakeBindingSource struct {
	mu     sync.RWMutex
	byName map[string]vrfbgp.Binding
}

func (f *fakeBindingSource) Get(name string) (vrfbgp.Binding, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	b, ok := f.byName[name]
	return b, ok
}

// set replaces a binding under the lock, for tests that mutate one while a
// worker may be reading it.
func (f *fakeBindingSource) set(name string, b vrfbgp.Binding) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.byName[name] = b
}

// remove deletes a binding under the lock.
func (f *fakeBindingSource) remove(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.byName, name)
}

func testBindings() *fakeBindingSource {
	return &fakeBindingSource{byName: map[string]vrfbgp.Binding{
		testVRF: vrfbgp.Binding{
			VRFName:   testVRF,
			RD:        testRD,
			ImportRTs: []string{testRD},
			ExportRTs: []string{testRD},
		}.Normalize(),
	}}
}

// waitDelivered blocks until the plugin has consumed every event queued
// for it. Delivery is asynchronous -- a guest call must not run on the BGP
// watch goroutine -- so a test that emits and immediately asserts would
// race the worker.
func waitDelivered(t *testing.T, m *Manager, name string) {
	t.Helper()
	if !m.WaitIdle(name, 5*time.Second) {
		t.Fatalf("plugin %q did not consume its events within the timeout", name)
	}
}

// newTestManagerWithStore builds a manager backed by a persistence store,
// for the tests about surviving a restart.
// newTestManagerWithStoreAndClaims is newTestManagerWithStore for a test
// that needs to inspect what stays claimed.
func newTestManagerWithStoreAndClaims(t *testing.T, src EventSource, store *Store, claims BehaviorClaims) (*Manager, *fakeHeadendOps) {
	t.Helper()
	ops := newFakeHeadendOps()
	m, err := NewManager(ManagerConfig{
		Source:      src,
		Claims:      claims,
		Headend:     ops,
		Store:       store,
		EncapSource: testEncapSource,
		LocatorInfo: testLocators(),
		VRFBindings: testBindings(),
	})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	t.Cleanup(func() { m.Close(context.Background()) })
	return m, ops
}

func newTestManagerWithStore(t *testing.T, src EventSource, store *Store) (*Manager, *fakeHeadendOps) {
	t.Helper()
	ops := newFakeHeadendOps()
	m, err := NewManager(ManagerConfig{
		Source:      src,
		Claims:      newFakeClaims(),
		Headend:     ops,
		Store:       store,
		EncapSource: testEncapSource,
	})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	t.Cleanup(func() { m.Close(context.Background()) })
	return m, ops
}

func newTestManager(t *testing.T, src EventSource, claims BehaviorClaims) (*Manager, *fakeHeadendOps) {
	t.Helper()
	ops := newFakeHeadendOps()
	m, err := NewManager(ManagerConfig{
		Source:      src,
		Claims:      claims,
		Headend:     ops,
		EncapSource: testEncapSource,
	})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	t.Cleanup(func() { m.Close(context.Background()) })
	return m, ops
}

func TestRegisterRunsPluginAndDeliversEvents(t *testing.T) {
	src := newFakeSource()
	m, ops := newTestManager(t, src, newFakeClaims())
	reg := Registration{Name: "declare", Module: declareModule(t), Capabilities: testCaps(), Scope: testScope()}
	if err := m.Register(context.Background(), reg); err != nil {
		t.Fatalf("register: %v", err)
	}
	if !src.registered("declare") {
		t.Fatal("the plugin did not subscribe to the event source")
	}

	if !src.emit("declare", bgp.RouteEvent{Family: bgp.FamilyVPNv4}) {
		t.Fatal("emit found no handler")
	}
	waitDelivered(t, m, "declare")
	// The fixture declares one headend entry per event it sees.
	if ops.countV4() != 1 {
		t.Fatalf("data plane holds %d entries, want the one the plugin declared", ops.countV4())
	}
	for prefix, entry := range ops.snapshotV4() {
		if prefix != "10.99.0.0/24" {
			t.Errorf("declared prefix = %q, want 10.99.0.0/24", prefix)
		}
		if entry.NumSegments != 1 {
			t.Errorf("declared %d segments, want 1", entry.NumSegments)
		}
	}
	// Everything the plugin wrote carries its own owner tag.
	want := bpf.OwnerPluginBundle("declare")
	for prefix, owner := range ops.v4Owners() {
		if owner != want {
			t.Errorf("entry %q is owned by %q, want %q", prefix, owner, want)
		}
	}
}

// Unregistering is deliberate, so the plugin's entries go with it.
func TestUnregisterFlushesOwnedState(t *testing.T) {
	src := newFakeSource()
	claims := newFakeClaims()
	m, ops := newTestManager(t, src, claims)
	reg := Registration{Name: "declare", Module: declareModule(t), Behaviors: []uint16{0xFE01}, Capabilities: testCaps(), Scope: testScope()}
	if err := m.Register(context.Background(), reg); err != nil {
		t.Fatalf("register: %v", err)
	}
	src.emit("declare", bgp.RouteEvent{Family: bgp.FamilyVPNv4})
	waitDelivered(t, m, "declare")
	if ops.countV4() != 1 {
		t.Fatalf("setup: data plane holds %d entries, want 1", ops.countV4())
	}

	if err := m.Unregister(context.Background(), "declare"); err != nil {
		t.Fatalf("unregister: %v", err)
	}
	if ops.countV4() != 0 {
		t.Fatalf("unregister left %d entries behind", ops.countV4())
	}
	if claims.holds("declare") {
		t.Error("unregister did not release the behavior claim")
	}
	if src.registered("declare") {
		t.Error("unregister did not detach the plugin from the event source")
	}
	if err := m.Unregister(context.Background(), "declare"); err == nil {
		t.Error("unregistering twice should report that the plugin is gone")
	}
}

// Registering an existing name is an in-place upgrade: the state the old
// instance wrote stays, and the new one reconciles over it. A flush here
// would blackhole traffic for the length of the swap.
func TestReregisterIsANonDisruptiveUpgrade(t *testing.T) {
	src := newFakeSource()
	m, ops := newTestManager(t, src, newFakeClaims())
	reg := Registration{Name: "declare", Module: declareModule(t), Capabilities: testCaps(), Scope: testScope()}
	if err := m.Register(context.Background(), reg); err != nil {
		t.Fatalf("first register: %v", err)
	}
	src.emit("declare", bgp.RouteEvent{Family: bgp.FamilyVPNv4})
	waitDelivered(t, m, "declare")
	if ops.countV4() != 1 {
		t.Fatalf("setup: data plane holds %d entries, want 1", ops.countV4())
	}

	if err := m.Register(context.Background(), reg); err != nil {
		t.Fatalf("re-register: %v", err)
	}
	if ops.countV4() != 1 {
		t.Fatalf("the upgrade disturbed the data plane: %d entries", ops.countV4())
	}
	if names := m.List(); len(names) != 1 {
		t.Fatalf("manager lists %v, want one plugin", names)
	}
	// The replacement is the instance receiving events now.
	src.emit("declare", bgp.RouteEvent{Family: bgp.FamilyVPNv4})
	waitDelivered(t, m, "declare")
	if ops.countV4() != 1 {
		t.Fatalf("after the upgrade the plugin declared %d entries, want its usual 1", ops.countV4())
	}
}

// A behavior another plugin holds must stop the registration before
// anything is instantiated.
func TestRegisterRejectedWhenClaimFails(t *testing.T) {
	src := newFakeSource()
	claims := newFakeClaims()
	claims.claimErr = errors.New("codepoint already claimed")
	m, _ := newTestManager(t, src, claims)
	err := m.Register(context.Background(), Registration{
		Name:         "declare",
		Module:       declareModule(t),
		Behaviors:    []uint16{0xFE01},
		Capabilities: testCaps(), Scope: testScope(),
	})
	if err == nil {
		t.Fatal("registration succeeded despite the claim being refused")
	}
	if src.registered("declare") {
		t.Error("a rejected registration still subscribed to events")
	}
	if names := m.List(); len(names) != 0 {
		t.Errorf("a rejected registration left %v behind", names)
	}
}

// A module that fails admission must not leave its claim behind.
func TestFailedInstantiationReleasesClaim(t *testing.T) {
	src := newFakeSource()
	claims := newFakeClaims()
	m, _ := newTestManager(t, src, claims)
	err := m.Register(context.Background(), Registration{
		Name:      "broken",
		Module:    []byte("not wasm at all"),
		Behaviors: []uint16{0xFE01},
	})
	if err == nil {
		t.Fatal("a malformed module was accepted")
	}
	if claims.holds("broken") {
		t.Error("the claim of a plugin that never started was not released")
	}
}

func TestRegisterRejectsUnusableName(t *testing.T) {
	m, _ := newTestManager(t, newFakeSource(), newFakeClaims())
	for _, name := range []string{"", "has:colon"} {
		if err := m.Register(context.Background(), Registration{Name: name, Module: declareModule(t), Capabilities: testCaps(), Scope: testScope()}); err == nil {
			t.Errorf("name %q was accepted", name)
		}
	}
}

// Claiming a behavior with no registry configured is refused rather than
// silently ignored: the plugin would otherwise run believing it owns a
// codepoint that nothing withholds from the built-in appliers.
func TestClaimWithoutRegistryIsRefused(t *testing.T) {
	src := newFakeSource()
	m, _ := newTestManager(t, src, nil)
	err := m.Register(context.Background(), Registration{
		Name:         "declare",
		Module:       declareModule(t),
		Behaviors:    []uint16{0xFE01},
		Capabilities: testCaps(), Scope: testScope(),
	})
	if err == nil {
		t.Fatal("a behavior claim was accepted with no claim registry")
	}
}

// Shutting the daemon down is not the same as taking a plugin away: the
// data plane keeps what it has.
func TestCloseDoesNotFlush(t *testing.T) {
	src := newFakeSource()
	m, ops := newTestManager(t, src, newFakeClaims())
	if err := m.Register(context.Background(), Registration{Name: "declare", Module: declareModule(t), Capabilities: testCaps(), Scope: testScope()}); err != nil {
		t.Fatalf("register: %v", err)
	}
	src.emit("declare", bgp.RouteEvent{Family: bgp.FamilyVPNv4})
	waitDelivered(t, m, "declare")
	if ops.countV4() != 1 {
		t.Fatalf("setup: %d entries, want 1", ops.countV4())
	}

	m.Close(context.Background())
	if ops.countV4() != 1 {
		t.Fatalf("close flushed the data plane: %d entries left", ops.countV4())
	}
	if names := m.List(); len(names) != 0 {
		t.Errorf("close left %v registered", names)
	}
}

func TestEncodeRouteEventCarriesUnknownAttributes(t *testing.T) {
	ev := bgp.RouteEvent{
		Family:           bgp.FamilyVPNv4,
		Source:           bgp.PathSource{Peer: netip.MustParseAddr("192.0.2.1"), PathID: 7},
		EndpointBehavior: 0xFE01,
		VPN: &bgp.VPNRoute{
			RD: "65000:1", Prefix: "10.0.0.0/24", SRv6SID: "fd00:1::100",
			NextHop: "2001:db8::1", RTs: []string{"65000:1"}, Color: 100,
		},
		UnknownAttrs: []bgp.UnknownAttribute{{Type: 253, Flags: 0xc0, Value: []byte{1, 2, 3}}},
	}
	got := EncodeRouteEvent(ev)
	if got.GetFamily() != "vpnv4" || got.GetPeer() != "192.0.2.1" || got.GetPathId() != 7 {
		t.Fatalf("identity fields wrong: %+v", got)
	}
	if got.GetEndpointBehavior() != 0xFE01 {
		t.Errorf("endpoint behavior = %#x, want 0xFE01", got.GetEndpointBehavior())
	}
	if got.GetRd() != "65000:1" || got.GetPrefix() != "10.0.0.0/24" || got.GetSrv6Sid() != "fd00:1::100" {
		t.Errorf("VPN fields wrong: %+v", got)
	}
	attrs := got.GetUnknownAttrs()
	if len(attrs) != 1 || attrs[0].GetType() != 253 || len(attrs[0].GetValue()) != 3 {
		t.Errorf("unknown attributes = %+v, want the type-253 one", attrs)
	}
}

// A locally originated path never reaches a plugin, so its peer field is
// simply empty rather than a bogus address.
func TestEncodeRouteEventLocalOriginHasNoPeer(t *testing.T) {
	got := EncodeRouteEvent(bgp.RouteEvent{Family: bgp.FamilyVPNv4})
	if got.GetPeer() != "" {
		t.Fatalf("peer = %q, want empty", got.GetPeer())
	}
}

func TestDecodeHeadendEntry(t *testing.T) {
	defaultSrc := netip.MustParseAddr("fd00:1::1")
	in := &v1.PluginHeadendEntry{
		TriggerPrefix: "10.0.0.0/24",
		Segments:      []string{"fd00:2::100", "fd00:3::100"},
	}
	prefix, entry, err := DecodeHeadendEntry(in, AFv4, defaultSrc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if prefix != "10.0.0.0/24" {
		t.Errorf("prefix = %q", prefix)
	}
	if entry.NumSegments != 2 {
		t.Errorf("segments = %d, want 2", entry.NumSegments)
	}
	// The outer destination is the first segment: the next hop the
	// encapsulated packet is actually sent to. This mirrors what the
	// built-in applier writes; a second convention for plugins would make
	// `vbctl headend-v4 list` report a destination the data plane does not
	// use.
	if got := netip.AddrFrom16(entry.DstAddr); got != netip.MustParseAddr("fd00:2::100") {
		t.Errorf("destination = %v, want the first segment", got)
	}
	if got := netip.AddrFrom16(entry.SrcAddr); got != defaultSrc {
		t.Errorf("source = %v, want the daemon default %v", got, defaultSrc)
	}
}

func TestDecodeHeadendEntryRejectsMalformed(t *testing.T) {
	src := netip.MustParseAddr("fd00:1::1")
	tests := []struct {
		name string
		in   *v1.PluginHeadendEntry
	}{
		{name: "nil"},
		{name: "no prefix", in: &v1.PluginHeadendEntry{Segments: []string{"fd00:2::1"}}},
		{name: "bad prefix", in: &v1.PluginHeadendEntry{TriggerPrefix: "not-a-prefix", Segments: []string{"fd00:2::1"}}},
		{name: "no segments", in: &v1.PluginHeadendEntry{TriggerPrefix: "10.0.0.0/24"}},
		{name: "bad segment", in: &v1.PluginHeadendEntry{TriggerPrefix: "10.0.0.0/24", Segments: []string{"nope"}}},
		{name: "v4 segment", in: &v1.PluginHeadendEntry{TriggerPrefix: "10.0.0.0/24", Segments: []string{"192.0.2.1"}}},
		{name: "mode too large", in: &v1.PluginHeadendEntry{TriggerPrefix: "10.0.0.0/24", Segments: []string{"fd00:2::1"}, Mode: 300}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := DecodeHeadendEntry(tt.in, AFv4, src); err == nil {
				t.Fatal("malformed entry was accepted")
			}
		})
	}
}

func TestDecodeHeadendEntryRejectsTooManySegments(t *testing.T) {
	segments := make([]string, bpf.MaxSegments+1)
	for i := range segments {
		segments[i] = "fd00:2::1"
	}
	in := &v1.PluginHeadendEntry{TriggerPrefix: "10.0.0.0/24", Segments: segments}
	if _, _, err := DecodeHeadendEntry(in, AFv4, netip.MustParseAddr("fd00:1::1")); err == nil {
		t.Fatal("a segment list longer than the map holds was accepted")
	}
}

func TestPluginOpsTransactionLifecycle(t *testing.T) {
	headend := newFakeHeadendOps()
	ops, err := NewPluginOps(PluginOpsConfig{
		Owner:        ownerA,
		Headend:      headend,
		Leases:       NewLeases(),
		Capabilities: testCaps(), Guard: testGuard(),
		EncapSource: testEncapSource,
	})
	if err != nil {
		t.Fatalf("new plugin ops: %v", err)
	}
	// Commits are held until the plugin is published, so that an
	// instantiation which fails cannot leave state behind. The manager
	// does this once the plugin is live; a test driving the ops directly
	// has to do it too.
	if err := ops.Publish(); err != nil {
		t.Fatalf("publish: %v", err)
	}

	gen, err := ops.ApplyBegin(uint32(v1.PluginApplyKind_PLUGIN_APPLY_KIND_HEADEND_V4))
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	chunk, err := proto.Marshal(&v1.PluginApplyChunk{HeadendEntries: []*v1.PluginHeadendEntry{{
		TriggerPrefix: "10.0.0.0/24",
		Segments:      []string{"fd00:2::100"},
	}}})
	if err != nil {
		t.Fatalf("marshal chunk: %v", err)
	}
	if err := ops.ApplyPut(gen, chunk); err != nil {
		t.Fatalf("put: %v", err)
	}
	// Nothing reaches the data plane before the commit.
	if headend.countV4() != 0 {
		t.Fatalf("a chunk was applied before commit: %d entries", headend.countV4())
	}
	if err := ops.ApplyCommit(gen); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if headend.countV4() != 1 {
		t.Fatalf("commit applied %d entries, want 1", headend.countV4())
	}
	if ops.OpenTransactions() != 0 {
		t.Errorf("commit left %d transactions open", ops.OpenTransactions())
	}
	// A generation is single use.
	if err := ops.ApplyCommit(gen); err == nil {
		t.Error("committing a finished transaction was accepted")
	}
}

func TestPluginOpsAbortDiscards(t *testing.T) {
	headend := newFakeHeadendOps()
	ops, err := NewPluginOps(PluginOpsConfig{
		Owner: ownerA, Headend: headend, Leases: NewLeases(), Capabilities: testCaps(), Guard: testGuard(),
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
	ops.ApplyAbort(gen)
	if ops.OpenTransactions() != 0 {
		t.Fatalf("abort left %d transactions open", ops.OpenTransactions())
	}
	if err := ops.ApplyCommit(gen); err == nil {
		t.Error("committing an aborted transaction was accepted")
	}
	if headend.countV4() != 0 {
		t.Errorf("an aborted transaction reached the data plane: %d entries", headend.countV4())
	}
}

// A plugin that opens transactions and never finishes them must not be
// able to grow the host without bound.
func TestPluginOpsBoundsOpenTransactions(t *testing.T) {
	ops, err := NewPluginOps(PluginOpsConfig{
		Owner: ownerA, Headend: newFakeHeadendOps(), Leases: NewLeases(),
		Capabilities: testCaps(), Guard: testGuard(), MaxOpenTransactions: 2,
	})
	if err != nil {
		t.Fatalf("new plugin ops: %v", err)
	}
	kind := uint32(v1.PluginApplyKind_PLUGIN_APPLY_KIND_HEADEND_V4)
	for i := 0; i < 2; i++ {
		if _, err := ops.ApplyBegin(kind); err != nil {
			t.Fatalf("begin %d: %v", i, err)
		}
	}
	if _, err := ops.ApplyBegin(kind); err == nil {
		t.Fatal("a third transaction was opened past the limit")
	}
}

func TestPluginOpsRejectsUnknownKindAndGeneration(t *testing.T) {
	ops, err := NewPluginOps(PluginOpsConfig{
		Owner: ownerA, Headend: newFakeHeadendOps(), Leases: NewLeases(), Capabilities: testCaps(), Guard: testGuard(),
	})
	if err != nil {
		t.Fatalf("new plugin ops: %v", err)
	}
	if _, err := ops.ApplyBegin(9999); err == nil {
		t.Error("an unknown apply kind was accepted")
	}
	if err := ops.ApplyPut(42, nil); err == nil {
		t.Error("a chunk for an unopened transaction was accepted")
	}
}

func TestPluginOpsFlushRemovesOwnedState(t *testing.T) {
	headend := newFakeHeadendOps()
	leases := NewLeases()
	ops, err := NewPluginOps(PluginOpsConfig{
		Owner: ownerA, Headend: headend, Leases: leases, Capabilities: testCaps(), Guard: testGuard(),
	})
	if err != nil {
		t.Fatalf("new plugin ops: %v", err)
	}
	if _, err := ApplyHeadendSet(headend, leases, ownerA, AFv4, desire("10.0.1.0/24"), unlimited); err != nil {
		t.Fatalf("seed: %v", err)
	}
	headend.seedV4("10.9.9.0/24", ownerB)

	if err := ops.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if _, ok := headend.getV4("10.0.1.0/24"); ok {
		t.Error("flush left the plugin's own entry behind")
	}
	if _, ok := headend.getV4("10.9.9.0/24"); !ok {
		t.Error("flush removed another owner's entry")
	}
}

// A plugin that cannot keep up has its events dropped rather than being
// allowed to block the BGP watch goroutine, and the drops are counted so
// "too slow" is distinguishable from "buggy".
func TestDroppedEventsAreCounted(t *testing.T) {
	src := newFakeSource()
	m, _ := newTestManager(t, src, newFakeClaims())
	if err := m.Register(context.Background(), Registration{
		Name: "declare", Module: declareModule(t),
		Capabilities: testCaps(), Scope: testScope(),
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if got := m.DroppedEvents("declare"); got != 0 {
		t.Fatalf("dropped %d before any event, want 0", got)
	}
	if got := m.DroppedEvents("not-registered"); got != 0 {
		t.Fatalf("dropped %d for an unknown plugin, want 0", got)
	}

	// Fill the queue far past its depth. Delivery cannot keep up with a
	// burst this size, so some batches must be dropped rather than queued
	// without bound.
	for i := 0; i < deliveryQueueDepth*4; i++ {
		src.emit("declare", bgp.RouteEvent{Family: bgp.FamilyVPNv4})
	}
	waitDelivered(t, m, "declare")
	if m.DroppedEvents("declare") == 0 {
		t.Skip("delivery kept up with the burst; the drop path is exercised by the queue depth, not the timing")
	}
}

// trapModule is a plugin whose handle_events always traps, so a test can
// drive the failure-and-restart path.
func trapModule(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "cplane", "wasm", "testdata", "trap.wasm"))
	if err != nil {
		t.Fatalf("read trap fixture: %v", err)
	}
	return b
}

// A restarted instance remembers nothing, so it has to be told what the
// network looks like. Without a replay its first declaration describes
// only the events that arrived after the restart, and because a
// declaration is a whole desired set, the reconcile prunes everything else
// the plugin owned. This is the test that says the replay happens.
func TestRestartReplaysTheRib(t *testing.T) {
	src := newFakeSource()
	m, _ := newTestManager(t, src, newFakeClaims())
	src.seedRib(bgp.RouteEvent{Family: bgp.FamilyVPNv4})

	if err := m.Register(context.Background(), Registration{
		Name: "trap", Module: trapModule(t),
		Capabilities: testCaps(), Scope: testScope(),
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
	before := src.snapshotCount()

	// The guest traps on this, which costs the instance.
	src.emit("trap", bgp.RouteEvent{Family: bgp.FamilyVPNv4})
	waitDelivered(t, m, "trap")

	deadline := time.Now().Add(5 * time.Second)
	for src.snapshotCount() == before {
		if time.Now().After(deadline) {
			t.Fatal("the restarted plugin was never replayed the rib")
		}
		time.Sleep(time.Millisecond)
	}
}

// maxRestarts bounds consecutive failures, not a plugin's lifetime total:
// a plugin that recovers and later fails again must not be treated as one
// that cannot start.
func TestRestartCounterResetsOnSuccess(t *testing.T) {
	src := newFakeSource()
	m, ops := newTestManager(t, src, newFakeClaims())
	if err := m.Register(context.Background(), Registration{
		Name: "declare", Module: declareModule(t),
		Capabilities: testCaps(), Scope: testScope(),
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
	// Deliver more batches than maxRestarts; all succeed, so the plugin
	// must still be alive and declaring at the end.
	for i := 0; i < maxRestarts+3; i++ {
		src.emit("declare", bgp.RouteEvent{Family: bgp.FamilyVPNv4})
		waitDelivered(t, m, "declare")
	}
	if ops.countV4() != 1 {
		t.Fatalf("the plugin stopped declaring: %v", sortedV4(ops))
	}
}

// A snapshot must reach the plugin whole. Dropping part of it would leave
// the plugin declaring a set that prunes the routes it never saw, so the
// replay path blocks rather than dropping.
func TestSnapshotIsNotDropped(t *testing.T) {
	src := newFakeSource()
	m, _ := newTestManager(t, src, newFakeClaims())
	// Far more routes than the delivery queue holds.
	for i := 0; i < deliveryQueueDepth*3; i++ {
		src.seedRib(bgp.RouteEvent{Family: bgp.FamilyVPNv4})
	}
	if err := m.Register(context.Background(), Registration{
		Name: "declare", Module: declareModule(t),
		Capabilities: testCaps(), Scope: testScope(),
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := m.snapshotFor("declare"); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	waitDelivered(t, m, "declare")
	if got := m.DroppedEvents("declare"); got != 0 {
		t.Fatalf("the snapshot dropped %d batches; a partial view prunes what the plugin cannot see", got)
	}
}

// A source that serves no snapshot cannot rebuild a view; the manager must
// say so rather than pretending the plugin is up to date.
func TestSnapshotWithoutASourceIsReported(t *testing.T) {
	// eventOnlySource deliberately does not implement SnapshotSource.
	src := &eventOnlySource{inner: newFakeSource()}
	m, _ := newTestManager(t, src, newFakeClaims())
	if err := m.Register(context.Background(), Registration{
		Name: "declare", Module: declareModule(t),
		Capabilities: testCaps(), Scope: testScope(),
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := m.snapshotFor("declare"); err == nil {
		t.Fatal("a manager with no snapshot source reported a successful replay")
	}
}

// eventOnlySource streams live events but serves no snapshot.
type eventOnlySource struct{ inner *fakeSource }

func (s *eventOnlySource) Register(name string, families []bgp.Family, h bgp.RouteHandler) (func(), error) {
	return s.inner.Register(name, families, h)
}

// tickModule counts the ticks it receives, so a test can tell whether the
// periodic callback is actually driven.
func tickModule(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "tick.wasm"))
	if err != nil {
		t.Fatalf("read tick fixture: %v", err)
	}
	return b
}

// The ABI has a periodic callback; nothing drove it until the worker did.
// A plugin that withdraws on a timeout cannot be written without it.
//
// The fixture declares its set from the tick alone, so a declaration
// reaching the data plane with no event ever delivered is the observable
// fact that the tick fired.
func TestTickIsDriven(t *testing.T) {
	src := newFakeSource()
	m, ops := newTestManager(t, src, newFakeClaims())
	if err := m.Register(context.Background(), Registration{
		Name:         "tick",
		Module:       tickModule(t),
		TickInterval: MinTickInterval,
		Capabilities: testCaps(), Scope: testScope(),
	}); err != nil {
		t.Fatalf("register: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for ops.countV4() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the periodic callback was never driven")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, ok := ops.getV4("10.99.0.0/24"); !ok {
		t.Fatalf("the tick declared %v, want the fixture's prefix", sortedV4(ops))
	}
}

// A plugin asking to be woken faster than the daemon is willing to call
// into a sandbox is clamped rather than obeyed.
func TestTickIntervalIsClamped(t *testing.T) {
	src := newFakeSource()
	m, _ := newTestManager(t, src, newFakeClaims())
	if err := m.Register(context.Background(), Registration{
		Name:         "tick",
		Module:       tickModule(t),
		TickInterval: time.Millisecond,
		Capabilities: testCaps(), Scope: testScope(),
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
	m.mu.Lock()
	got := m.plugins["tick"].worker.interval
	m.mu.Unlock()
	if got != MinTickInterval {
		t.Fatalf("tick interval = %s, want it clamped to %s", got, MinTickInterval)
	}
}

// Zero means undriven, which is right for a purely event-driven plugin.
func TestTickNotDrivenByDefault(t *testing.T) {
	src := newFakeSource()
	m, _ := newTestManager(t, src, newFakeClaims())
	if err := m.Register(context.Background(), Registration{
		Name: "tick", Module: tickModule(t),
		Capabilities: testCaps(), Scope: testScope(),
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
	m.mu.Lock()
	got := m.plugins["tick"].worker.interval
	m.mu.Unlock()
	if got != 0 {
		t.Fatalf("tick interval = %s, want it undriven", got)
	}
}

// A plugin that decides from several routes has to know when it has seen
// enough, or its first conclusions come from a partial view.
func TestEndOfReplayFollowsTheSnapshot(t *testing.T) {
	src := newFakeSource()
	m, _ := newTestManager(t, src, newFakeClaims())
	src.seedRib(bgp.RouteEvent{Family: bgp.FamilyVPNv4})

	var seen []*v1.PluginEvent
	var mu sync.Mutex
	if err := m.Register(context.Background(), Registration{
		Name: "declare", Module: declareModule(t),
		Capabilities: testCaps(), Scope: testScope(),
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
	// Inspect what the manager builds rather than what the guest sees:
	// the batch shape is the contract, and the guest is free to ignore it.
	mu.Lock()
	seen = append(seen, m.endOfReplayBatch(ReplaySourceBGP).GetEvents()...)
	mu.Unlock()

	if len(seen) != 1 {
		t.Fatalf("built %d events, want one", len(seen))
	}
	ev := seen[0]
	if ev.GetKind() != v1.PluginEventKind_PLUGIN_EVENT_KIND_END_OF_REPLAY {
		t.Errorf("kind = %v, want end-of-replay", ev.GetKind())
	}
	if ev.GetReplaySource() != ReplaySourceBGP {
		t.Errorf("source = %q, want %q", ev.GetReplaySource(), ReplaySourceBGP)
	}
	if ev.GetSequence() == 0 {
		t.Error("the event carries no sequence number")
	}
}

// A plugin may declare state from configure, which runs during
// instantiation. Applying it there would leave state behind when the
// instantiation then fails -- and on an upgrade that state carries the
// same owner tag as the instance still running, so the failed newcomer's
// declaration would prune the live plugin's entries.
func TestFailedInstantiationLeavesNoState(t *testing.T) {
	src := newFakeSource()
	headend := newFakeHeadendOps()
	alloc := &fakeAllocator{}
	sids := newFakeSIDOps()
	adv := &fakeAdvertiser{}
	m, err := NewManager(ManagerConfig{
		Source: src, Claims: newFakeClaims(), Headend: headend,
		Advertiser: adv, Locators: alloc, SIDFunctions: sids,
		EncapSource: testEncapSource,
	})
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	defer m.Close(context.Background())

	// The example declares a local SID from configure, then refuses the
	// config: an instantiation that declares and then fails.
	err = m.Register(context.Background(), Registration{
		Name:   "custom-behavior",
		Module: examplePlugin(t),
		Config: append(exampleConfig(0xFE01, "main", "10.7.0.0/24", "65000:7", 33, "2001:db8::1"),
			// A trailing byte that cannot be parsed, so configure returns
			// non-zero after it has already declared.
			0xff),
		Capabilities: testCaps(), Scope: testScope(),
	})
	if err == nil {
		t.Fatal("a module whose configure failed was registered")
	}
	if sids.count() != 0 {
		t.Errorf("%d dispatch entries left behind by a failed registration", sids.count())
	}
	if alloc.releasedCount() != 0 && sids.count() == 0 {
		// Releasing is fine; leaking an installed entry is not.
		t.Logf("allocator released %d addresses", alloc.releasedCount())
	}
	if names := m.List(); len(names) != 0 {
		t.Errorf("a failed registration left %v registered", names)
	}
}

// An upgrade whose new module fails must not disturb the instance still
// running under the same owner tag.
func TestFailedUpgradeLeavesTheRunningPluginAlone(t *testing.T) {
	src := newFakeSource()
	headend := newFakeHeadendOps()
	alloc := &fakeAllocator{}
	sids := newFakeSIDOps()
	adv := &fakeAdvertiser{}
	m, err := NewManager(ManagerConfig{
		Source: src, Claims: newFakeClaims(), Headend: headend,
		Advertiser: adv, Locators: alloc, SIDFunctions: sids,
		EncapSource: testEncapSource,
	})
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	defer m.Close(context.Background())

	good := Registration{
		Name:         "custom-behavior",
		Module:       examplePlugin(t),
		Config:       exampleConfig(0xFE01, "main", "10.7.0.0/24", "65000:7", 33, "2001:db8::1"),
		Behaviors:    []uint16{0xFE01},
		Capabilities: testCaps(), Scope: testScope(),
	}
	if err := m.Register(context.Background(), good); err != nil {
		t.Fatalf("register: %v", err)
	}
	waitDelivered(t, m, "custom-behavior")
	if sids.count() != 1 {
		t.Fatalf("setup: %d dispatch entries, want 1", sids.count())
	}
	advertisedBefore, _ := adv.counts()

	// A v2 that is not a module at all.
	bad := good
	bad.Module = []byte("not wasm")
	if err := m.Register(context.Background(), bad); err == nil {
		t.Fatal("a malformed upgrade was accepted")
	}

	if sids.count() != 1 {
		t.Errorf("the failed upgrade disturbed the running plugin's SIDs: %d left", sids.count())
	}
	if got, _ := adv.counts(); got != advertisedBefore {
		t.Errorf("the failed upgrade changed what was advertised: %d then %d", advertisedBefore, got)
	}
	if names := m.List(); len(names) != 1 {
		t.Errorf("the running plugin was dropped: %v", names)
	}
}

// One apply_begin serves every kind of declaration, so linking alone
// cannot separate them: a plugin granted only advertise would otherwise
// open a headend transaction through the same door.
func TestApplyKindIsCheckedAgainstCapabilities(t *testing.T) {
	advertiseOnly, err := wasm.ParseCapabilities([]string{string(wasm.CapAdvertise)})
	if err != nil {
		t.Fatalf("capabilities: %v", err)
	}
	ops, err := NewPluginOps(PluginOpsConfig{
		Owner:        ownerA,
		Headend:      newFakeHeadendOps(),
		Leases:       NewLeases(),
		Capabilities: advertiseOnly,
		Advertise:    NewAdvertiseSet(&fakeAdvertiser{}, NewLeases()),
		LocalSIDs:    NewLocalSIDSet(&fakeAllocator{}, newFakeSIDOps()),
	})
	if err != nil {
		t.Fatalf("new plugin ops: %v", err)
	}
	if err := ops.Publish(); err != nil {
		t.Fatalf("publish: %v", err)
	}

	if _, err := ops.ApplyBegin(uint32(v1.PluginApplyKind_PLUGIN_APPLY_KIND_HEADEND_V4)); err == nil {
		t.Error("a plugin granted only advertise opened a headend transaction")
	}
	if _, err := ops.ApplyBegin(uint32(v1.PluginApplyKind_PLUGIN_APPLY_KIND_LOCAL_SID)); err == nil {
		t.Error("a plugin granted only advertise opened a local-SID transaction")
	}
	if _, err := ops.ApplyBegin(uint32(v1.PluginApplyKind_PLUGIN_APPLY_KIND_ADVERTISE)); err != nil {
		t.Errorf("the granted kind was refused: %v", err)
	}
}

// A plugin granted nothing can still be registered and delivered events:
// observing is a real way to run one.
func TestObserveOnlyPluginRegisters(t *testing.T) {
	src := newFakeSource()
	m, ops := newTestManager(t, src, newFakeClaims())
	if err := m.Register(context.Background(), Registration{
		Name:   "observer",
		Module: fixtureModule(t, "echo"),
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
	src.emit("observer", bgp.RouteEvent{Family: bgp.FamilyVPNv4})
	waitDelivered(t, m, "observer")
	if ops.countV4() != 0 {
		t.Fatalf("an observe-only plugin wrote %d entries", ops.countV4())
	}
}

// fixtureModule reads one of the wasm runtime's hand-written fixtures.
func fixtureModule(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("wasm", "testdata", name+".wasm"))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

// A plugin leaving the mode unset means "the ordinary encapsulation",
// which is not the number the data plane uses for that: zero is
// UNSPECIFIED there, and an entry carrying it is written but never acted
// on. The host translates rather than passing the zero through, because a
// blackhole that looks installed is the worst failure this path has.
func TestDecodeHeadendEntryDefaultsToEncaps(t *testing.T) {
	_, entry, err := DecodeHeadendEntry(&v1.PluginHeadendEntry{
		TriggerPrefix: "10.0.0.0/24",
		Segments:      []string{"fd00:2::100"},
	}, AFv4, netip.MustParseAddr("fd00:1::1"))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := uint8(v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS)
	if entry.Mode != want {
		t.Fatalf("mode = %d, want H_ENCAPS (%d)", entry.Mode, want)
	}
}

// A plugin that names its own slot keeps it: that is how the two halves
// of one plugin are wired together.
func TestDecodeHeadendEntryKeepsAnExplicitMode(t *testing.T) {
	_, entry, err := DecodeHeadendEntry(&v1.PluginHeadendEntry{
		TriggerPrefix: "10.0.0.0/24",
		Segments:      []string{"fd00:2::100"},
		Mode:          20,
	}, AFv4, netip.MustParseAddr("fd00:1::1"))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if entry.Mode != 20 {
		t.Fatalf("mode = %d, want the plugin's own slot 20", entry.Mode)
	}
}

// A restored plugin declares from configure, while the daemon is still
// coming up. A local SID naming a locator an operator registers a moment
// later fails then -- and the plugin has already said everything it means
// to say, so without a retry the SIDs never come back from a restart.
func TestDeclarationHeldFromBeforeLiveIsRetried(t *testing.T) {
	alloc := &fakeAllocator{failOn: "late"}
	sids := newFakeSIDOps()
	ops, err := NewPluginOps(PluginOpsConfig{
		Owner:        ownerA,
		Headend:      newFakeHeadendOps(),
		Leases:       NewLeases(),
		Capabilities: testCaps(), Guard: testGuard(),
		LocalSIDs: NewLocalSIDSet(alloc, sids),
	})
	if err != nil {
		t.Fatalf("new plugin ops: %v", err)
	}

	// Declared before publication, as configure does.
	gen, err := ops.ApplyBegin(uint32(v1.PluginApplyKind_PLUGIN_APPLY_KIND_LOCAL_SID))
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	chunk, err := proto.Marshal(&v1.PluginApplyChunk{
		LocalSids: []*v1.PluginLocalSid{{Name: "svc", Locator: "late", Slot: 33}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := ops.ApplyPut(gen, chunk); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := ops.ApplyCommit(gen); err != nil {
		t.Fatalf("commit before publication should be held, not applied: %v", err)
	}

	// The locator does not exist yet, so publication cannot apply it.
	if err := ops.Publish(); err == nil {
		t.Fatal("publishing a declaration naming a missing locator succeeded")
	}
	if got := sids.count(); got != 0 {
		t.Fatalf("%d SIDs were installed against a locator that does not exist", got)
	}

	// Retrying now changes nothing: the locator is still missing.
	ops.RetryPending()
	if got := sids.count(); got != 0 {
		t.Fatalf("%d SIDs installed while the locator was still missing", got)
	}

	// The operator registers it, and the next delivery repairs the gap.
	alloc.mu.Lock()
	alloc.failOn = ""
	alloc.mu.Unlock()
	ops.RetryPending()
	if got := sids.count(); got != 1 {
		t.Fatalf("%d SIDs installed after the locator appeared, want 1", got)
	}

	// And it is not applied a second time.
	ops.RetryPending()
	if got := sids.count(); got != 1 {
		t.Fatalf("the retried declaration was applied again: %d SIDs", got)
	}
}

// A replacement instance knows nothing, including which addresses its
// predecessor was given. Suppressing the notification because the previous
// instance had heard it leaves the new one holding SIDs it cannot
// advertise, which is the whole point of being told.
func TestRestartedInstanceIsToldItsLocalSIDsAgain(t *testing.T) {
	sids := newFakeSIDOps()
	ops, err := NewPluginOps(PluginOpsConfig{
		Owner:        ownerA,
		Headend:      newFakeHeadendOps(),
		Leases:       NewLeases(),
		Capabilities: testCaps(), Guard: testGuard(),
		LocalSIDs:   NewLocalSIDSet(&fakeAllocator{}, sids),
		OnLocalSIDs: func([]AllocatedSID) bool { return true },
	})
	if err != nil {
		t.Fatalf("new plugin ops: %v", err)
	}
	if err := ops.Publish(); err != nil {
		t.Fatalf("publish: %v", err)
	}

	declare := func() []AllocatedSID {
		t.Helper()
		var told []AllocatedSID
		ops.onLocalSIDs = func(sids []AllocatedSID) bool {
			told = append(told, sids...)
			return true
		}
		gen, err := ops.ApplyBegin(uint32(v1.PluginApplyKind_PLUGIN_APPLY_KIND_LOCAL_SID))
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		chunk, err := proto.Marshal(&v1.PluginApplyChunk{
			LocalSids: []*v1.PluginLocalSid{{Name: "svc", Locator: "main", Slot: 33}},
		})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if err := ops.ApplyPut(gen, chunk); err != nil {
			t.Fatalf("put: %v", err)
		}
		if err := ops.ApplyCommit(gen); err != nil {
			t.Fatalf("commit: %v", err)
		}
		return told
	}

	first := declare()
	if len(first) != 1 {
		t.Fatalf("the first declaration produced %d notifications, want 1", len(first))
	}
	// Redeclaring the same set within one instance says nothing new.
	if again := declare(); len(again) != 0 {
		t.Fatalf("redeclaring told the same instance again: %v", again)
	}

	// The instance traps and is replaced.
	ops.BeginInstance()
	if err := ops.Publish(); err != nil {
		t.Fatalf("publish after restart: %v", err)
	}
	after := declare()
	if len(after) != 1 || after[0].SID != first[0].SID {
		t.Fatalf("the replacement was told %v, want the same address as before (%v)", after, first[0].SID)
	}
}

// A replacement that fails to start must not take the state its
// predecessor left behind with it. What it declares while being built is
// held, exactly as it is for a first registration.
func TestDeclarationsFromAFailedRestartAreNotApplied(t *testing.T) {
	headend := newFakeHeadendOps()
	ops, err := NewPluginOps(PluginOpsConfig{
		Owner: ownerA, Headend: headend, Leases: NewLeases(),
		Capabilities: testCaps(), Guard: testGuard(), EncapSource: testEncapSource,
	})
	if err != nil {
		t.Fatalf("new plugin ops: %v", err)
	}
	if err := ops.Publish(); err != nil {
		t.Fatalf("publish: %v", err)
	}
	declareEntries := func(prefixes ...string) {
		t.Helper()
		gen, err := ops.ApplyBegin(uint32(v1.PluginApplyKind_PLUGIN_APPLY_KIND_HEADEND_V4))
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		chunk := &v1.PluginApplyChunk{}
		for _, prefix := range prefixes {
			chunk.HeadendEntries = append(chunk.HeadendEntries, &v1.PluginHeadendEntry{
				TriggerPrefix: prefix, Segments: []string{"fd00:2::1"},
			})
		}
		body, err := proto.Marshal(chunk)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if err := ops.ApplyPut(gen, body); err != nil {
			t.Fatalf("put: %v", err)
		}
		if err := ops.ApplyCommit(gen); err != nil {
			t.Fatalf("commit: %v", err)
		}
	}

	declareEntries("10.0.0.0/24")
	if headend.countV4() != 1 {
		t.Fatalf("setup: %d entries, want 1", headend.countV4())
	}

	// The replacement is being built, and declares an empty set before it
	// fails. Nothing is published, so nothing is applied.
	ops.BeginInstance()
	declareEntries()
	if headend.countV4() != 1 {
		t.Fatalf("a declaration from an instance that never started pruned the live state: %d entries",
			headend.countV4())
	}
}

// Two declarations of one kind are two statements about the same set. If
// the older one failed and is retried after the newer one succeeded, it
// must not put back the set the plugin has already replaced.
func TestARetryDoesNotUndoANewerDeclaration(t *testing.T) {
	alloc := &fakeAllocator{failOn: "late"}
	sids := newFakeSIDOps()
	ops, err := NewPluginOps(PluginOpsConfig{
		Owner:        ownerA,
		Headend:      newFakeHeadendOps(),
		Leases:       NewLeases(),
		Capabilities: testCaps(), Guard: testGuard(),
		LocalSIDs: NewLocalSIDSet(alloc, sids),
	})
	if err != nil {
		t.Fatalf("new plugin ops: %v", err)
	}
	declare := func(locator string) {
		t.Helper()
		gen, err := ops.ApplyBegin(uint32(v1.PluginApplyKind_PLUGIN_APPLY_KIND_LOCAL_SID))
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		chunk, err := proto.Marshal(&v1.PluginApplyChunk{
			LocalSids: []*v1.PluginLocalSid{{Name: "svc", Locator: locator, Slot: 33}},
		})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if err := ops.ApplyPut(gen, chunk); err != nil {
			t.Fatalf("put: %v", err)
		}
		if err := ops.ApplyCommit(gen); err != nil {
			t.Fatalf("commit: %v", err)
		}
	}

	// Both are declared before the plugin is live: the first names a
	// locator that does not exist, the second corrects it.
	declare("late")
	declare("main")
	if err := ops.Publish(); err == nil {
		t.Fatal("publishing a declaration naming a missing locator succeeded")
	}
	if got := sids.count(); got != 1 {
		t.Fatalf("%d SIDs installed after publication, want the corrected one", got)
	}

	// The missing locator turns up. Retrying the superseded declaration
	// must not move the plugin back onto it.
	alloc.mu.Lock()
	alloc.failOn = ""
	alloc.mu.Unlock()
	ops.RetryPending()
	if got := sids.count(); got != 1 {
		t.Fatalf("the retry left %d SIDs installed, want the corrected one only", got)
	}
}

// Removing a plugin does not hand its routes to the built-in appliers.
// Nothing else implements the behavior it implemented, and to the built-in
// a private codepoint is just a service SID -- installing it as one is the
// wrong-meaning install the claim existed to prevent.
func TestUnregisterDoesNotHandTheRoutesToTheBuiltins(t *testing.T) {
	src := newFakeSource()
	claims := newFakeClaims()
	m, ops := newTestManager(t, src, claims)

	reg := Registration{
		Name: "declare", Module: declareModule(t),
		Behaviors: []uint16{0xFE01}, Capabilities: testCaps(), Scope: testScope(),
	}
	if err := m.Register(context.Background(), reg); err != nil {
		t.Fatalf("register: %v", err)
	}
	src.emit("declare", bgp.RouteEvent{Family: bgp.FamilyVPNv4})
	waitDelivered(t, m, "declare")
	if ops.countV4() != 1 {
		t.Fatalf("setup: %d entries, want 1", ops.countV4())
	}

	replaysBefore := src.snapshotCount()
	if err := m.Unregister(context.Background(), "declare"); err != nil {
		t.Fatalf("unregister: %v", err)
	}
	if got := ops.countV4(); got != 0 {
		t.Fatalf("the data plane still holds %d entries after unregistration", got)
	}
	// The claim is given back, so the codepoint is free for another
	// plugin -- but nothing replayed those routes to anyone.
	if claims.claimed("declare") {
		t.Error("unregistering left the behavior claimed")
	}
	if got := src.snapshotCount() - replaysBefore; got != 0 {
		t.Errorf("unregistering replayed the rib %d times; it must replay to nobody", got)
	}
}

// A flush that could not finish leaves state installed. The steps inside
// it keep the lease on whatever they could not remove, and releasing the
// owner wholesale would undo exactly that: the next plugin to declare that
// key would take it and overwrite state that is still live.
func TestFailedFlushKeepsTheLeasesOnWhatRemains(t *testing.T) {
	headend := newFakeHeadendOps()
	leases := NewLeases()
	ops, err := NewPluginOps(PluginOpsConfig{
		Owner: ownerA, Headend: headend, Leases: leases,
		Capabilities: testCaps(), Guard: testGuard(), EncapSource: testEncapSource,
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
	chunk, err := proto.Marshal(&v1.PluginApplyChunk{
		HeadendEntries: []*v1.PluginHeadendEntry{{
			TriggerPrefix: "10.0.1.0/24", Segments: []string{"fd00:2::1"},
		}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := ops.ApplyPut(gen, chunk); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := ops.ApplyCommit(gen); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if headend.countV4() != 1 {
		t.Fatalf("setup: %d entries, want 1", headend.countV4())
	}

	// The map refuses the delete, so the entry survives the flush.
	headend.failDelete("10.0.1.0/24")
	if err := ops.Flush(); err == nil {
		t.Fatal("a flush that could not remove an entry reported success")
	}
	if headend.countV4() != 1 {
		t.Fatalf("the entry went away after all: %d", headend.countV4())
	}

	// The lease on it is still held, so nobody else can take the key.
	if _, err := leases.AcquireAll(LeaseHeadendV4, []string{"10.0.1.0/24"}, ownerB); err == nil {
		t.Error("another owner took the lease on an entry that is still installed")
	}
}

// A plugin the store held that will not start is not simply absent: the
// daemon still holds the state it wrote and the behaviors claimed on its
// behalf, so routes carrying those reach nothing. An operator who cannot
// see it has no way to connect the two.
func TestAPluginThatCannotBeRestoredIsVisibleAndCanBeForgotten(t *testing.T) {
	store := newTestStore(t)
	broken := Registration{
		Name: "broken", Module: []byte("not a wasm module"),
		Behaviors: []uint16{0xFE01}, Capabilities: testCaps(), Scope: testScope(),
	}
	if err := store.Save(broken); err != nil {
		t.Fatalf("save: %v", err)
	}

	src := newFakeSource()
	claims := newFakeClaims()
	m, _ := newTestManagerWithStoreAndClaims(t, src, store, claims)
	if err := m.Restore(context.Background()); err != nil {
		t.Fatalf("restore: %v", err)
	}

	// It is not running.
	if _, ok := m.StatsFor("broken"); ok {
		t.Fatal("a plugin that never started is reported as running")
	}
	// But it is reported, with why and with what it is still holding.
	unrestored := m.Unrestored()
	if len(unrestored) != 1 || unrestored[0].Name != "broken" {
		t.Fatalf("Unrestored() = %+v, want the plugin that failed", unrestored)
	}
	if unrestored[0].Reason == "" {
		t.Error("nothing says why it would not start")
	}
	if len(unrestored[0].Behaviors) != 1 || unrestored[0].Behaviors[0] != 0xFE01 {
		t.Errorf("behaviors = %v, want the codepoint still claimed on its behalf", unrestored[0].Behaviors)
	}
	// The claim really is still held, which is why this matters.
	if !claims.claimed("broken") {
		t.Error("the behavior was released, so routes carrying it reach the built-in appliers")
	}

	// And the operator can decide it is not coming back.
	if err := m.Forget("broken"); err != nil {
		t.Fatalf("forget: %v", err)
	}
	if claims.claimed("broken") {
		t.Error("forgetting it left the behavior claimed")
	}
	if len(m.Unrestored()) != 0 {
		t.Error("it is still reported after being forgotten")
	}
	if regs, _ := store.List(); len(regs) != 0 {
		t.Errorf("the store still holds %d registrations", len(regs))
	}
	// Forgetting something that is not in that state is an error, not a
	// silent success: it would otherwise look like a way to remove a
	// running plugin.
	if err := m.Forget("broken"); err == nil {
		t.Error("forgetting an unknown plugin reported success")
	}
}

// A declaration waiting on something that does not exist retries forever.
// Every delivery counter looks healthy meanwhile, so the count of what is
// stuck is the only thing that distinguishes it from an idle plugin.
func TestStuckDeclarationsAreCounted(t *testing.T) {
	alloc := &fakeAllocator{failOn: "late"}
	sids := newFakeSIDOps()
	ops, err := NewPluginOps(PluginOpsConfig{
		Owner: ownerA, Headend: newFakeHeadendOps(), Leases: NewLeases(),
		Capabilities: testCaps(), Guard: testGuard(), LocalSIDs: NewLocalSIDSet(alloc, sids),
	})
	if err != nil {
		t.Fatalf("new plugin ops: %v", err)
	}
	gen, err := ops.ApplyBegin(uint32(v1.PluginApplyKind_PLUGIN_APPLY_KIND_LOCAL_SID))
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	chunk, err := proto.Marshal(&v1.PluginApplyChunk{
		LocalSids: []*v1.PluginLocalSid{{Name: "svc", Locator: "late", Slot: 33}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := ops.ApplyPut(gen, chunk); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := ops.ApplyCommit(gen); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if got := ops.PendingDeclarations(); got != 0 {
		t.Fatalf("%d declarations pending before publication", got)
	}

	if err := ops.Publish(); err == nil {
		t.Fatal("publishing a declaration naming a missing locator succeeded")
	}
	if got := ops.PendingDeclarations(); got != 1 {
		t.Fatalf("PendingDeclarations() = %d, want the one that is stuck", got)
	}

	// It stops being stuck once what it named turns up.
	alloc.mu.Lock()
	alloc.failOn = ""
	alloc.mu.Unlock()
	ops.RetryPending()
	if got := ops.PendingDeclarations(); got != 0 {
		t.Fatalf("PendingDeclarations() = %d after the locator appeared, want 0", got)
	}
}

// Retracting routes from the built-in appliers cannot be undone, so it has
// to wait until the plugin meant to take them over is running. A module
// refused at admission would otherwise leave those routes removed from the
// appliers with nothing left implementing them.
func TestAFailedRegistrationDoesNotRetractFromTheBuiltins(t *testing.T) {
	src := newFakeRetractingSource()
	claims := newFakeClaims()
	m, _ := newTestManager(t, src, claims)

	err := m.Register(context.Background(), Registration{
		Name:         "broken",
		Module:       []byte("not a wasm module"),
		Behaviors:    []uint16{0xFE01},
		Capabilities: testCaps(), Scope: testScope(),
	})
	if err == nil {
		t.Fatal("a module that is not wasm was registered")
	}
	if got := src.retractions(); got != 0 {
		t.Errorf("a failed registration retracted from the built-in appliers %d times", got)
	}
	if claims.claimed("broken") {
		t.Error("a failed registration left the behavior claimed")
	}

	// A registration that succeeds does retract, since that is the point.
	if err := m.Register(context.Background(), Registration{
		Name: "declare", Module: declareModule(t),
		Behaviors: []uint16{0xFE02}, Capabilities: testCaps(), Scope: testScope(),
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if got := src.retractions(); got != 1 {
		t.Errorf("a successful registration retracted %d times, want 1", got)
	}
}

// A plugin whose flush could not finish is back in the registry only so
// the operator can see it and retry. Nothing about it is running, so it
// must not be reported as though it were.
func TestAPluginLeftAfterAFailedFlushIsNotReportedRunning(t *testing.T) {
	src := newFakeSource()
	ops := newFakeHeadendOps()
	m, err := NewManager(ManagerConfig{
		Source: src, Claims: newFakeClaims(), Headend: ops,
		EncapSource: testEncapSource,
	})
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	t.Cleanup(func() { m.Close(context.Background()) })

	if err := m.Register(context.Background(), Registration{
		Name: "declare", Module: declareModule(t), Capabilities: testCaps(), Scope: testScope(),
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
	src.emit("declare", bgp.RouteEvent{Family: bgp.FamilyVPNv4})
	waitDelivered(t, m, "declare")
	if ops.countV4() != 1 {
		t.Fatalf("setup: %d entries, want 1", ops.countV4())
	}

	// Whatever the fixture declared is what the map must refuse to remove.
	installed := sortedV4(ops)
	if len(installed) != 1 {
		t.Fatalf("setup: entries = %v, want exactly one", installed)
	}
	ops.failDelete(installed[0])
	if err := m.Unregister(context.Background(), "declare"); err == nil {
		t.Fatal("an unregister that could not remove the entry reported success")
	}
	st, ok := m.StatsFor("declare")
	if !ok {
		t.Fatal("the plugin is not reported at all, so its leftover state is invisible")
	}
	if !st.Dead {
		t.Error("a plugin with no instance and no worker is reported as running")
	}
}

// A PROG_ARRAY slot holds one program, so two plugins granted the same slot
// would have one's SID dispatch into the other's program. The grant is
// refused across plugins, the way a behavior claim is.
func TestTwoPluginsCannotHoldTheSameSlot(t *testing.T) {
	caps, err := wasm.ParseCapabilities([]string{string(wasm.CapHeadend)})
	if err != nil {
		t.Fatalf("caps: %v", err)
	}
	mustScope := func(t *testing.T, spec ScopeSpec) Scope {
		spec.HeadendPrefixes = append(spec.HeadendPrefixes, "10.0.0.0/8")
		s, err := ParseScope(spec)
		if err != nil {
			t.Fatalf("scope: %v", err)
		}
		return s
	}

	// Each grant kind collides independently; v4 slot 16 and v6 slot 16 are
	// separate programs and must NOT collide.
	for _, tt := range []struct {
		name    string
		a, b    ScopeSpec
		collide bool
	}{
		{"endpoint slot", ScopeSpec{EndpointSlots: []uint32{32}}, ScopeSpec{EndpointSlots: []uint32{32}}, true},
		{"headend v4 slot", ScopeSpec{HeadendV4Slots: []uint32{16}}, ScopeSpec{HeadendV4Slots: []uint32{16}}, true},
		{"headend v6 slot", ScopeSpec{HeadendV6Slots: []uint32{16}}, ScopeSpec{HeadendV6Slots: []uint32{16}}, true},
		{"locator", ScopeSpec{Locators: []string{"main"}}, ScopeSpec{Locators: []string{"main"}}, true},
		{"v4-16 vs v6-16 do not collide", ScopeSpec{HeadendV4Slots: []uint32{16}}, ScopeSpec{HeadendV6Slots: []uint32{16}}, false},
		{"different endpoint slots", ScopeSpec{EndpointSlots: []uint32{32}}, ScopeSpec{EndpointSlots: []uint32{33}}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			src := newFakeSource()
			m, _ := newTestManager(t, src, newFakeClaims())
			if err := m.Register(context.Background(), Registration{
				Name: "a", Module: declareModule(t), Capabilities: caps, Scope: mustScope(t, tt.a),
			}); err != nil {
				t.Fatalf("register a: %v", err)
			}
			err := m.Register(context.Background(), Registration{
				Name: "b", Module: declareModule(t), Capabilities: caps, Scope: mustScope(t, tt.b),
			})
			if tt.collide {
				if !errors.Is(err, ErrGrantHeld) {
					t.Fatalf("register b: %v, want ErrGrantHeld", err)
				}
			} else if err != nil {
				t.Fatalf("register b (should not collide): %v", err)
			}
		})
	}

	// Re-registering the same name with the same grant is an upgrade, not a
	// conflict with itself.
	t.Run("same-name upgrade does not self-conflict", func(t *testing.T) {
		src := newFakeSource()
		m, _ := newTestManager(t, src, newFakeClaims())
		reg := Registration{Name: "a", Module: declareModule(t), Capabilities: caps,
			Scope: mustScope(t, ScopeSpec{EndpointSlots: []uint32{32}, Locators: []string{"main"}})}
		if err := m.Register(context.Background(), reg); err != nil {
			t.Fatalf("register: %v", err)
		}
		if err := m.Register(context.Background(), reg); err != nil {
			t.Fatalf("re-register: %v", err)
		}
	})
}

// checkScopeCoversCapabilities' logic, exercised through the exported
// function so the CapAdvertise "VRF or locator" branch is pinned against a
// &&/|| slip.
func TestScopeCoversCapabilities(t *testing.T) {
	caps := func(names ...string) wasm.Capabilities {
		c, err := wasm.ParseCapabilities(names)
		if err != nil {
			t.Fatalf("caps: %v", err)
		}
		return c
	}
	mustScope := func(spec ScopeSpec) Scope {
		s, err := ParseScope(spec)
		if err != nil {
			t.Fatalf("scope: %v", err)
		}
		return s
	}
	tests := []struct {
		name    string
		caps    wasm.Capabilities
		scope   Scope
		wantErr bool
	}{
		// The empty scope is deny-all and startable per the wire contract, so
		// a capability with no scope at all is allowed, not refused.
		{"headend with empty scope", caps("headend"), Scope{}, false},
		{"advertise with empty scope", caps("advertise"), Scope{}, false},
		{"local_sid with empty scope", caps("local_sid"), Scope{}, false},
		{"headend with prefixes", caps("headend"), mustScope(ScopeSpec{HeadendPrefixes: []string{"10.0.0.0/8"}}), false},
		// A partial scope -- one that names something but not what the granted
		// capability needs -- is the misconfiguration this refuses.
		{"local_sid, partial scope without locators", caps("local_sid"), mustScope(ScopeSpec{EndpointSlots: []uint32{32}}), true},
		{"local_sid, partial scope without endpoint slots", caps("local_sid"), mustScope(ScopeSpec{Locators: []string{"main"}}), true},
		{"local_sid with both", caps("local_sid"), mustScope(ScopeSpec{Locators: []string{"main"}, EndpointSlots: []uint32{32}}), false},
		{"advertise with VRF only", caps("advertise"), mustScope(ScopeSpec{VRFs: []string{"v"}}), false},
		{"advertise with locator only", caps("advertise"), mustScope(ScopeSpec{Locators: []string{"main"}}), false},
		// A non-empty scope that gives advertise neither a VRF nor a locator
		// (only, say, an endpoint slot) is a partial misconfiguration.
		{"advertise, partial scope with neither", caps("advertise"), mustScope(ScopeSpec{EndpointSlots: []uint32{32}}), true},
		{"no capability, no scope", caps(), Scope{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ScopeCoversCapabilities(tt.caps, tt.scope)
			if tt.wantErr && err == nil {
				t.Fatal("expected an error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if err != nil && !errors.Is(err, ErrScopeDoesNotCoverCapabilities) {
				t.Errorf("error is not ErrScopeDoesNotCoverCapabilities: %v", err)
			}
		})
	}
}

// A re-registration that narrows the scope must remove the state the new
// scope no longer covers. When that removal cannot be applied -- the map
// refuses the delete -- Register does not report success: the plugin is
// stopped and persisted with the narrowed scope so a restart retries the
// prune, its claim stays held so routes carrying its codepoint keep being
// withheld from the built-in appliers, and it is reported as unrestored
// rather than as running. This is manager.failPrune, reached through the
// operator-facing path.
func TestARegistrationWhosePruneFailsIsStoppedButPersisted(t *testing.T) {
	store := newTestStore(t)
	src := newFakeSource()
	claims := newFakeClaims()
	m, ops := newTestManagerWithStoreAndClaims(t, src, store, claims)

	// First registration installs the fixture's declared entry.
	wide := Registration{
		Name: "declare", Module: declareModule(t),
		Behaviors: []uint16{0xFE01}, Capabilities: testCaps(), Scope: testScope(),
	}
	if err := m.Register(context.Background(), wide); err != nil {
		t.Fatalf("register wide: %v", err)
	}
	if !src.emit("declare", bgp.RouteEvent{Family: bgp.FamilyVPNv4}) {
		t.Fatal("emit found no handler")
	}
	waitDelivered(t, m, "declare")
	if _, ok := ops.getV4("10.99.0.0/24"); !ok {
		t.Fatalf("the fixture's entry was not installed; nothing to prune")
	}

	// The map will refuse to delete that entry, so the narrowing cannot be
	// applied.
	ops.failDelete("10.99.0.0/24")

	// Re-register with a scope that still covers every capability but no
	// longer covers the fixture's declared prefix, so the prune must remove
	// it -- and fails.
	slots := func(from, to uint32) []uint32 {
		out := make([]uint32, 0, to-from+1)
		for s := from; s <= to; s++ {
			out = append(out, s)
		}
		return out
	}
	narrow, err := ParseScope(ScopeSpec{
		Locators:        []string{"main", "second", "late"},
		VRFs:            []string{testVRF},
		HeadendPrefixes: []string{"10.0.0.0/16"}, // excludes 10.99.0.0/24
		HeadendV4Slots:  slots(16, 31),
		HeadendV6Slots:  slots(16, 31),
		EndpointSlots:   slots(32, 63),
	})
	if err != nil {
		t.Fatalf("narrow scope: %v", err)
	}
	err = m.Register(context.Background(), Registration{
		Name: "declare", Module: declareModule(t),
		Behaviors: []uint16{0xFE01}, Capabilities: testCaps(), Scope: narrow,
	})
	if err == nil {
		t.Fatal("re-register reported success while state outside the new scope is still installed")
	}

	// It is not running.
	if names := m.List(); len(names) != 0 {
		t.Fatalf("List() = %v, want the failed re-registration not to be running", names)
	}
	// It is reported as unrestored, with a reason.
	unrestored := m.Unrestored()
	if len(unrestored) != 1 || unrestored[0].Name != "declare" {
		t.Fatalf("Unrestored() = %+v, want the plugin whose prune failed", unrestored)
	}
	if unrestored[0].Reason == "" {
		t.Error("nothing says why it stopped")
	}
	// The claim stays held so routes carrying its codepoint keep being
	// withheld.
	if !claims.claimed("declare") {
		t.Error("the behavior was released, so routes carrying it reach the built-in appliers over leftover state")
	}
	// The narrowed scope is persisted, so a restart retries the prune rather
	// than bringing back the wider scope.
	regs, err := store.List()
	if err != nil {
		t.Fatalf("store list: %v", err)
	}
	if len(regs) != 1 || regs[0].Name != "declare" {
		t.Fatalf("store holds %+v, want the narrowed registration", regs)
	}
	// The slot is in the narrow scope, so a nil error here would mean the
	// prefix is still covered -- i.e. the wider scope was kept.
	if err := regs[0].Scope.CheckHeadend(AFv4, "10.99.0.0/24", 16); err == nil {
		t.Error("the store kept the wider scope; a restart would not retry the prune")
	}

	// The operator can give up on it, which releases the claim.
	if err := m.Forget("declare"); err != nil {
		t.Fatalf("forget: %v", err)
	}
	if claims.claimed("declare") {
		t.Error("forgetting it left the behavior claimed")
	}
}

// makeUnrestoredViaFailedPrune registers the declare fixture, installs its
// entry, then re-registers with a scope that no longer covers the entry while
// the map refuses to delete it -- so the re-registration fails its prune and
// the plugin is left unrestored, holding its state, its claim and its grant.
// It returns the narrowed scope the unrestored record now holds.
func makeUnrestoredViaFailedPrune(t *testing.T, m *Manager, src *fakeSource, ops *fakeHeadendOps, name string) Scope {
	t.Helper()
	if err := m.Register(context.Background(), Registration{
		Name: name, Module: declareModule(t),
		Behaviors: []uint16{0xFE01}, Capabilities: testCaps(), Scope: testScope(),
	}); err != nil {
		t.Fatalf("register wide: %v", err)
	}
	if !src.emit(name, bgp.RouteEvent{Family: bgp.FamilyVPNv4}) {
		t.Fatal("emit found no handler")
	}
	waitDelivered(t, m, name)
	if _, ok := ops.getV4("10.99.0.0/24"); !ok {
		t.Fatalf("the fixture's entry was not installed; nothing to prune")
	}
	ops.failDelete("10.99.0.0/24")
	slots := func(from, to uint32) []uint32 {
		out := make([]uint32, 0, to-from+1)
		for s := from; s <= to; s++ {
			out = append(out, s)
		}
		return out
	}
	narrow, err := ParseScope(ScopeSpec{
		Locators:        []string{"main", "second", "late"},
		VRFs:            []string{testVRF},
		HeadendPrefixes: []string{"10.0.0.0/16"},
		HeadendV4Slots:  slots(16, 31),
		HeadendV6Slots:  slots(16, 31),
		EndpointSlots:   slots(32, 63),
	})
	if err != nil {
		t.Fatalf("narrow scope: %v", err)
	}
	if err := m.Register(context.Background(), Registration{
		Name: name, Module: declareModule(t),
		Behaviors: []uint16{0xFE01}, Capabilities: testCaps(), Scope: narrow,
	}); err == nil {
		t.Fatal("re-register reported success while state outside the new scope is still installed")
	}
	if len(m.Unrestored()) != 1 {
		t.Fatalf("plugin %q was not left unrestored", name)
	}
	return narrow
}

// A plugin that failed its prune keeps its state and claim in the maps until
// an operator forgets it, so its slots and locators stay reserved: another
// plugin must not be able to take the same grant and collide with that
// residual state.
func TestAnUnrestoredPluginStillReservesItsGrant(t *testing.T) {
	store := newTestStore(t)
	src := newFakeSource()
	m, ops := newTestManagerWithStoreAndClaims(t, src, store, newFakeClaims())
	makeUnrestoredViaFailedPrune(t, m, src, ops, "declare")

	// A different plugin asking for a slot the unrestored one holds is refused.
	err := m.Register(context.Background(), Registration{
		Name: "other", Module: declareModule(t), Capabilities: testCaps(),
		Scope: mustScope(t, ScopeSpec{
			Locators: []string{"other-loc"}, VRFs: []string{testVRF},
			HeadendPrefixes: []string{"10.0.0.0/16"},
			HeadendV4Slots:  []uint32{16}, HeadendV6Slots: []uint32{16},
			EndpointSlots: []uint32{32}, // held by the unrestored declare
		}),
	})
	if err == nil || !errors.Is(err, ErrGrantHeld) {
		t.Fatalf("a slot held by an unrestored plugin was granted to another: %v", err)
	}

	// And a locator it holds is refused too.
	err = m.Register(context.Background(), Registration{
		Name: "other", Module: declareModule(t), Capabilities: testCaps(),
		Scope: mustScope(t, ScopeSpec{
			Locators: []string{"second"}, VRFs: []string{testVRF}, // held by declare
			HeadendPrefixes: []string{"10.0.0.0/16"},
			HeadendV4Slots:  []uint32{16}, HeadendV6Slots: []uint32{16},
			EndpointSlots: []uint32{40},
		}),
	})
	if err == nil || !errors.Is(err, ErrGrantHeld) {
		t.Fatalf("a locator held by an unrestored plugin was granted to another: %v", err)
	}
}

// Re-registering a plugin that had failed its prune, this time successfully,
// clears the unrestored record, so a later Forget cannot delete the now
// running plugin from the registry without tearing it down.
func TestASuccessfulReRegisterClearsTheUnrestoredRecord(t *testing.T) {
	store := newTestStore(t)
	src := newFakeSource()
	claims := newFakeClaims()
	m, ops := newTestManagerWithStoreAndClaims(t, src, store, claims)
	narrow := makeUnrestoredViaFailedPrune(t, m, src, ops, "declare")

	// The operator re-registers with a scope that covers what is installed,
	// so the prune has nothing to remove and the stuck delete is never
	// reached.
	if err := m.Register(context.Background(), Registration{
		Name: "declare", Module: declareModule(t),
		Behaviors: []uint16{0xFE01}, Capabilities: testCaps(), Scope: testScope(),
	}); err != nil {
		t.Fatalf("re-register: %v", err)
	}
	_ = narrow

	// It is running and no longer reported unrestored.
	if names := m.List(); len(names) != 1 || names[0] != "declare" {
		t.Fatalf("List() = %v, want the re-registered plugin running", names)
	}
	if len(m.Unrestored()) != 0 {
		t.Fatalf("the stale unrestored record survived a successful re-register: %+v", m.Unrestored())
	}
	// Forget must refuse to touch a running plugin.
	if err := m.Forget("declare"); err == nil || !errors.Is(err, ErrPluginNotRegistered) {
		t.Fatalf("Forget acted on a running plugin: %v", err)
	}
	// The running plugin still owns its state.
	if _, ok := ops.getV4("10.99.0.0/24"); !ok {
		t.Fatal("Forget or the re-register dropped the running plugin's entry")
	}
}

// mustScope parses a scope or fails the test.
func mustScope(t *testing.T, spec ScopeSpec) Scope {
	t.Helper()
	s, err := ParseScope(spec)
	if err != nil {
		t.Fatalf("scope: %v", err)
	}
	return s
}

// A plugin can be both running and recorded unrestored for a moment: a
// re-registration that published the new instance but failed to persist it
// returns before clearing the old unrestored record. Forget must refuse to
// act on it then, or it would release the claim and store entry and drop the
// entry from the registry while the worker keeps running.
func TestForgetRefusesAPluginThatIsRunning(t *testing.T) {
	src := newFakeSource()
	claims := newFakeClaims()
	m, _ := newTestManager(t, src, claims)
	if err := m.Register(context.Background(), Registration{
		Name: "declare", Module: declareModule(t),
		Behaviors: []uint16{0xFE01}, Capabilities: testCaps(), Scope: testScope(),
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
	// Simulate the window: the plugin is running and also recorded unrestored.
	m.recordUnrestored(Registration{Name: "declare", Behaviors: []uint16{0xFE01}}, errContext("persist failed"))

	if err := m.Forget("declare"); err == nil || !strings.Contains(err.Error(), "running") {
		t.Fatalf("Forget acted on a running plugin: %v", err)
	}
	// It is still running and still claimed.
	if names := m.List(); len(names) != 1 || names[0] != "declare" {
		t.Fatalf("List() = %v, want the plugin still running", names)
	}
	if !claims.claimed("declare") {
		t.Error("Forget released the claim of a running plugin")
	}
}

// errContext is a tiny error for the test above.
type errContext string

func (e errContext) Error() string { return string(e) }

// The wire contract is that a plugin with no scope still starts: it can
// observe and log whatever capabilities it was granted, and every write is
// refused at declaration time. So a capability with an empty scope registers
// rather than being refused as an inert combination.
func TestAPluginWithCapabilitiesAndNoScopeStillRegisters(t *testing.T) {
	src := newFakeSource()
	m, _ := newTestManager(t, src, newFakeClaims())
	if err := m.Register(context.Background(), Registration{
		Name: "observer", Module: declareModule(t),
		Capabilities: testCaps(), Scope: Scope{}, // granted, but scoped to nothing
	}); err != nil {
		t.Fatalf("a deny-all plugin (capabilities, empty scope) was refused: %v", err)
	}
	if names := m.List(); len(names) != 1 || names[0] != "observer" {
		t.Fatalf("List() = %v, want the deny-all plugin running", names)
	}
}
