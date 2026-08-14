package cplane

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/bpf"
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
type fakeSource struct {
	mu       sync.Mutex
	handlers map[string]bgp.RouteHandler
	families map[string][]bgp.Family
	regErr   error
	cancels  int
}

func newFakeSource() *fakeSource {
	return &fakeSource{
		handlers: map[string]bgp.RouteHandler{},
		families: map[string][]bgp.Family{},
	}
}

func (f *fakeSource) Register(name string, families []bgp.Family, h bgp.RouteHandler) (func(), error) {
	if f.regErr != nil {
		return nil, f.regErr
	}
	f.mu.Lock()
	f.handlers[name] = h
	f.families[name] = families
	f.mu.Unlock()
	return func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.cancels++
		delete(f.handlers, name)
	}, nil
}

func (f *fakeSource) emit(name string, ev bgp.RouteEvent) bool {
	f.mu.Lock()
	h := f.handlers[name]
	f.mu.Unlock()
	if h == nil {
		return false
	}
	h(ev)
	return true
}

func (f *fakeSource) registered(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.handlers[name]
	return ok
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

func (c *fakeClaims) Claim(plugin string, codepoints []uint16) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.claimErr != nil {
		return c.claimErr
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

func (c *fakeClaims) holds(plugin string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.held[plugin]
	return ok
}

func newTestManager(t *testing.T, src EventSource, claims BehaviorClaims) (*Manager, *fakeHeadendOps) {
	t.Helper()
	ops := newFakeHeadendOps()
	m, err := NewManager(ManagerConfig{
		Source:             src,
		Claims:             claims,
		Headend:            ops,
		DefaultEncapSource: netip.MustParseAddr("fd00:1::1"),
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
	reg := Registration{Name: "declare", Module: declareModule(t)}
	if err := m.Register(context.Background(), reg); err != nil {
		t.Fatalf("register: %v", err)
	}
	if !src.registered("declare") {
		t.Fatal("the plugin did not subscribe to the event source")
	}

	if !src.emit("declare", bgp.RouteEvent{Family: bgp.FamilyVPNv4}) {
		t.Fatal("emit found no handler")
	}
	// The fixture declares one headend entry per event it sees.
	if len(ops.v4) != 1 {
		t.Fatalf("data plane holds %d entries, want the one the plugin declared", len(ops.v4))
	}
	for prefix, entry := range ops.v4 {
		if prefix != "10.99.0.0/24" {
			t.Errorf("declared prefix = %q, want 10.99.0.0/24", prefix)
		}
		if entry.NumSegments != 1 {
			t.Errorf("declared %d segments, want 1", entry.NumSegments)
		}
	}
	// Everything the plugin wrote carries its own owner tag.
	want := bpf.OwnerPluginBundle("declare")
	for prefix, owner := range ops.owner4 {
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
	reg := Registration{Name: "declare", Module: declareModule(t), Behaviors: []uint16{0xFE01}}
	if err := m.Register(context.Background(), reg); err != nil {
		t.Fatalf("register: %v", err)
	}
	src.emit("declare", bgp.RouteEvent{Family: bgp.FamilyVPNv4})
	if len(ops.v4) != 1 {
		t.Fatalf("setup: data plane holds %d entries, want 1", len(ops.v4))
	}

	if err := m.Unregister(context.Background(), "declare"); err != nil {
		t.Fatalf("unregister: %v", err)
	}
	if len(ops.v4) != 0 {
		t.Fatalf("unregister left %d entries behind", len(ops.v4))
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
	reg := Registration{Name: "declare", Module: declareModule(t)}
	if err := m.Register(context.Background(), reg); err != nil {
		t.Fatalf("first register: %v", err)
	}
	src.emit("declare", bgp.RouteEvent{Family: bgp.FamilyVPNv4})
	if len(ops.v4) != 1 {
		t.Fatalf("setup: data plane holds %d entries, want 1", len(ops.v4))
	}

	if err := m.Register(context.Background(), reg); err != nil {
		t.Fatalf("re-register: %v", err)
	}
	if len(ops.v4) != 1 {
		t.Fatalf("the upgrade disturbed the data plane: %d entries", len(ops.v4))
	}
	if names := m.List(); len(names) != 1 {
		t.Fatalf("manager lists %v, want one plugin", names)
	}
	// The replacement is the instance receiving events now.
	src.emit("declare", bgp.RouteEvent{Family: bgp.FamilyVPNv4})
	if len(ops.v4) != 1 {
		t.Fatalf("after the upgrade the plugin declared %d entries, want its usual 1", len(ops.v4))
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
		Name:      "declare",
		Module:    declareModule(t),
		Behaviors: []uint16{0xFE01},
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
		if err := m.Register(context.Background(), Registration{Name: name, Module: declareModule(t)}); err == nil {
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
		Name:      "declare",
		Module:    declareModule(t),
		Behaviors: []uint16{0xFE01},
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
	if err := m.Register(context.Background(), Registration{Name: "declare", Module: declareModule(t)}); err != nil {
		t.Fatalf("register: %v", err)
	}
	src.emit("declare", bgp.RouteEvent{Family: bgp.FamilyVPNv4})
	if len(ops.v4) != 1 {
		t.Fatalf("setup: %d entries, want 1", len(ops.v4))
	}

	m.Close(context.Background())
	if len(ops.v4) != 1 {
		t.Fatalf("close flushed the data plane: %d entries left", len(ops.v4))
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
	prefix, entry, err := DecodeHeadendEntry(in, defaultSrc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if prefix != "10.0.0.0/24" {
		t.Errorf("prefix = %q", prefix)
	}
	if entry.NumSegments != 2 {
		t.Errorf("segments = %d, want 2", entry.NumSegments)
	}
	// The last segment is where the packet is actually sent.
	if got := netip.AddrFrom16(entry.DstAddr); got != netip.MustParseAddr("fd00:3::100") {
		t.Errorf("destination = %v, want the last segment", got)
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
			if _, _, err := DecodeHeadendEntry(tt.in, src); err == nil {
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
	if _, _, err := DecodeHeadendEntry(in, netip.MustParseAddr("fd00:1::1")); err == nil {
		t.Fatal("a segment list longer than the map holds was accepted")
	}
}

func TestPluginOpsTransactionLifecycle(t *testing.T) {
	headend := newFakeHeadendOps()
	ops, err := NewPluginOps(PluginOpsConfig{
		Owner:              ownerA,
		Headend:            headend,
		Leases:             NewLeases(),
		DefaultEncapSource: netip.MustParseAddr("fd00:1::1"),
	})
	if err != nil {
		t.Fatalf("new plugin ops: %v", err)
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
	if len(headend.v4) != 0 {
		t.Fatalf("a chunk was applied before commit: %d entries", len(headend.v4))
	}
	if err := ops.ApplyCommit(gen); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if len(headend.v4) != 1 {
		t.Fatalf("commit applied %d entries, want 1", len(headend.v4))
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
	ops, err := NewPluginOps(PluginOpsConfig{Owner: ownerA, Headend: headend, Leases: NewLeases()})
	if err != nil {
		t.Fatalf("new plugin ops: %v", err)
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
	if len(headend.v4) != 0 {
		t.Errorf("an aborted transaction reached the data plane: %d entries", len(headend.v4))
	}
}

// A plugin that opens transactions and never finishes them must not be
// able to grow the host without bound.
func TestPluginOpsBoundsOpenTransactions(t *testing.T) {
	ops, err := NewPluginOps(PluginOpsConfig{
		Owner: ownerA, Headend: newFakeHeadendOps(), Leases: NewLeases(),
		MaxOpenTransactions: 2,
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
	ops, err := NewPluginOps(PluginOpsConfig{Owner: ownerA, Headend: newFakeHeadendOps(), Leases: NewLeases()})
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
	ops, err := NewPluginOps(PluginOpsConfig{Owner: ownerA, Headend: headend, Leases: leases})
	if err != nil {
		t.Fatalf("new plugin ops: %v", err)
	}
	if _, err := ApplyHeadendSet(headend, leases, ownerA, AFv4, desire("10.0.1.0/24")); err != nil {
		t.Fatalf("seed: %v", err)
	}
	headend.seedV4("10.9.9.0/24", ownerB)

	if err := ops.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if _, ok := headend.v4["10.0.1.0/24"]; ok {
		t.Error("flush left the plugin's own entry behind")
	}
	if _, ok := headend.v4["10.9.9.0/24"]; !ok {
		t.Error("flush removed another owner's entry")
	}
}
