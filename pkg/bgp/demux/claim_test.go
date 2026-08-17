package demux

import (
	"net/netip"
	"testing"

	"github.com/takehaya/vinbero/pkg/bgp"
)

// reservedForTest stands in for the behaviors Vinbero implements: End.DT4
// and End.DT6 in RFC 8986 numbering.
var reservedForTest = []uint16{0x0013, 0x0014}

func TestClaimAssignsCodepoints(t *testing.T) {
	r := NewClaimRegistry(reservedForTest)
	if err := r.Claim("acl-prefix", []uint16{0xFE01, 0xFE02}); err != nil {
		t.Fatalf("claim: %v", err)
	}
	holder, ok := r.HolderOf(0xFE01)
	if !ok || holder != "acl-prefix" {
		t.Fatalf("HolderOf(0xFE01) = (%q, %v), want acl-prefix", holder, ok)
	}
	if !r.IsClaimed(0xFE02) {
		t.Error("0xFE02 should be claimed")
	}
	if r.IsClaimed(0xFE03) {
		t.Error("0xFE03 was never claimed")
	}
}

func TestClaimRejectsReservedCodepoint(t *testing.T) {
	r := NewClaimRegistry(reservedForTest)
	if err := r.Claim("greedy", []uint16{0x0013}); err == nil {
		t.Fatal("claiming a behavior vinbero implements must fail")
	}
	if r.IsClaimed(0x0013) {
		t.Error("a rejected claim must not take effect")
	}
}

func TestClaimRejectsConflict(t *testing.T) {
	r := NewClaimRegistry(reservedForTest)
	if err := r.Claim("first", []uint16{0xFE01}); err != nil {
		t.Fatalf("first claim: %v", err)
	}
	if err := r.Claim("second", []uint16{0xFE01}); err == nil {
		t.Fatal("a second plugin claiming the same codepoint must fail")
	}
	if holder, _ := r.HolderOf(0xFE01); holder != "first" {
		t.Errorf("holder = %q, want the original claimant", holder)
	}
}

// A claim must be all-or-nothing: a plugin that fails partway must not be
// left owning half its behaviors.
func TestClaimIsAllOrNothing(t *testing.T) {
	r := NewClaimRegistry(reservedForTest)
	if err := r.Claim("other", []uint16{0xFE02}); err != nil {
		t.Fatalf("setup claim: %v", err)
	}
	// 0xFE01 is free, 0xFE02 is taken: the whole call must fail.
	if err := r.Claim("newcomer", []uint16{0xFE01, 0xFE02}); err == nil {
		t.Fatal("a claim containing a conflict must fail")
	}
	if r.IsClaimed(0xFE01) {
		t.Error("the free codepoint was taken despite the claim failing")
	}
}

// Re-claiming the same set under the same name is what an in-place upgrade
// does, and must not be read as a conflict with itself.
func TestReclaimSameNameSucceeds(t *testing.T) {
	r := NewClaimRegistry(reservedForTest)
	if err := r.Claim("acl-prefix", []uint16{0xFE01}); err != nil {
		t.Fatalf("first claim: %v", err)
	}
	if err := r.Claim("acl-prefix", []uint16{0xFE01, 0xFE02}); err != nil {
		t.Fatalf("re-claim by the same plugin: %v", err)
	}
}

// Codepoint 0 is "this path names no behavior", so claiming it would divert
// every ordinary route away from the built-in appliers.
func TestClaimRejectsZero(t *testing.T) {
	r := NewClaimRegistry(reservedForTest)
	if err := r.Claim("acl-prefix", []uint16{0}); err == nil {
		t.Fatal("claiming codepoint 0 must fail")
	}
}

func TestReleaseFreesCodepoints(t *testing.T) {
	r := NewClaimRegistry(reservedForTest)
	if err := r.Claim("acl-prefix", []uint16{0xFE01, 0xFE02}); err != nil {
		t.Fatalf("claim: %v", err)
	}
	r.Release("acl-prefix")
	if r.IsClaimed(0xFE01) || r.IsClaimed(0xFE02) {
		t.Fatal("Release must free every codepoint the plugin held")
	}
	if err := r.Claim("successor", []uint16{0xFE01}); err != nil {
		t.Fatalf("claiming a released codepoint: %v", err)
	}
}

func TestNilRegistryClaimsNothing(t *testing.T) {
	var r *ClaimRegistry
	if r.IsClaimed(0xFE01) {
		t.Fatal("a nil registry must claim nothing")
	}
}

// A built-in consumer must not see a route whose behavior a plugin claimed:
// it would read the unrecognized codepoint as an ordinary service SID.
func TestClaimedRouteWithheldFromBuiltin(t *testing.T) {
	src := &fakeSource{}
	d := New(src, src, nil)
	claims := NewClaimRegistry(reservedForTest)
	if err := claims.Claim("acl-prefix", []uint16{0xFE01}); err != nil {
		t.Fatalf("claim: %v", err)
	}
	d.SetClaimRegistry(claims)

	var builtin, plug collector
	if _, err := d.RegisterBuiltin("applier", nil, builtin.handle); err != nil {
		t.Fatalf("register builtin: %v", err)
	}
	if _, err := d.Register("acl-prefix", nil, plug.handle); err != nil {
		t.Fatalf("register plugin: %v", err)
	}
	if err := d.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}

	claimedRoute := peerEvent(bgp.FamilyVPNv4, "192.0.2.1")
	claimedRoute.EndpointBehavior = 0xFE01
	src.emit(claimedRoute)
	if builtin.len() != 0 {
		t.Errorf("built-in consumer saw a claimed route: %d events, want 0", builtin.len())
	}
	if plug.len() != 1 {
		t.Errorf("plugin consumer missed its claimed route: %d events, want 1", plug.len())
	}

	// An unclaimed route still reaches both: the plugin may need the
	// unclaimed ones for context.
	src.emit(peerEvent(bgp.FamilyVPNv4, "192.0.2.1"))
	if builtin.len() != 1 {
		t.Errorf("built-in consumer missed an unclaimed route: %d events, want 1", builtin.len())
	}
	if plug.len() != 2 {
		t.Errorf("plugin consumer missed an unclaimed route: %d events, want 2", plug.len())
	}
}

// The snapshot replay applies the same rule, so a built-in consumer that
// registers after a claim does not pick claimed routes up from the rib.
func TestClaimedRouteWithheldFromBuiltinOnReplay(t *testing.T) {
	claimedRoute := peerEvent(bgp.FamilyVPNv4, "192.0.2.1")
	claimedRoute.EndpointBehavior = 0xFE01
	src := &fakeSource{rib: map[bgp.Family][]bgp.RouteEvent{
		bgp.FamilyVPNv4: {claimedRoute, peerEvent(bgp.FamilyVPNv4, "192.0.2.2")},
	}}
	d := New(src, src, nil)
	claims := NewClaimRegistry(reservedForTest)
	if err := claims.Claim("acl-prefix", []uint16{0xFE01}); err != nil {
		t.Fatalf("claim: %v", err)
	}
	d.SetClaimRegistry(claims)
	if err := d.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}

	var builtin collector
	if _, err := d.RegisterBuiltin("applier", []bgp.Family{bgp.FamilyVPNv4}, builtin.handle); err != nil {
		t.Fatalf("register builtin: %v", err)
	}
	if builtin.len() != 1 {
		t.Fatalf("replay delivered %d events to the built-in consumer, want 1 unclaimed", builtin.len())
	}
	if builtin.got[0].EndpointBehavior == 0xFE01 {
		t.Error("the claimed route reached the built-in consumer through the replay")
	}
}

// With no registry installed, every route reaches the built-in appliers, so
// a daemon without plugins behaves as it did before claims existed.
func TestNoRegistryDeliversEverythingToBuiltin(t *testing.T) {
	src := &fakeSource{}
	d := New(src, src, nil)
	var builtin collector
	if _, err := d.RegisterBuiltin("applier", nil, builtin.handle); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := d.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	ev := peerEvent(bgp.FamilyVPNv4, "192.0.2.1")
	ev.EndpointBehavior = 0xFE01
	src.emit(ev)
	if builtin.len() != 1 {
		t.Fatalf("got %d events, want 1", builtin.len())
	}
}

// Sanity: the address helper the other tests use produces a peer-learned
// source, so a mistake there would not silently mask the claim assertions.
func TestPeerEventIsNotLocal(t *testing.T) {
	ev := peerEvent(bgp.FamilyVPNv4, "192.0.2.1")
	if ev.Source.IsLocal() {
		t.Fatal("peerEvent produced a local-origin source")
	}
	if ev.Source.Peer != netip.MustParseAddr("192.0.2.1") {
		t.Fatalf("peer = %v, want 192.0.2.1", ev.Source.Peer)
	}
}
