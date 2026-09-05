package demux

import (
	"testing"

	"github.com/takehaya/vinbero/pkg/bgp"
)

// vpnEvent builds a VPNv4 advertise for one RD and prefix.
func vpnEvent(rd, prefix string, behavior uint16) bgp.RouteEvent {
	ev := peerEvent(bgp.FamilyVPNv4, "192.0.2.1")
	ev.EndpointBehavior = behavior
	ev.VPN = &bgp.VPNRoute{Family: bgp.FamilyVPNv4, RD: rd, Prefix: prefix}
	return ev
}

// vpnWithdraw is the withdraw of the same NLRI. It deliberately carries no
// behavior: gobgp builds a withdraw path with an empty attribute list,
// because BGP sends only the NLRI being removed.
func vpnWithdraw(rd, prefix string) bgp.RouteEvent {
	ev := peerEvent(bgp.FamilyVPNv4, "192.0.2.1")
	ev.IsWithdraw = true
	ev.VPN = &bgp.VPNRoute{Family: bgp.FamilyVPNv4, RD: rd, Prefix: prefix}
	return ev
}

func claimedDemux(t *testing.T, src *fakeSource) *Demux {
	t.Helper()
	d := New(src, src, nil)
	claims := NewClaimRegistry(reservedForTest)
	if err := claims.Claim("acl-prefix", []uint16{0xFE01}); err != nil {
		t.Fatalf("claim: %v", err)
	}
	d.SetClaimRegistry(claims)
	return d
}

// A claimed advertisement first cleans up any independently replayed state.
// The later wire withdrawal needs no further delivery to the built-in.
func TestWithdrawOfClaimedRouteWithheldFromBuiltin(t *testing.T) {
	src := &fakeSource{}
	d := claimedDemux(t, src)
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

	src.emit(vpnEvent("65000:1", "10.0.0.0/24", 0xFE01))
	src.emit(vpnWithdraw("65000:1", "10.0.0.0/24"))

	if builtin.len() != 1 || !builtin.got[0].IsWithdraw {
		t.Fatal("built-in must receive only the synthetic cleanup withdrawal")
	}
	if plug.len() != 2 {
		t.Fatalf("plugin consumer saw %d events, want the advertise and its withdraw", plug.len())
	}
}

// A withdraw for an NLRI that was never advertised under a claimed
// behavior still reaches the built-in applier, which is the ordinary case.
func TestWithdrawOfUnclaimedRouteReachesBuiltin(t *testing.T) {
	src := &fakeSource{}
	d := claimedDemux(t, src)
	var builtin collector
	if _, err := d.RegisterBuiltin("applier", nil, builtin.handle); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := d.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}

	src.emit(vpnEvent("65000:1", "10.0.0.0/24", 0x0013)) // End.DT4, not claimed
	src.emit(vpnWithdraw("65000:1", "10.0.0.0/24"))
	if builtin.len() != 2 {
		t.Fatalf("built-in consumer saw %d events, want both the advertise and the withdraw", builtin.len())
	}
}

// The ledger tracks live routes: a withdraw consumes its record, so a
// long-running daemon does not accumulate one entry per route it ever saw.
func TestLedgerReleasesOnWithdraw(t *testing.T) {
	src := &fakeSource{}
	d := claimedDemux(t, src)
	if err := d.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	src.emit(vpnEvent("65000:1", "10.0.0.0/24", 0xFE01))
	if got := d.ledger.size(); got != 1 {
		t.Fatalf("ledger holds %d entries after an advertise, want 1", got)
	}
	src.emit(vpnWithdraw("65000:1", "10.0.0.0/24"))
	if got := d.ledger.size(); got != 0 {
		t.Fatalf("ledger holds %d entries after the withdraw, want 0", got)
	}
}

// A prefix re-advertised under an unclaimed behavior must go back to the
// built-in applier, and its later withdraw must follow it there.
func TestReadvertiseUnderUnclaimedBehaviorClearsTheRecord(t *testing.T) {
	src := &fakeSource{}
	d := claimedDemux(t, src)
	var builtin collector
	if _, err := d.RegisterBuiltin("applier", nil, builtin.handle); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := d.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}

	src.emit(vpnEvent("65000:1", "10.0.0.0/24", 0xFE01)) // claimed
	src.emit(vpnEvent("65000:1", "10.0.0.0/24", 0x0013)) // now End.DT4
	src.emit(vpnWithdraw("65000:1", "10.0.0.0/24"))      // must follow the second
	if builtin.len() != 3 || !builtin.got[0].IsWithdraw || builtin.got[1].IsWithdraw || !builtin.got[2].IsWithdraw {
		t.Fatal("want synthetic cleanup followed by the ordinary advertise and withdraw")
	}
	if got := d.ledger.size(); got != 0 {
		t.Fatalf("ledger holds %d entries, want 0", got)
	}
}

// Records are per NLRI, so one prefix being claimed does not divert
// another's withdraw.
func TestLedgerDistinguishesNLRIs(t *testing.T) {
	src := &fakeSource{}
	d := claimedDemux(t, src)
	var builtin collector
	if _, err := d.RegisterBuiltin("applier", nil, builtin.handle); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := d.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}

	src.emit(vpnEvent("65000:1", "10.0.0.0/24", 0xFE01)) // claimed
	src.emit(vpnEvent("65000:1", "10.0.1.0/24", 0x0013)) // ordinary
	src.emit(vpnWithdraw("65000:1", "10.0.1.0/24"))      // ordinary, must be delivered
	src.emit(vpnWithdraw("65000:1", "10.0.0.0/24"))      // claimed, must be withheld

	if builtin.len() != 3 || !builtin.got[0].IsWithdraw {
		t.Fatal("want synthetic cleanup followed by the ordinary advertise and withdraw")
	}
	for _, ev := range builtin.got[1:] {
		if ev.VPN.Prefix != "10.0.1.0/24" {
			t.Fatalf("built-in consumer saw the claimed prefix: %+v", ev.VPN)
		}
	}
}

// The same RD and prefix under different families are different NLRIs.
func TestNLRIKeyDistinguishesFamilies(t *testing.T) {
	v4 := vpnEvent("65000:1", "10.0.0.0/24", 0xFE01)
	v6 := v4
	v6.Family = bgp.FamilyVPNv6
	v6.VPN = &bgp.VPNRoute{Family: bgp.FamilyVPNv6, RD: "65000:1", Prefix: "10.0.0.0/24"}
	if nlriKey(v4) == nlriKey(v6) {
		t.Fatal("two families produced the same NLRI key")
	}
}

// An event carrying no decoded route yields no key, and the caller then
// falls back to the behavior on the event itself.
func TestNLRIKeyEmptyForUndecodedEvent(t *testing.T) {
	if got := nlriKey(peerEvent(bgp.FamilyVPNv4, "192.0.2.1")); got != "" {
		t.Fatalf("nlriKey = %q, want empty", got)
	}
}

// An on-demand snapshot fed to a built-in consumer applies the same claim
// rule as live delivery; without this the applier's EVPN rescue would pick
// up exactly the routes dispatch withheld from it.
func TestBuiltinSnapshotHandlerFiltersClaimed(t *testing.T) {
	src := &fakeSource{}
	d := claimedDemux(t, src)
	var got collector
	h := d.BuiltinSnapshotHandler(got.handle)

	h(vpnEvent("65000:1", "10.0.0.0/24", 0xFE01)) // claimed
	h(vpnEvent("65000:1", "10.0.1.0/24", 0x0013)) // ordinary
	h(localEvent(bgp.FamilyEVPN))                 // this node's own advertisement

	if got.len() != 1 {
		t.Fatalf("snapshot delivered %d events, want only the ordinary one", got.len())
	}
	if got.got[0].VPN.Prefix != "10.0.1.0/24" {
		t.Fatalf("snapshot delivered %+v, want the unclaimed prefix", got.got[0].VPN)
	}
}

func TestBuiltinSnapshotHandlerNilSafe(t *testing.T) {
	var d *Demux
	var got collector
	h := d.BuiltinSnapshotHandler(got.handle)
	h(vpnEvent("65000:1", "10.0.0.0/24", 0xFE01))
	if got.len() != 1 {
		t.Fatal("a nil demux must pass events through unchanged")
	}
	if d.BuiltinSnapshotHandler(nil) != nil {
		t.Fatal("wrapping a nil handler should stay nil")
	}
}

// A registry that does not exist (a daemon started without BGP) must
// refuse a claim rather than panic on the nil receiver.
func TestNilRegistryMutatorsAreSafe(t *testing.T) {
	var r *ClaimRegistry
	if err := r.Claim("acl-prefix", []uint16{0xFE01}); err == nil {
		t.Fatal("claiming against a nil registry should fail")
	}
	r.Release("acl-prefix") // must not panic
	if got := r.Claims("acl-prefix"); got != nil {
		t.Fatalf("Claims on a nil registry = %v, want nil", got)
	}
}

// vpnEventFrom is an advertise of one NLRI by a named peer, so a test can
// build the several paths a route reflector pair produces.
func vpnEventFrom(peer, rd, prefix string, behavior uint16) bgp.RouteEvent {
	ev := peerEvent(bgp.FamilyVPNv4, peer)
	ev.EndpointBehavior = behavior
	ev.VPN = &bgp.VPNRoute{Family: bgp.FamilyVPNv4, RD: rd, Prefix: prefix}
	return ev
}

// vpnWithdrawFrom is that peer's withdraw of the same NLRI.
func vpnWithdrawFrom(peer, rd, prefix string) bgp.RouteEvent {
	ev := peerEvent(bgp.FamilyVPNv4, peer)
	ev.IsWithdraw = true
	ev.VPN = &bgp.VPNRoute{Family: bgp.FamilyVPNv4, RD: rd, Prefix: prefix}
	return ev
}

// One NLRI advertised by two route reflectors is withdrawn twice. The
// first withdraw must not consume the claim for the second: that second
// withdraw carries no attributes either, and letting it through would hand
// the built-in applier a delete for state it never installed.
func TestLedgerTracksEachPathSeparately(t *testing.T) {
	src := &fakeSource{}
	d := claimedDemux(t, src)
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

	src.emit(vpnEventFrom("192.0.2.1", "65000:1", "10.0.0.0/24", 0xFE01))
	src.emit(vpnEventFrom("192.0.2.2", "65000:1", "10.0.0.0/24", 0xFE01))
	// One NLRI, so one ledger key, holding two paths.
	if got := d.ledger.size(); got != 1 {
		t.Fatalf("ledger holds %d NLRIs, want 1", got)
	}

	src.emit(vpnWithdrawFrom("192.0.2.1", "65000:1", "10.0.0.0/24"))
	if got := d.ledger.size(); got != 1 {
		t.Fatalf("the first withdraw dropped the NLRI while another peer still advertises it")
	}
	src.emit(vpnWithdrawFrom("192.0.2.2", "65000:1", "10.0.0.0/24"))
	if got := d.ledger.size(); got != 0 {
		t.Fatalf("ledger holds %d NLRIs after the last withdraw, want 0", got)
	}

	if builtin.len() != 2 || !builtin.got[0].IsWithdraw || !builtin.got[1].IsWithdraw {
		t.Fatal("built-in must receive only synthetic cleanup for the two paths")
	}
	if plug.len() != 4 {
		t.Fatalf("plugin consumer saw %d events, want both advertises and both withdraws", plug.len())
	}
}
