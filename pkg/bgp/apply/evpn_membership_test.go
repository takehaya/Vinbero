package apply

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/takehaya/vinbero/pkg/bgp"
)

func esPath(rd, peer string, pathID uint32) bgp.RouteEvent {
	r := rt4(testESI, "fd00:2::")
	r.RD, r.IPAddr = rd, "fd00:2::"
	return bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: r, Source: bgp.PathSource{Peer: netip.MustParseAddr(peer), PathID: pathID}}
}

func TestEVPNMembershipPathReferences(t *testing.T) {
	a, f := evpnApplier(t)
	seedLocalEsi(f, testESI, "fd00:3::")
	paths := []bgp.RouteEvent{
		esPath("65000:1", "192.0.2.1", 1),
		esPath("65000:2", "192.0.2.1", 1),
		esPath("65000:1", "192.0.2.2", 1),
		esPath("65000:1", "192.0.2.1", 2),
	}
	for _, ev := range paths {
		a.Apply(ev)
		a.Apply(ev) // duplicate update is not an extra reference
	}
	if len(f.esPeers) != 1 || f.esPeerCreates != 1 || dfAddr(f, testESI) != "fd00:2::" {
		t.Fatalf("membership not coalesced: peers=%v creates=%d", f.esPeers, f.esPeerCreates)
	}
	if err := a.ReplayEVPN(func(h bgp.RouteHandler) error {
		for _, ev := range paths {
			h(ev)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for i, ev := range paths {
		ev.IsWithdraw = true
		ev.EVPN.NextHop = "" // withdrawal identity does not need MP_REACH
		a.Apply(ev)
		a.Apply(ev)
		want := 1
		if i == len(paths)-1 {
			want = 0
		}
		if len(f.esPeers) != want {
			t.Fatalf("withdraw %d removed another path: %v", i, f.esPeers)
		}
	}
	if f.esPeerDeletes != 1 || len(a.evpn.esPaths) != 0 || len(a.evpn.esRefs) != 0 || dfAddr(f, testESI) != "fd00:3::" {
		t.Fatalf("last reference leaked: paths=%v refs=%v deletes=%d", a.evpn.esPaths, a.evpn.esRefs, f.esPeerDeletes)
	}
}

func TestEVPNMembershipNextHopReplacementAndInvalidation(t *testing.T) {
	a, f := evpnApplier(t)
	seedLocalEsi(f, testESI, "fd00:9::")
	ev := esPath("65000:1", "192.0.2.1", 1)
	ev.BGPPath = &bgp.EncodedBGPPath{RouteKey: []byte("stable RT4 NLRI")}
	a.Apply(ev)
	ev.EVPN.NextHop = "fd00:4::"
	a.Apply(ev)
	key := esPeerKey{esi: testESI, source: netip.MustParseAddr("fd00:4::").As16()}
	if _, ok := f.esPeers[key]; !ok || len(f.esPeers) != 1 || dfAddr(f, testESI) != "fd00:4::" {
		t.Fatalf("next-hop replacement retained old member: %v", f.esPeers)
	}
	ev.EVPN.NextHop = "::ffff:192.0.2.1"
	a.Apply(ev)
	if len(f.esPeers) != 0 || len(a.evpn.esPaths) != 0 || dfAddr(f, testESI) != "fd00:9::" {
		t.Fatalf("invalid replacement retained membership: %v", f.esPeers)
	}
	for _, invalid := range []string{"::", "ff02::1", "fe80::1%eth0", "not-an-ip"} {
		ev.EVPN.NextHop = invalid
		a.Apply(ev)
	}
	if len(f.esPeers) != 0 {
		t.Fatal("invalid member installed")
	}
}

func TestEVPNMembershipMapFailuresRetry(t *testing.T) {
	a, f := evpnApplier(t)
	ev := esPath("65000:1", "192.0.2.1", 1)
	f.esPeerCreateErr = errors.New("map full")
	a.Apply(ev)
	if len(a.evpn.esRefs) != 1 || len(a.evpn.esApplied) != 0 || len(f.esPeers) != 0 {
		t.Fatal("failed create reported applied")
	}
	f.esPeerCreateErr = nil
	a.Apply(ev)
	if len(f.esPeers) != 1 || f.esPeerCreates != 2 {
		t.Fatal("duplicate did not retry create")
	}
	f.esPeerDeleteErr = errors.New("delete failed")
	ev.IsWithdraw = true
	a.Apply(ev)
	if len(a.evpn.esRefs) != 0 || len(a.evpn.esApplied) != 1 || len(f.esPeers) != 1 {
		t.Fatal("failed delete lost retry state")
	}
	f.esPeerDeleteErr = nil
	if err := a.ReplayEVPN(func(bgp.RouteHandler) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if len(f.esPeers) != 0 || len(a.evpn.esApplied) != 0 {
		t.Fatal("empty replay did not retry delete")
	}
	f.esPeerCreateErr = errors.New("temporary")
	ev.IsWithdraw = false
	a.Apply(ev)
	f.esPeerCreateErr = nil
	a.ReelectDF(testESI)
	if len(f.esPeers) != 1 {
		t.Fatal("ReelectDF did not retry")
	}
}

func TestEVPNMembershipIndependentOfMAC(t *testing.T) {
	a, f := evpnApplier(t)
	ev := esPath("65000:1", "192.0.2.1", 1)
	a.Apply(ev) // no local attachment yet: no invented local ES/DF
	if len(f.esPeers) != 1 || len(f.esis) != 0 {
		t.Fatal("RT4 must only populate independent membership")
	}
	mac := &bgp.EVPNRoute{Type: bgp.EVPNRouteTypeMACIP, RD: "65000:1", MAC: "02:00:00:00:00:01", ESI: testESI}
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: mac, IsWithdraw: true})
	if len(f.esPeers) != 1 {
		t.Fatal("RT2 withdraw changed RT4 membership")
	}
	seedLocalEsi(f, testESI, "fd00:3::")
	a.ReelectDF(testESI)
	if dfAddr(f, testESI) != "fd00:2::" {
		t.Fatal("late attach lost membership")
	}
}

func TestEVPNMembershipPathLimit(t *testing.T) {
	a, f := evpnApplier(t)
	// Populate only the bounded path ledger, avoiding an O(limit²) sequence
	// of map synchronizations in this admission-boundary test.
	peer := esPeerKey{esi: testESI, source: netip.MustParseAddr("fd00:2::").As16()}
	for i := 0; i < maxESPaths; i++ {
		ev := esPath("65000:1", "192.0.2.1", uint32(i))
		a.evpn.esPaths[esRouteKey(ev)] = peer
	}
	a.evpn.esRefs[peer] = maxESPaths
	a.evpn.esMembers[testESI] = map[string]struct{}{"fd00:2::": {}}
	a.Apply(esPath("65000:1", "192.0.2.1", maxESPaths))
	if len(a.evpn.esPaths) != maxESPaths || a.evpn.esRefs[peer] != maxESPaths || len(f.esPeers) != 1 {
		t.Fatal("duplicate-member paths bypassed path quota")
	}
	// Existing paths remain replaceable at the limit.
	ev := esPath("65000:1", "192.0.2.1", 0)
	ev.EVPN.NextHop = "fd00:4::"
	a.Apply(ev)
	if len(a.evpn.esPaths) != maxESPaths || len(f.esPeers) != 2 {
		t.Fatal("replacement blocked at quota")
	}
}
