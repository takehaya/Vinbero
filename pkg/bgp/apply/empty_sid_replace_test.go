package apply

import (
	"testing"

	"go.uber.org/zap"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/vrfbgp"
)

// A BGP UPDATE is an implicit replace. These tests pin that rule for the
// MUP and EVPN appliers: a re-advertisement of a tracked NLRI whose SID
// became unusable (empty -- e.g. it failed RFC 9252 Sec.7 validation on
// decode) or whose RTs no longer match must tear the previous state down,
// exactly like a withdraw, instead of leaving it forwarding.

func TestApplyMUP_ISDUnusableSIDUpdateReplaces(t *testing.T) {
	const (
		rd   = "65100:1"
		ue   = "10.1.0.1/32"
		isdP = "172.16.0.0/24"
		isid = "fd00:a:0:1::"
	)
	// "" is the decoder's no-SID rendering; "::" is what an all-zero SID
	// decodes to; loopback, link-local, and multicast are parseable but
	// unreachable from a remote PE -- all must tear down, not black-hole.
	for _, badSID := range []string{"", "::", "::1", "fe80::1", "ff02::1"} {
		t.Run("sid="+badSID, func(t *testing.T) {
			fh := newFakeHeadend()
			a := newMUPApplier(t, fh)
			a.Apply(mupISD(rd, isdP, isid))
			a.Apply(mupT1ST(rd, ue, "172.16.0.1", 256, 9, ""))
			assertT1STBase(t, fh, ue, isid)

			a.Apply(mupISD(rd, isdP, badSID)) // same key, SID became unusable
			if len(fh.v4deleted) != 1 || fh.v4deleted[0] != ue {
				t.Errorf("unusable-SID ISD update did not tear down the resolved T1ST; deleted=%v", fh.v4deleted)
			}
			if len(a.mupISD) != 0 {
				t.Errorf("stale ISD entry survived the unusable-SID update: %v", a.mupISD)
			}
		})
	}
}

// An unusable advertisement for a key that was never tracked must return
// before the reconcile-all sweep: a flood of them is not allowed to drive
// repeated whole-table reconciliation.
func TestApplyMUP_ISDUnusableSIDUntrackedNoop(t *testing.T) {
	fh := newFakeHeadend()
	a := newMUPApplier(t, fh)
	a.Apply(mupISD("65100:1", "172.16.0.0/24", "fd00:a:0:1::"))
	a.Apply(mupT1ST("65100:1", "10.1.0.1/32", "172.16.0.1", 256, 9, ""))
	a.Apply(mupISD("65100:1", "172.17.0.0/24", "")) // different, untracked key
	if len(fh.v4deleted) != 0 {
		t.Errorf("untracked unusable ISD tore down an unrelated session; deleted=%v", fh.v4deleted)
	}
	if len(a.mupISD) != 1 {
		t.Errorf("tracked ISD count = %d, want 1", len(a.mupISD))
	}
}

// A session route (T1ST) whose re-advertisement stops matching any MUP
// import RT is dispatched as a withdraw: the installed downlink must not
// survive it.
func TestApplyMUP_T1STRTMismatchUpdateReplaces(t *testing.T) {
	const (
		rd   = "65100:1"
		ue   = "10.1.0.1/32"
		isdP = "172.16.0.0/24"
		isid = "fd00:a:0:1::"
	)
	fh := newFakeHeadend()
	vm := vrfbgp.NewManager()
	if err := vm.Bind(vrfbgp.Binding{VRFName: "vrf-mup", Families: map[bgp.Family]vrfbgp.FamilyPolicy{
		bgp.FamilyMUPIPv4: {RouteTargets: []vrfbgp.RouteTarget{{RT: testRTInterwork, Direction: vrfbgp.DirectionImport}}},
	}}); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	a := NewApplier(fh, testLocatorManager(t), vm, &fakeFib{}, "LOC1", 65000, zap.NewNop())
	a.Apply(mupISD(rd, isdP, isid))
	a.Apply(mupT1ST(rd, ue, "172.16.0.1", 256, 9, ""))
	assertT1STBase(t, fh, ue, isid)

	replaced := mupT1ST(rd, ue, "172.16.0.1", 256, 9, "")
	replaced.MUP.RTs = []string{"100:9999"}
	a.Apply(replaced)
	if len(fh.v4deleted) != 1 || fh.v4deleted[0] != ue {
		t.Errorf("RT-mismatch T1ST update left the downlink installed; deleted=%v", fh.v4deleted)
	}
}

func TestApplyMUP_DSDUnusableSIDUpdateReplaces(t *testing.T) {
	const (
		rd       = "65100:1"
		endpoint = "192.0.2.100"
		dsdAddr  = "10.0.0.1"
	)
	fh := newFakeHeadend()
	a := newMUPApplier(t, fh)
	a.Apply(mupDSD(rd, dsdAddr, 1, 2, "fd00:d:0:1::"))
	a.Apply(mupT2ST(rd, endpoint, 0x100, 32, 1, 2, ""))
	if _, ok := fh.mupUplink[mupUplinkKey{0, endpoint, 0x100, 32}]; !ok {
		t.Fatal("uplink was not installed via the DSD")
	}

	a.Apply(mupDSD(rd, dsdAddr, 1, 2, "::")) // same key, SID became unusable
	if _, ok := fh.mupUplink[mupUplinkKey{0, endpoint, 0x100, 32}]; ok {
		t.Error("empty-SID DSD update left the resolved uplink installed")
	}
	if len(a.mupDSD) != 0 {
		t.Errorf("stale DSD entry survived the empty-SID update: %v", a.mupDSD)
	}
}

// Same untracked-key rule for DSD: an unusable advertisement for a key
// never tracked must neither touch existing discoveries nor drive the
// reconcile sweep's teardown of resolved uplinks.
func TestApplyMUP_DSDUnusableSIDUntrackedNoop(t *testing.T) {
	const endpoint = "192.0.2.100"
	fh := newFakeHeadend()
	a := newMUPApplier(t, fh)
	a.Apply(mupDSD("65100:1", "10.0.0.1", 1, 2, "fd00:d:0:1::"))
	a.Apply(mupT2ST("65100:1", endpoint, 0x100, 32, 1, 2, ""))
	if _, ok := fh.mupUplink[mupUplinkKey{0, endpoint, 0x100, 32}]; !ok {
		t.Fatal("uplink was not installed")
	}

	a.Apply(mupDSD("65100:1", "10.0.0.2", 1, 2, "::")) // different, untracked key
	if _, ok := fh.mupUplink[mupUplinkKey{0, endpoint, 0x100, 32}]; !ok {
		t.Error("untracked unusable DSD tore down an unrelated uplink")
	}
	if len(a.mupDSD) != 1 {
		t.Errorf("tracked DSD count = %d, want 1", len(a.mupDSD))
	}
}

func TestApplier_EVPNRT2UnusableUpdateReplaces(t *testing.T) {
	const mac = "aa:bb:cc:00:00:01"
	cases := []struct {
		name   string
		mutate func(*bgp.EVPNRoute)
	}{
		{"empty SID", func(r *bgp.EVPNRoute) { r.SRv6SID = "" }},
		{"unusable SID", func(r *bgp.EVPNRoute) { r.SRv6SID = "::" }},
		{"RTs match no binding", func(r *bgp.EVPNRoute) { r.RTs = []string{"65000:999"} }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, fh := evpnApplier(t)
			a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: rt2(mac, "fd00:2:2:d2::")})
			if _, ok := fh.fdb[fdbKey{100, mac}]; !ok {
				t.Fatal("RT2 was not installed")
			}

			replaced := rt2(mac, "fd00:2:2:d2::")
			c.mutate(replaced)
			a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: replaced})
			if _, ok := fh.fdb[fdbKey{100, mac}]; ok {
				t.Error("unusable RT2 update left the FDB entry installed")
			}
			if len(fh.bdPeers) != 0 {
				t.Errorf("unusable RT2 update left a bd_peer installed: %v", fh.bdPeers)
			}
		})
	}
}

func TestApplier_EVPNRT3UnusableUpdateReplaces(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*bgp.EVPNRoute)
	}{
		{"empty SID", func(r *bgp.EVPNRoute) { r.SRv6SID = "" }},
		{"unusable SID", func(r *bgp.EVPNRoute) { r.SRv6SID = "::" }},
		{"RTs match no binding", func(r *bgp.EVPNRoute) { r.RTs = []string{"65000:999"} }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, fh := evpnApplier(t)
			a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: rt3("fd00:2:2:24::")})
			if len(fh.bdPeers) != 1 {
				t.Fatal("RT3 was not installed")
			}

			replaced := rt3("fd00:2:2:24::")
			c.mutate(replaced)
			a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: replaced})
			if len(fh.bdPeers) != 0 {
				t.Errorf("unusable RT3 update left the flood bd_peer installed: %v", fh.bdPeers)
			}
		})
	}
}

// An unusable claim from a DIFFERENT PE (next hop) must not clear the
// entry the original PE's route still backs -- teardown is confined to
// the PE that taught us the state.
func TestApplier_EVPNRT2UnusableFromOtherPEKeepsEntry(t *testing.T) {
	const mac = "aa:bb:cc:00:00:01"
	a, fh := evpnApplier(t)
	installed := rt2(mac, "fd00:2:2:d2::")
	installed.NextHop = "2001:db8::a"
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: installed})
	if _, ok := fh.fdb[fdbKey{100, mac}]; !ok {
		t.Fatal("RT2 was not installed")
	}

	other := rt2(mac, "")
	other.NextHop = "2001:db8::b"
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: other})
	if _, ok := fh.fdb[fdbKey{100, mac}]; !ok {
		t.Error("unusable claim from another PE cleared the tracked entry")
	}
}

// A next-hop move with an unchanged SID refreshes the RT3 ledger's PE, so
// a later unusable UPDATE from the current PE still tears the flood peer
// down.
func TestApplier_EVPNRT3NextHopMoveThenUnusableReplaces(t *testing.T) {
	a, fh := evpnApplier(t)
	first := rt3("fd00:2:2:24::")
	first.NextHop = "2001:db8::a"
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: first})
	moved := rt3("fd00:2:2:24::")
	moved.NextHop = "2001:db8::b"
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: moved})
	if len(fh.bdPeers) != 1 {
		t.Fatalf("flood peer count = %d, want 1", len(fh.bdPeers))
	}

	bad := rt3("")
	bad.NextHop = "2001:db8::b"
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: bad})
	if len(fh.bdPeers) != 0 {
		t.Errorf("unusable UPDATE from the current PE left the flood peer installed: %v", fh.bdPeers)
	}
}

// A T2ST whose re-advertisement stops matching the MUP import filter is
// dispatched as a withdraw: the uplink F-TEID entry and its endpoint gate
// (its only referencing session) must both go.
func TestApplyMUP_T2STRTMismatchUpdateReplaces(t *testing.T) {
	const endpoint = "192.0.2.100"
	fh := newFakeHeadend()
	vm := vrfbgp.NewManager()
	if err := vm.Bind(vrfbgp.Binding{VRFName: "vrf-mup", Families: map[bgp.Family]vrfbgp.FamilyPolicy{
		bgp.FamilyMUPIPv4: {RouteTargets: []vrfbgp.RouteTarget{{RT: testRTDirect, Direction: vrfbgp.DirectionImport}}},
	}}); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	a := NewApplier(fh, testLocatorManager(t), vm, &fakeFib{}, "LOC1", 65000, zap.NewNop())
	// The uplink installs under the vrf_id of the binding that imported it,
	// so match on {endpoint, teid} across instances.
	uplinks := func() int {
		n := 0
		for k := range fh.mupUplink {
			if k.endpoint == endpoint && k.teid == 0x100 {
				n++
			}
		}
		return n
	}
	a.Apply(mupT2ST("65100:1", endpoint, 0x100, 32, 0, 0, "fd00:3:3:c::"))
	if uplinks() != 1 {
		t.Fatal("uplink was not installed")
	}
	if _, ok := fh.v4created[endpoint+"/32"]; !ok {
		t.Fatal("endpoint gate was not installed")
	}

	replaced := mupT2ST("65100:1", endpoint, 0x100, 32, 0, 0, "fd00:3:3:c::")
	replaced.MUP.RTs = []string{"100:9999"}
	a.Apply(replaced)
	if uplinks() != 0 {
		t.Error("RT-mismatch T2ST update left the uplink installed")
	}
	if len(fh.v4deleted) != 1 || fh.v4deleted[0] != endpoint+"/32" {
		t.Errorf("RT-mismatch T2ST update left the gate installed; deleted=%v", fh.v4deleted)
	}
}

// A session route re-advertised with an unusable own Prefix-SID and no
// covering discovery must tear down the previously installed session, not
// re-install it toward the bad SID.
func TestApplyMUP_SessionUnusableOwnSIDUpdateReplaces(t *testing.T) {
	t.Run("T1ST", func(t *testing.T) {
		const ue = "10.1.0.1/32"
		fh := newFakeHeadend()
		a := newMUPApplier(t, fh)
		a.Apply(mupT1ST("65100:1", ue, "172.16.0.1", 256, 9, "fd00:a:0:1::"))
		if _, ok := fh.v4created[ue]; !ok {
			t.Fatal("downlink was not installed via the own SID")
		}

		a.Apply(mupT1ST("65100:1", ue, "172.16.0.1", 256, 9, "::"))
		if len(fh.v4deleted) != 1 || fh.v4deleted[0] != ue {
			t.Errorf("unusable own-SID T1ST update left the downlink installed; deleted=%v", fh.v4deleted)
		}
	})

	t.Run("T2ST", func(t *testing.T) {
		const endpoint = "192.0.2.100"
		fh := newFakeHeadend()
		a := newMUPApplier(t, fh)
		a.Apply(mupT2ST("65100:1", endpoint, 0x100, 32, 0, 0, "fd00:3:3:c::"))
		if _, ok := fh.mupUplink[mupUplinkKey{0, endpoint, 0x100, 32}]; !ok {
			t.Fatal("uplink was not installed via the own SID")
		}

		a.Apply(mupT2ST("65100:1", endpoint, 0x100, 32, 0, 0, "fe80::1"))
		if _, ok := fh.mupUplink[mupUplinkKey{0, endpoint, 0x100, 32}]; ok {
			t.Error("unusable own-SID T2ST update left the uplink installed")
		}
	})
}

// The RT3 counterpart of the other-PE guard: an unusable claim from a
// different PE must not clear the flood peer the original PE still backs.
func TestApplier_EVPNRT3UnusableFromOtherPEKeepsPeer(t *testing.T) {
	a, fh := evpnApplier(t)
	installed := rt3("fd00:2:2:24::")
	installed.NextHop = "2001:db8::a"
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: installed})
	if len(fh.bdPeers) != 1 {
		t.Fatal("RT3 was not installed")
	}

	other := rt3("")
	other.NextHop = "2001:db8::b"
	a.Apply(bgp.RouteEvent{Family: bgp.FamilyEVPN, EVPN: other})
	if len(fh.bdPeers) != 1 {
		t.Error("unusable claim from another PE cleared the flood peer")
	}
}
