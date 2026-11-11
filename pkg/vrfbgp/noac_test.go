package vrfbgp

import (
	"slices"
	"testing"

	"github.com/takehaya/vinbero/pkg/bgp"
	"github.com/takehaya/vinbero/pkg/vrf"
)

// BindingsWithoutAC lists a VRF that imports L3VPN or MUP routes and has no
// AC, and nothing else: not a VRF with an AC, not an EVPN-only or export-only
// binding, not one outside the names asked for.
func TestBindingsWithoutAC(t *testing.T) {
	m := NewManager()
	imp := func(fams ...bgp.Family) map[bgp.Family]FamilyPolicy {
		out := map[bgp.Family]FamilyPolicy{}
		for _, f := range fams {
			out[f] = FamilyPolicy{RouteTargets: []RouteTarget{{RT: "65000:1", Direction: DirectionImport}}}
		}
		return out
	}
	for _, b := range []Binding{
		{VRFName: "no-ac", Families: imp(bgp.FamilyVPNv4, bgp.FamilyMUPIPv4)},
		{VRFName: "with-ac", Families: imp(bgp.FamilyVPNv4)},
		{VRFName: "evpn-only", Families: imp(bgp.FamilyEVPN)},
		{VRFName: "export-only", Families: map[bgp.Family]FamilyPolicy{bgp.FamilyVPNv6: {RouteTargets: []RouteTarget{{RT: "65000:2", Direction: DirectionExport}}}}},
	} {
		if err := m.Bind(b); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := m.VRF().AddAC("with-ac", vrf.AC{Interface: "eth9"}); err != nil {
		t.Fatal(err)
	}
	got := m.BindingsWithoutAC(nil)
	id, _ := m.VRF().IDForName("no-ac")
	if len(got) != 1 || got[0].VRF != "no-ac" || got[0].VRFID != id ||
		!slices.Equal(got[0].Families, []bgp.Family{bgp.FamilyVPNv4, bgp.FamilyMUPIPv4}) {
		t.Fatalf("BindingsWithoutAC = %+v, want only no-ac (id %d) for vpnv4 and mup_ipv4", got, id)
	}
	if got := m.BindingsWithoutAC([]string{"with-ac", "evpn-only"}); len(got) != 0 {
		t.Errorf("names without the AC-less VRF: %+v, want none", got)
	}
}
