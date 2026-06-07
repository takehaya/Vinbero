package vrfbgp

import (
	"errors"
	"slices"
	"testing"

	"github.com/takehaya/vinbero/pkg/bgp"
)

func TestManager_BindListUnbind(t *testing.T) {
	m := NewManager()
	if !m.Empty() {
		t.Fatal("a fresh Manager must report Empty()")
	}
	b := Binding{
		VRFName:        "vrf-a",
		ImportRTs:      []string{"65000:100"},
		ExportRTs:      []string{"65000:100"},
		DefaultLocator: "LOC1",
	}
	if err := m.Bind(b); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if m.Empty() {
		t.Error("Empty() = true after Bind")
	}
	if list := m.List(); len(list) != 1 || list[0].VRFName != "vrf-a" {
		t.Errorf("List = %v, want one vrf-a", list)
	}
	if err := m.Unbind("vrf-a"); err != nil {
		t.Fatalf("Unbind: %v", err)
	}
	if !m.Empty() {
		t.Error("Empty() = false after Unbind")
	}
}

func TestManager_BindEmptyNameRejected(t *testing.T) {
	if err := NewManager().Bind(Binding{VRFName: ""}); !errors.Is(err, ErrEmptyVRFName) {
		t.Errorf("Bind with empty name: got %v, want ErrEmptyVRFName", err)
	}
}

func TestManager_UnbindUnknownRejected(t *testing.T) {
	if err := NewManager().Unbind("nope"); !errors.Is(err, ErrBindingNotFound) {
		t.Errorf("Unbind unknown: got %v, want ErrBindingNotFound", err)
	}
}

// TestManager_BindReplaces pins that re-binding a VRF name overwrites the
// previous policy rather than accumulating a second entry.
func TestManager_BindReplaces(t *testing.T) {
	m := NewManager()
	if err := m.Bind(Binding{VRFName: "vrf-a", ImportRTs: []string{"65000:1"}}); err != nil {
		t.Fatalf("first Bind: %v", err)
	}
	if err := m.Bind(Binding{VRFName: "vrf-a", ImportRTs: []string{"65000:2"}}); err != nil {
		t.Fatalf("re-Bind: %v", err)
	}
	if list := m.List(); len(list) != 1 {
		t.Errorf("re-Bind must replace, got %d bindings", len(list))
	}
	if _, ok := m.MatchImport([]string{"65000:2"}); !ok {
		t.Error("MatchImport should see the replacement import RT")
	}
	if _, ok := m.MatchImport([]string{"65000:1"}); ok {
		t.Error("MatchImport should not see the stale import RT after replace")
	}
}

func TestManager_GetByBDID(t *testing.T) {
	m := NewManager()
	if err := m.Bind(Binding{VRFName: "evi100", RD: "65000:100", BDID: 100}); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if err := m.Bind(Binding{VRFName: "l3vrf", RD: "65000:1"}); err != nil { // BDID 0
		t.Fatalf("Bind: %v", err)
	}
	b, ok := m.GetByBDID(100)
	if !ok || b.VRFName != "evi100" {
		t.Errorf("GetByBDID(100) = %+v, %v; want the evi100 binding", b, ok)
	}
	if _, ok := m.GetByBDID(200); ok {
		t.Error("GetByBDID(200) should miss when no binding has that bd_id")
	}
	if _, ok := m.GetByBDID(0); ok {
		t.Error("GetByBDID(0) must never match an L3VPN-only binding")
	}
	// Two bindings claiming the same bd_id is ambiguous: GetByBDID must refuse
	// rather than return a map-order-dependent result.
	if err := m.Bind(Binding{VRFName: "evi100-dup", RD: "65000:101", BDID: 100}); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if _, ok := m.GetByBDID(100); ok {
		t.Error("GetByBDID(100) must be ambiguous (ok=false) when two bindings share the bd_id")
	}
}

func TestManager_MatchImport(t *testing.T) {
	m := NewManager()
	if err := m.Bind(Binding{VRFName: "vrf-a", ImportRTs: []string{"65000:100", "65000:101"}}); err != nil {
		t.Fatalf("Bind vrf-a: %v", err)
	}
	if err := m.Bind(Binding{VRFName: "vrf-b", ImportRTs: []string{"65000:200"}}); err != nil {
		t.Fatalf("Bind vrf-b: %v", err)
	}

	if vrf, ok := m.MatchImport([]string{"65000:101"}); !ok || vrf != "vrf-a" {
		t.Errorf("MatchImport 65000:101 = (%q,%v), want (vrf-a,true)", vrf, ok)
	}
	if vrf, ok := m.MatchImport([]string{"65000:200"}); !ok || vrf != "vrf-b" {
		t.Errorf("MatchImport 65000:200 = (%q,%v), want (vrf-b,true)", vrf, ok)
	}
	if _, ok := m.MatchImport([]string{"65000:999"}); ok {
		t.Error("MatchImport of an unregistered RT should miss")
	}
	// A route carrying several RTs matches if any one is imported.
	if _, ok := m.MatchImport([]string{"65000:999", "65000:200"}); !ok {
		t.Error("MatchImport should match when any RT is imported")
	}
}

// TestNormalize_LegacyL3VPNExpansion pins that a binding given only the
// legacy ImportRTs/ExportRTs (no Families) expands to both vpnv4 and vpnv6
// when bd_id == 0, matching the L3VPN "RT shared across v4 and v6" convention.
func TestNormalize_LegacyL3VPNExpansion(t *testing.T) {
	b := Binding{
		VRFName:   "vrf-a",
		ImportRTs: []string{"65000:1"},
		ExportRTs: []string{"65000:1"},
	}.Normalize()
	if _, ok := b.Families[bgp.FamilyVPNv4]; !ok {
		t.Errorf("legacy L3VPN expansion must include vpnv4, got %v", keys(b.Families))
	}
	if _, ok := b.Families[bgp.FamilyVPNv6]; !ok {
		t.Errorf("legacy L3VPN expansion must include vpnv6, got %v", keys(b.Families))
	}
	if _, ok := b.Families[bgp.FamilyEVPN]; ok {
		t.Error("legacy L3VPN expansion must not touch the evpn family")
	}
	vpnv4 := b.Families[bgp.FamilyVPNv4].RouteTargets
	if len(vpnv4) != 1 || vpnv4[0].RT != "65000:1" || !vpnv4[0].Direction.Has(DirectionImport) || !vpnv4[0].Direction.Has(DirectionExport) {
		t.Errorf("RT shared across import+export must end with DirectionBoth, got %+v", vpnv4)
	}
}

// TestNormalize_LegacyEVPNExpansion pins that a binding with bd_id != 0
// expands its legacy RTs into the evpn family only (not vpnv4/vpnv6).
func TestNormalize_LegacyEVPNExpansion(t *testing.T) {
	b := Binding{
		VRFName:   "evi100",
		BDID:      100,
		ImportRTs: []string{"65000:100"},
		ExportRTs: []string{"65000:100"},
	}.Normalize()
	if _, ok := b.Families[bgp.FamilyEVPN]; !ok {
		t.Errorf("legacy EVPN expansion must include the evpn family, got %v", keys(b.Families))
	}
	if _, ok := b.Families[bgp.FamilyVPNv4]; ok {
		t.Error("legacy EVPN expansion (bd_id != 0) must not populate vpnv4")
	}
}

// TestNormalize_FamiliesSourceOfTruth pins that when Families is set the
// legacy ImportRTs/ExportRTs are synthesized from it (so the exporter and
// the legacy MatchImport helpers see one consistent view).
func TestNormalize_FamiliesSourceOfTruth(t *testing.T) {
	b := Binding{
		VRFName: "vrf-a",
		Families: map[bgp.Family]FamilyPolicy{
			bgp.FamilyVPNv4: {RouteTargets: []RouteTarget{
				{RT: "65000:1", Direction: DirectionImport},
				{RT: "65000:2", Direction: DirectionExport},
			}},
		},
	}.Normalize()
	if !slices.Equal(b.ImportRTs, []string{"65000:1"}) {
		t.Errorf("ImportRTs synthesis = %v, want [65000:1]", b.ImportRTs)
	}
	if !slices.Equal(b.ExportRTs, []string{"65000:2"}) {
		t.Errorf("ExportRTs synthesis = %v, want [65000:2]", b.ExportRTs)
	}
}

// TestMatchImportForFamily_LegacyBindingsMUPDefaultAllow pins that a
// binding given only the legacy form never imports a MUP family: MUP keeps
// its historical default-allow until an operator opts in by writing a new-form
// mup_ipv* family explicitly.
func TestMatchImportForFamily_LegacyBindingsMUPDefaultAllow(t *testing.T) {
	m := NewManager()
	if err := m.Bind(Binding{VRFName: "vrf-a", ImportRTs: []string{"65000:1"}}); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if !m.EmptyForFamily(bgp.FamilyMUPIPv4) {
		t.Error("a legacy-form binding must leave MUP_IPv4 EmptyForFamily")
	}
	if _, _, ok := m.MatchImportForFamily([]string{"65000:1"}, bgp.FamilyMUPIPv4); ok {
		t.Error("a legacy-form binding must NOT match a MUP family lookup")
	}
}

func TestMatchImportForFamily_NewFormPerFamilyIsolation(t *testing.T) {
	m := NewManager()
	if err := m.Bind(Binding{
		VRFName: "vrf-a",
		BDID:    100,
		Families: map[bgp.Family]FamilyPolicy{
			bgp.FamilyEVPN: {RouteTargets: []RouteTarget{
				{RT: "65000:100", Direction: DirectionImport},
			}},
			bgp.FamilyMUPIPv4: {RouteTargets: []RouteTarget{
				{RT: "65000:200", Direction: DirectionImport},
			}},
		},
	}); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	// EVPN RT only resolves under FamilyEVPN, returning the bd_id.
	vrf, bdID, ok := m.MatchImportForFamily([]string{"65000:100"}, bgp.FamilyEVPN)
	if !ok || vrf != "vrf-a" || bdID != 100 {
		t.Errorf("EVPN lookup = (%q, %d, %v), want (vrf-a, 100, true)", vrf, bdID, ok)
	}
	// The same EVPN RT must NOT resolve under MUP.
	if _, _, ok := m.MatchImportForFamily([]string{"65000:100"}, bgp.FamilyMUPIPv4); ok {
		t.Error("EVPN RT must not leak into a MUP_IPv4 lookup")
	}
	// MUP RT resolves only under MUP family.
	if vrf, _, ok := m.MatchImportForFamily([]string{"65000:200"}, bgp.FamilyMUPIPv4); !ok || vrf != "vrf-a" {
		t.Errorf("MUP lookup = (%q, %v), want (vrf-a, true)", vrf, ok)
	}
}

// TestExportRTsForFamily_DirectionFilter pins that ExportRTsForFamily only
// returns RTs with the export bit set, in declaration order.
func TestExportRTsForFamily_DirectionFilter(t *testing.T) {
	m := NewManager()
	if err := m.Bind(Binding{
		VRFName: "vrf-a",
		Families: map[bgp.Family]FamilyPolicy{
			bgp.FamilyMUPIPv4: {RouteTargets: []RouteTarget{
				{RT: "65000:100", Direction: DirectionImport},
				{RT: "65000:200", Direction: DirectionExport},
				{RT: "65000:300", Direction: DirectionBoth},
			}},
		},
	}); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	got := m.ExportRTsForFamily("vrf-a", bgp.FamilyMUPIPv4)
	want := []string{"65000:200", "65000:300"}
	if !slices.Equal(got, want) {
		t.Errorf("ExportRTsForFamily = %v, want %v", got, want)
	}
	// Unknown VRF or unknown family returns nil rather than panicking.
	if got := m.ExportRTsForFamily("vrf-zzz", bgp.FamilyMUPIPv4); got != nil {
		t.Errorf("unknown vrf must return nil, got %v", got)
	}
	if got := m.ExportRTsForFamily("vrf-a", bgp.FamilyEVPN); got != nil {
		t.Errorf("unknown family must return nil, got %v", got)
	}
}

func TestBindingByRD(t *testing.T) {
	m := NewManager()
	if err := m.Bind(Binding{VRFName: "vrf-a", RD: "10.0.0.1:100"}); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if err := m.Bind(Binding{VRFName: "vrf-b", RD: "10.0.0.1:200"}); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	b, ok := m.BindingByRD("10.0.0.1:100")
	if !ok || b.VRFName != "vrf-a" {
		t.Errorf("BindingByRD = %+v, %v; want vrf-a", b, ok)
	}
	if _, ok := m.BindingByRD(""); ok {
		t.Error("BindingByRD(\"\") must miss")
	}
	if _, ok := m.BindingByRD("10.0.0.1:999"); ok {
		t.Error("BindingByRD of an unknown RD must miss")
	}
	// Ambiguous: two bindings share the same RD -> ok=false.
	if err := m.Bind(Binding{VRFName: "vrf-dup", RD: "10.0.0.1:100"}); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if _, ok := m.BindingByRD("10.0.0.1:100"); ok {
		t.Error("BindingByRD must be ambiguous (ok=false) when two bindings share the RD")
	}
}

func TestEmptyForFamily(t *testing.T) {
	m := NewManager()
	if !m.EmptyForFamily(bgp.FamilyVPNv4) {
		t.Error("a fresh Manager must report EmptyForFamily=true")
	}
	if err := m.Bind(Binding{
		VRFName: "vrf-a",
		Families: map[bgp.Family]FamilyPolicy{
			bgp.FamilyVPNv4: {RouteTargets: []RouteTarget{{RT: "65000:1", Direction: DirectionImport}}},
		},
	}); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if m.EmptyForFamily(bgp.FamilyVPNv4) {
		t.Error("EmptyForFamily(vpnv4) must be false once a vpnv4 binding exists")
	}
	// EVPN and MUP remain Empty: a vpnv4-only binding does not leak into other AFs.
	if !m.EmptyForFamily(bgp.FamilyEVPN) {
		t.Error("EVPN must remain EmptyForFamily until an EVPN binding exists")
	}
	if !m.EmptyForFamily(bgp.FamilyMUPIPv4) {
		t.Error("MUP must remain EmptyForFamily until a MUP binding exists")
	}
}

func keys[K comparable, V any](m map[K]V) []K {
	out := make([]K, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
