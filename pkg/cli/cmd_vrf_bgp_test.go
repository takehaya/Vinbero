package cli

import (
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
)

// parseOneRTFlag rounds-trips ASN-form and IP-form RTs and treats a trailing
// known direction word as a separate token. An IP-form RT (10.0.0.1:200)
// must not be misread as having a direction.
func TestParseOneRTFlag(t *testing.T) {
	cases := []struct {
		in      string
		family  string
		rt      string
		dir     string
		wantErr bool
	}{
		{in: "vpnv4:65000:200:both", family: "vpnv4", rt: "65000:200", dir: "both"},
		{in: "vpnv4:65000:200:import", family: "vpnv4", rt: "65000:200", dir: "import"},
		{in: "vpnv4:65000:200", family: "vpnv4", rt: "65000:200", dir: ""},
		{in: "mup_ipv4:100:6000:export", family: "mup_ipv4", rt: "100:6000", dir: "export"},
		{in: "vpnv4:10.0.0.1:200", family: "vpnv4", rt: "10.0.0.1:200", dir: ""},
		{in: "vpnv4:10.0.0.1:200:import", family: "vpnv4", rt: "10.0.0.1:200", dir: "import"},
		{in: "evpn:65000:100:BOTH", family: "evpn", rt: "65000:100", dir: "both"}, // case-insensitive direction
		{in: "vpnv4", wantErr: true},       // missing RT
		{in: "vpnv4:65000", wantErr: true}, // RT needs ASN:value form
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			fam, rt, dir, err := parseOneRTFlag(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got family=%q rt=%q dir=%q", fam, rt, dir)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if fam != tc.family || rt != tc.rt || dir != tc.dir {
				t.Errorf("got (%q,%q,%q), want (%q,%q,%q)", fam, rt, dir, tc.family, tc.rt, tc.dir)
			}
		})
	}
}

// parseRTFlags groups repeated --rt entries by family and preserves the
// per-family order entries were registered in (so the server's listing order
// stays predictable).
func TestParseRTFlags_GroupsAndPreservesOrder(t *testing.T) {
	got, err := parseRTFlags([]string{
		"vpnv4:65000:200:import",
		"vpnv4:65000:201:export",
		"evpn:65000:100:import",
	})
	if err != nil {
		t.Fatalf("parseRTFlags: %v", err)
	}
	v4 := got["vpnv4"]
	if v4 == nil || len(v4.GetRouteTargets()) != 2 {
		t.Fatalf("vpnv4 must group 2 RTs; got %+v", v4)
	}
	if v4.GetRouteTargets()[0].GetRt() != "65000:200" || v4.GetRouteTargets()[1].GetRt() != "65000:201" {
		t.Errorf("vpnv4 must preserve --rt order; got %+v", v4.GetRouteTargets())
	}
	if ev := got["evpn"]; ev == nil || len(ev.GetRouteTargets()) != 1 {
		t.Errorf("evpn must carry its single RT; got %+v", ev)
	}
}

// parseFamilyRTs is the family-scoped form (family add --rt) where the
// FAMILY: prefix is omitted because --family supplies it.
func TestParseFamilyRTs(t *testing.T) {
	got, err := parseFamilyRTs("vpnv4", []string{"65000:200:import", "10.0.0.1:200"})
	if err != nil {
		t.Fatalf("parseFamilyRTs: %v", err)
	}
	if len(got.GetRouteTargets()) != 2 {
		t.Fatalf("want 2 RTs, got %+v", got)
	}
	if got.GetRouteTargets()[0].GetRt() != "65000:200" || got.GetRouteTargets()[0].GetDirection() != "import" {
		t.Errorf("first RT mismatch; got %+v", got.GetRouteTargets()[0])
	}
	if got.GetRouteTargets()[1].GetRt() != "10.0.0.1:200" || got.GetRouteTargets()[1].GetDirection() != "" {
		t.Errorf("IP-form RT without direction should round-trip with empty direction; got %+v", got.GetRouteTargets()[1])
	}
}

// renderFamilies lays out the families column for `vrf-bgp list` with a
// stable family ordering and direction normalized to "both" when empty.
func TestRenderFamilies(t *testing.T) {
	in := map[string]*v1.VrfBgpFamily{
		"vpnv4": {RouteTargets: []*v1.VrfBgpRouteTarget{
			{Rt: "65000:200", Direction: "import"},
			{Rt: "65000:201", Direction: ""},
		}},
		"evpn": {RouteTargets: []*v1.VrfBgpRouteTarget{{Rt: "65000:100", Direction: "import"}}},
	}
	got := renderFamilies(in)
	want := "evpn=[65000:100(import)]; vpnv4=[65000:200(import),65000:201(both)]"
	if got != want {
		t.Errorf("renderFamilies mismatch\n got: %s\nwant: %s", got, want)
	}
	if renderFamilies(nil) != "-" {
		t.Errorf("nil families should render as %q", "-")
	}
}

// loadBatchOpsFile reads a YAML ops file and maps add/remove to the proto
// kind enum. The ops list keeps the file order so a deliberate (add X, remove
// X, add X) sequence reaches the server in the documented order.
func TestLoadBatchOpsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ops.yaml")
	yaml := `
ops:
  - kind: add
    family: vpnv4
    rt: "65000:200"
    direction: import
  - kind: remove
    family: vpnv4
    rt: "65000:200"
  - kind: add
    family: vpnv4
    rt: "65000:201"
    direction: both
`
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatalf("write ops file: %v", err)
	}
	got, err := loadBatchOpsFile(path)
	if err != nil {
		t.Fatalf("loadBatchOpsFile: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 ops, got %d", len(got))
	}
	if got[0].GetKind() != v1.RouteTargetOp_KIND_ADD || got[0].GetRouteTarget().GetRt() != "65000:200" {
		t.Errorf("first op mismatch: %+v", got[0])
	}
	if got[1].GetKind() != v1.RouteTargetOp_KIND_REMOVE {
		t.Errorf("second op kind mismatch: %+v", got[1])
	}
	if got[2].GetRouteTarget().GetDirection() != "both" {
		t.Errorf("third op direction mismatch: %+v", got[2])
	}
}

// batchKind rejects an unknown kind so a typo cannot silently no-op an op.
func TestBatchKind_Invalid(t *testing.T) {
	if _, err := batchKind("toggle"); err == nil {
		t.Error("unknown kind must be an error")
	}
	if k, _ := batchKind("ADD"); k != v1.RouteTargetOp_KIND_ADD {
		t.Errorf("case-insensitive add must map to KIND_ADD; got %v", k)
	}
}
