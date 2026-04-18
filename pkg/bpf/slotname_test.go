package bpf

import "testing"

func TestFormatEndpointBuiltinName(t *testing.T) {
	// Spot-check representative enum values to catch regressions when
	// Srv6LocalAction is extended or the pretty-name heuristic changes.
	cases := []struct {
		slot uint32
		want string
	}{
		{0, ""},          // UNSPECIFIED
		{1, "End"},       // SRV6_LOCAL_ACTION_END
		{2, "End.X"},     // SRV6_LOCAL_ACTION_END_X
		{8, "End.DT4"},   // SRV6_LOCAL_ACTION_END_DT4
		{9, "End.DT46"},  // SRV6_LOCAL_ACTION_END_DT46 (digit-bearing token)
		{11, "End.B6.Encaps"},
		{EndpointPluginBase, ""},  // plugin range returns empty
		{EndpointProgMax - 1, ""}, // last plugin slot
	}
	for _, tc := range cases {
		got := FormatEndpointBuiltinName(tc.slot)
		if got != tc.want {
			t.Errorf("FormatEndpointBuiltinName(%d) = %q, want %q", tc.slot, got, tc.want)
		}
	}
}

func TestFormatHeadendBuiltinName(t *testing.T) {
	cases := []struct {
		slot uint32
		want string
	}{
		{0, ""},                  // UNSPECIFIED
		{HeadendPluginBase, ""},  // first plugin slot
		{HeadendProgMax - 1, ""}, // last plugin slot
	}
	for _, tc := range cases {
		got := FormatHeadendBuiltinName(tc.slot)
		if got != tc.want {
			t.Errorf("FormatHeadendBuiltinName(%d) = %q, want %q", tc.slot, got, tc.want)
		}
	}
}

func TestPrettyEnumName(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"UNSPECIFIED", ""},
		{"END", "End"},
		{"END_X", "End.X"},             // short token stays upper
		{"END_DT4", "End.DT4"},         // digit token stays upper
		{"END_DT46", "End.DT46"},       // multi-digit token stays upper
		{"END_B6_ENCAPS", "End.B6.Encaps"},
		{"H_ENCAPS", "H.Encaps"},
		{"H_ENCAPS_RED", "H.Encaps.Red"}, // len=3 "Red" stays upper: want "H.Encaps.Red"
	}
	for _, tc := range cases {
		got := prettyEnumName(tc.in)
		if got != tc.want {
			t.Errorf("prettyEnumName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestValidateSlotStatsMapType(t *testing.T) {
	for _, t_ := range SlotStatsMapTypes {
		if err := ValidateSlotStatsMapType(t_); err != nil {
			t.Errorf("%q should be valid: %v", t_, err)
		}
	}
	if err := ValidateSlotStatsMapType("bogus"); err == nil {
		t.Error("bogus map type should be rejected")
	}
}
