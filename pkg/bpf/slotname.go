package bpf

import (
	"fmt"
	"slices"
	"strings"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
)

// SlotStatsMapTypes enumerates the three slot_stats_* PROG_ARRAY map types
// in a stable order. Tests, server handlers, and CLI help all derive the
// set of valid --type values from here to avoid drift.
var SlotStatsMapTypes = []string{
	MapTypeEndpoint,
	MapTypeHeadendV4,
	MapTypeHeadendV6,
}

// ValidateSlotStatsMapType returns an error if mapType is not one of
// SlotStatsMapTypes.
func ValidateSlotStatsMapType(mapType string) error {
	if slices.Contains(SlotStatsMapTypes, mapType) {
		return nil
	}
	return fmt.Errorf("unknown slot stats map type %q (valid: %s)",
		mapType, strings.Join(SlotStatsMapTypes, ", "))
}

// FormatEndpointBuiltinName returns the pretty name for an endpoint slot
// occupied by a builtin (slot < EndpointPluginBase). Returns "" for
// unknown / unspecified values.
func FormatEndpointBuiltinName(slot uint32) string {
	if slot >= EndpointPluginBase {
		return ""
	}
	s := strings.TrimPrefix(v1.Srv6LocalAction(slot).String(), "SRV6_LOCAL_ACTION_")
	return prettyEnumName(s)
}

// FormatHeadendBuiltinName returns the pretty name for a headend slot
// occupied by a builtin (slot < HeadendPluginBase). Returns "" for
// unknown / unspecified values.
func FormatHeadendBuiltinName(slot uint32) string {
	if slot >= HeadendPluginBase {
		return ""
	}
	s := strings.TrimPrefix(v1.Srv6HeadendBehavior(slot).String(), "SRV6_HEADEND_BEHAVIOR_")
	return prettyEnumName(s)
}

// prettyEnumName turns UPPER_SNAKE into a dotted mixed-case label:
//
//	END           -> End
//	END_DT4       -> End.DT4
//	END_B6_ENCAPS -> End.B6.Encaps
//	H_ENCAPS_RED  -> H.Encaps.Red
//
// Tokens that contain digits stay upper (so GTP4/DX4/DT46/B6 read naturally);
// all-letter tokens get first-letter-upper-rest-lower (END→End, ENCAPS→Encaps).
func prettyEnumName(s string) string {
	if s == "" || s == "UNSPECIFIED" {
		return ""
	}
	parts := strings.Split(s, "_")
	for i, p := range parts {
		parts[i] = titleCaseToken(p)
	}
	return strings.Join(parts, ".")
}

func titleCaseToken(s string) string {
	if s == "" {
		return s
	}
	for _, r := range s {
		if r >= '0' && r <= '9' {
			return s
		}
	}
	return strings.ToUpper(s[:1]) + strings.ToLower(s[1:])
}
