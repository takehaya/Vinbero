package cli

import (
	"fmt"
	"strings"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
)

// resolveAction converts user-friendly action names to proto enum values.
// Accepts: "END_DT4", "SRV6_LOCAL_ACTION_END_DT4", "End.DT4"
func resolveAction(input string) (v1.Srv6LocalAction, error) {
	upper := strings.ToUpper(strings.ReplaceAll(input, ".", "_"))

	if v, ok := v1.Srv6LocalAction_value[upper]; ok {
		return v1.Srv6LocalAction(v), nil
	}
	if v, ok := v1.Srv6LocalAction_value["SRV6_LOCAL_ACTION_"+upper]; ok {
		return v1.Srv6LocalAction(v), nil
	}
	return 0, fmt.Errorf("unknown action: %s (valid: END, END_X, END_T, END_DX2, END_DX4, END_DX6, END_DT2, END_DT4, END_DT6, END_DT46)", input)
}

// resolveMode converts user-friendly mode names to proto enum values.
// Accepts: "H_ENCAPS", "SRV6_HEADEND_BEHAVIOR_H_ENCAPS", "H.Encaps"
func resolveMode(input string) (v1.Srv6HeadendBehavior, error) {
	upper := strings.ToUpper(strings.ReplaceAll(input, ".", "_"))

	if v, ok := v1.Srv6HeadendBehavior_value[upper]; ok {
		return v1.Srv6HeadendBehavior(v), nil
	}
	if v, ok := v1.Srv6HeadendBehavior_value["SRV6_HEADEND_BEHAVIOR_"+upper]; ok {
		return v1.Srv6HeadendBehavior(v), nil
	}
	return 0, fmt.Errorf("unknown mode: %s (valid: H_INSERT, H_ENCAPS, H_ENCAPS_L2)", input)
}

// formatAction converts proto enum to human-readable string.
func formatAction(action v1.Srv6LocalAction) string {
	name := action.String()
	return strings.TrimPrefix(name, "SRV6_LOCAL_ACTION_")
}

// formatMode converts proto enum to human-readable string.
func formatMode(mode v1.Srv6HeadendBehavior) string {
	name := mode.String()
	return strings.TrimPrefix(name, "SRV6_HEADEND_BEHAVIOR_")
}
