package cli

import (
	"fmt"
	"strconv"
	"strings"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
)

// protoEnum is a constraint for protobuf-generated enum types
type protoEnum interface {
	~int32
	String() string
}

// resolveProtoEnum converts user-friendly names to proto enum values.
// Accepts short names ("END_DT4"), full names ("SRV6_LOCAL_ACTION_END_DT4"),
// and dotted names ("End.DT4") which are normalized to underscore-uppercase.
func resolveProtoEnum[T protoEnum](input string, prefix string, valueMap map[string]int32) (T, error) {
	upper := strings.ToUpper(strings.ReplaceAll(input, ".", "_"))

	if v, ok := valueMap[upper]; ok {
		return T(v), nil
	}
	if v, ok := valueMap[prefix+upper]; ok {
		return T(v), nil
	}

	// Allow raw numeric values (e.g., "32" for plugin slot indices)
	if n, err := strconv.ParseInt(input, 10, 32); err == nil {
		return T(n), nil
	}

	// Build valid names list from the value map, excluding UNSPECIFIED
	var valid []string
	for name := range valueMap {
		short := strings.TrimPrefix(name, prefix)
		if short == "UNSPECIFIED" {
			continue
		}
		valid = append(valid, short)
	}
	return 0, fmt.Errorf("unknown value: %s (valid: %s)", input, strings.Join(valid, ", "))
}

// formatProtoEnum converts proto enum to human-readable string, stripping the prefix.
// Returns "" for NONE or UNSPECIFIED values.
func formatProtoEnum[T protoEnum](value T, prefix string) string {
	s := strings.TrimPrefix(value.String(), prefix)
	if s == "NONE" || s == "UNSPECIFIED" {
		return ""
	}
	return s
}

func resolveAction(input string) (v1.Srv6LocalAction, error) {
	return resolveProtoEnum[v1.Srv6LocalAction](input, "SRV6_LOCAL_ACTION_", v1.Srv6LocalAction_value)
}

func resolveMode(input string) (v1.Srv6HeadendBehavior, error) {
	return resolveProtoEnum[v1.Srv6HeadendBehavior](input, "SRV6_HEADEND_BEHAVIOR_", v1.Srv6HeadendBehavior_value)
}

func resolveFlavor(input string) (v1.Srv6LocalFlavor, error) {
	return resolveProtoEnum[v1.Srv6LocalFlavor](input, "SRV6_LOCAL_FLAVOR_", v1.Srv6LocalFlavor_value)
}

func formatAction(action v1.Srv6LocalAction) string {
	return formatProtoEnum(action, "SRV6_LOCAL_ACTION_")
}

func formatMode(mode v1.Srv6HeadendBehavior) string {
	return formatProtoEnum(mode, "SRV6_HEADEND_BEHAVIOR_")
}

func formatFlavor(flavor v1.Srv6LocalFlavor) string {
	return formatProtoEnum(flavor, "SRV6_LOCAL_FLAVOR_")
}
