package server

import (
	"testing"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
)

// TestSidFunctionErrorIdentifier pins the contract that batched
// SidFunctionCreate failures return an OperationError TriggerPrefix the
// caller can correlate back to its input even when locator_ref failed
// before the SID was materialized.
func TestSidFunctionErrorIdentifier(t *testing.T) {
	tests := []struct {
		name string
		in   *v1.SidFunction
		want string
	}{
		{
			name: "trigger_prefix-set",
			in:   &v1.SidFunction{TriggerPrefix: "fc00:1::1/128"},
			want: "fc00:1::1/128",
		},
		{
			name: "locator_ref-only",
			in:   &v1.SidFunction{LocatorRef: &v1.LocatorRef{Name: "LOC1"}},
			want: "locator:LOC1",
		},
		{
			name: "both-empty",
			in:   &v1.SidFunction{},
			want: "",
		},
		{
			name: "prefix-preferred-when-both-set",
			in:   &v1.SidFunction{TriggerPrefix: "fc00:1::1/128", LocatorRef: &v1.LocatorRef{Name: "LOC2"}},
			want: "fc00:1::1/128",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sidFunctionErrorIdentifier(tc.in); got != tc.want {
				t.Errorf("sidFunctionErrorIdentifier: got %q, want %q", got, tc.want)
			}
		})
	}
}
