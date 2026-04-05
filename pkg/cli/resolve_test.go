package cli

import (
	"testing"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
)

func TestResolveAction(t *testing.T) {
	tests := []struct {
		input    string
		expected v1.Srv6LocalAction
		wantErr  bool
	}{
		// Short name
		{"END", v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END, false},
		{"END_DT4", v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DT4, false},
		{"END_X", v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_X, false},
		{"END_T", v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_T, false},
		// Full name
		{"SRV6_LOCAL_ACTION_END_DT6", v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DT6, false},
		// Dotted name
		{"End.DT4", v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DT4, false},
		{"End.X", v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_X, false},
		{"End.DX2", v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DX2, false},
		// Case insensitive
		{"end_dt4", v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DT4, false},
		{"end.dt4", v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DT4, false},
		// Invalid
		{"INVALID", 0, true},
		{"", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := resolveAction(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("resolveAction(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.expected {
				t.Errorf("resolveAction(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestResolveMode(t *testing.T) {
	tests := []struct {
		input    string
		expected v1.Srv6HeadendBehavior
		wantErr  bool
	}{
		{"H_ENCAPS", v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS, false},
		{"H.Encaps", v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS, false},
		{"H_ENCAPS_L2", v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2, false},
		{"H.Encaps.L2", v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2, false},
		{"SRV6_HEADEND_BEHAVIOR_H_INSERT", v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_INSERT, false},
		{"INVALID", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := resolveMode(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("resolveMode(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.expected {
				t.Errorf("resolveMode(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestResolveFlavor(t *testing.T) {
	tests := []struct {
		input    string
		expected v1.Srv6LocalFlavor
		wantErr  bool
	}{
		{"PSP", v1.Srv6LocalFlavor_SRV6_LOCAL_FLAVOR_PSP, false},
		{"USP", v1.Srv6LocalFlavor_SRV6_LOCAL_FLAVOR_USP, false},
		{"USD", v1.Srv6LocalFlavor_SRV6_LOCAL_FLAVOR_USD, false},
		{"psp", v1.Srv6LocalFlavor_SRV6_LOCAL_FLAVOR_PSP, false},
		{"SRV6_LOCAL_FLAVOR_PSP", v1.Srv6LocalFlavor_SRV6_LOCAL_FLAVOR_PSP, false},
		{"INVALID", 0, true},
		{"", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := resolveFlavor(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("resolveFlavor(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.expected {
				t.Errorf("resolveFlavor(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestFormatAction(t *testing.T) {
	tests := []struct {
		input    v1.Srv6LocalAction
		expected string
	}{
		{v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END, "END"},
		{v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_X, "END_X"},
		{v1.Srv6LocalAction_SRV6_LOCAL_ACTION_END_DT4, "END_DT4"},
		{v1.Srv6LocalAction_SRV6_LOCAL_ACTION_UNSPECIFIED, ""},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := formatAction(tt.input)
			if got != tt.expected {
				t.Errorf("formatAction(%v) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestFormatFlavor(t *testing.T) {
	tests := []struct {
		input    v1.Srv6LocalFlavor
		expected string
	}{
		{v1.Srv6LocalFlavor_SRV6_LOCAL_FLAVOR_PSP, "PSP"},
		{v1.Srv6LocalFlavor_SRV6_LOCAL_FLAVOR_USP, "USP"},
		{v1.Srv6LocalFlavor_SRV6_LOCAL_FLAVOR_USD, "USD"},
		{v1.Srv6LocalFlavor_SRV6_LOCAL_FLAVOR_NONE, ""},
		{v1.Srv6LocalFlavor_SRV6_LOCAL_FLAVOR_UNSPECIFIED, ""},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := formatFlavor(tt.input)
			if got != tt.expected {
				t.Errorf("formatFlavor(%v) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestFormatMode(t *testing.T) {
	tests := []struct {
		input    v1.Srv6HeadendBehavior
		expected string
	}{
		{v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_ENCAPS, "H_ENCAPS"},
		{v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_H_INSERT, "H_INSERT"},
		{v1.Srv6HeadendBehavior_SRV6_HEADEND_BEHAVIOR_UNSPECIFIED, ""},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := formatMode(tt.input)
			if got != tt.expected {
				t.Errorf("formatMode(%v) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}
