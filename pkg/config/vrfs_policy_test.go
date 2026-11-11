package config

import "testing"

// The config owns the VRF policy when the file states default_deny or
// deny_action, with any value, written in place or through a merge.
func TestVRFsPolicyDeclared(t *testing.T) {
	for _, tc := range []struct {
		yaml string
		want bool
	}{
		{"internal: {}\n", false},
		{"vrfs:\n  entries: []\n", false},
		{"vrfs:\n  default_deny: false\n", true},
		{"vrfs:\n  deny_action: drop\n", true},
		{"vrfs:\n  default_deny: true\n", true},
		{"base: &b\n  default_deny: false\nvrfs:\n  <<: *b\n", true},
		{"base: &b\n  deny_action: pass\nvrfs: *b\n", true},
	} {
		cfg, err := Load(tc.yaml)
		if err != nil {
			t.Fatalf("%q: %v", tc.yaml, err)
		}
		if got := cfg.VRFs.PolicyDeclared(); got != tc.want {
			t.Errorf("%q: PolicyDeclared() = %v, want %v", tc.yaml, got, tc.want)
		}
	}
}
