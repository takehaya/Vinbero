package config

import "testing"

func TestLoadCplaneNativeDefault(t *testing.T) {
	for _, tc := range []struct {
		name, yaml string
		want       bool
	}{
		{"empty", "", true},
		{"other settings", "settings:\n  enable_stats: true\n", true},
		{"empty plugins", "settings:\n  cplane_plugins: {}\n", true},
		{"enabled", "settings:\n  cplane_plugins:\n    native_enabled: true\n", true},
		{"disabled", "settings:\n  cplane_plugins:\n    native_enabled: false\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Load(tc.yaml)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Setting.CplanePlugins.NativeEnabled != tc.want {
				t.Fatalf("native_enabled = %v, want %v", cfg.Setting.CplanePlugins.NativeEnabled, tc.want)
			}
		})
	}
}
