package config

import (
	"strings"
	"testing"
)

func TestL2BumModeConfig(t *testing.T) {
	cases := []struct {
		name    string
		yaml    string
		wantErr string
		check   func(t *testing.T, c *Config)
	}{
		{
			name: "default is tc and adds no BPF constants",
			yaml: "internal:\n  bpf:\n    device_mode: driver\n",
			check: func(t *testing.T, c *Config) {
				if c.Setting.L2.AnyXDP() || c.Setting.L2.EffectiveBumMode(100) != BumModeValueTC {
					t.Errorf("default mode is not tc")
				}
				consts := c.BpfConstants()
				if _, ok := consts["bum_xdp_enabled"]; ok || len(consts) != 1 {
					t.Errorf("tc-only config must keep the constant set unchanged, got %v", consts)
				}
			},
		},
		{
			name: "xdp default with generic XDP",
			yaml: "internal:\n  bpf:\n    device_mode: generic\nsettings:\n  l2:\n    bum_mode: xdp\n    bridge_domains:\n      - bd_id: 200\n        bum_mode: tc\n",
			check: func(t *testing.T, c *Config) {
				l2 := &c.Setting.L2
				if l2.EffectiveBumMode(100) != BumModeValueXDP || l2.EffectiveBumMode(200) != BumModeValueTC {
					t.Errorf("modes: bd100=%d bd200=%d", l2.EffectiveBumMode(100), l2.EffectiveBumMode(200))
				}
				consts := c.BpfConstants()
				if consts["bum_xdp_enabled"] != uint8(1) || consts["bum_mode_default"] != BumModeValueXDP {
					t.Errorf("constants = %v", consts)
				}
			},
		},
		{
			name: "per-BD xdp override",
			yaml: "internal:\n  bpf:\n    device_mode: generic\nsettings:\n  l2:\n    bridge_domains:\n      - bd_id: 100\n        bum_mode: xdp\n",
			check: func(t *testing.T, c *Config) {
				if c.BpfConstants()["bum_mode_default"] != BumModeValueTC {
					t.Errorf("default must stay tc")
				}
				if got := c.Setting.L2.BumModeOverrides(); got[100] != BumModeValueXDP || len(got) != 1 {
					t.Errorf("overrides = %v", got)
				}
			},
		},
		{
			name:    "xdp requires generic XDP (driver is the default)",
			yaml:    "settings:\n  l2:\n    bum_mode: xdp\n",
			wantErr: `requires internal.bpf.device_mode "generic"`,
		},
		{
			name:    "a per-BD xdp override also requires generic XDP",
			yaml:    "internal:\n  bpf:\n    device_mode: driver\nsettings:\n  l2:\n    bridge_domains:\n      - bd_id: 7\n        bum_mode: xdp\n",
			wantErr: `requires internal.bpf.device_mode "generic"`,
		},
		{
			name:    "auto is not implemented yet",
			yaml:    "internal:\n  bpf:\n    device_mode: generic\nsettings:\n  l2:\n    bum_mode: auto\n",
			wantErr: "not implemented",
		},
		{
			name:    "unknown mode",
			yaml:    "settings:\n  l2:\n    bum_mode: bridge\n",
			wantErr: "unknown bum_mode",
		},
		{
			name:    "duplicate BD",
			yaml:    "settings:\n  l2:\n    bridge_domains:\n      - bd_id: 7\n      - bd_id: 7\n",
			wantErr: "listed twice",
		},
		{
			name:    "BD 0",
			yaml:    "settings:\n  l2:\n    bridge_domains:\n      - bum_mode: tc\n",
			wantErr: "non-zero",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := Load(tc.yaml)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to mention %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			tc.check(t, c)
		})
	}
}

func TestL2DisableXDP(t *testing.T) {
	c, err := Load("internal:\n  bpf:\n    device_mode: generic\nsettings:\n  l2:\n    bum_mode: xdp\n    bridge_domains:\n      - bd_id: 200\n        bum_mode: tc\n      - bd_id: 300\n        bum_mode: xdp\n")
	if err != nil {
		t.Fatal(err)
	}
	l2 := &c.Setting.L2
	l2.DisableXDP("test")
	if l2.AnyXDP() || !l2.ConfiguresXDP() || l2.XDPUnavailable() != "test" {
		t.Errorf("AnyXDP=%v ConfiguresXDP=%v reason=%q", l2.AnyXDP(), l2.ConfiguresXDP(), l2.XDPUnavailable())
	}
	for bd, want := range map[uint16]uint8{100: BumModeValueTCFallback, 200: BumModeValueTC, 300: BumModeValueTCFallback} {
		if got := l2.EffectiveBumMode(bd); got != want {
			t.Errorf("bd %d: mode %d, want %d", bd, got, want)
		}
	}
	// The constants stay, so the fallback BDs can count their frames.
	consts := c.BpfConstants()
	if consts["bum_xdp_enabled"] != uint8(1) || consts["bum_mode_default"] != BumModeValueTCFallback {
		t.Errorf("constants = %v", consts)
	}
}
