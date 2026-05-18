package config

import "testing"

// TestLoad_BGPPeerDefaults pins that per-peer timer defaults survive the
// load path. The defaults live on slice-of-struct fields, which the
// pre-unmarshal SetDefaults pass cannot reach -- Load runs a second pass
// after unmarshal precisely to cover this.
func TestLoad_BGPPeerDefaults(t *testing.T) {
	const y = `
bgp:
  global:
    local_asn: 65000
    router_id: "10.0.0.1"
  peers:
    - neighbor: "10.0.0.2"
      peer_asn: 65001
`
	cfg, err := Load(y)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.BGP.Peers) != 1 {
		t.Fatalf("BGP.Peers len = %d, want 1", len(cfg.BGP.Peers))
	}
	p := cfg.BGP.Peers[0]
	if p.HoldTimeSec != 90 {
		t.Errorf("HoldTimeSec = %d, want 90 (default)", p.HoldTimeSec)
	}
	if p.KeepaliveSec != 30 {
		t.Errorf("KeepaliveSec = %d, want 30 (default)", p.KeepaliveSec)
	}
	if cfg.BGP.Global.ListenPort != -1 {
		t.Errorf("Global.ListenPort = %d, want -1 (default)", cfg.BGP.Global.ListenPort)
	}
}

// TestLoad_BGPPeerExplicitOverride pins that explicit YAML values are not
// clobbered by the second SetDefaults pass.
func TestLoad_BGPPeerExplicitOverride(t *testing.T) {
	const y = `
bgp:
  peers:
    - neighbor: "10.0.0.2"
      peer_asn: 65001
      hold_time_sec: 180
      keepalive_sec: 60
`
	cfg, err := Load(y)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	p := cfg.BGP.Peers[0]
	if p.HoldTimeSec != 180 {
		t.Errorf("HoldTimeSec = %d, want 180 (explicit)", p.HoldTimeSec)
	}
	if p.KeepaliveSec != 60 {
		t.Errorf("KeepaliveSec = %d, want 60 (explicit)", p.KeepaliveSec)
	}
}

// TestLoad_NoBGPSection confirms a config without a bgp: block loads
// cleanly with an empty BGPConfig.
func TestLoad_NoBGPSection(t *testing.T) {
	cfg, err := Load("settings:\n  enable_stats: true\n")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.BGP.Peers) != 0 {
		t.Errorf("BGP.Peers should be empty, got %d", len(cfg.BGP.Peers))
	}
}
