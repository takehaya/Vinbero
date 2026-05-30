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
	if p.ConnectRetrySec != 5 {
		t.Errorf("ConnectRetrySec = %d, want 5 (default)", p.ConnectRetrySec)
	}
	if p.Passive {
		t.Errorf("Passive = true, want false (default)")
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
      connect_retry_sec: 10
      passive: true
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
	if p.ConnectRetrySec != 10 {
		t.Errorf("ConnectRetrySec = %d, want 10 (explicit)", p.ConnectRetrySec)
	}
	if !p.Passive {
		t.Errorf("Passive = false, want true (explicit)")
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

// TestLoad_ExplicitZeroSurvives is the regression guard for the BGP-peer
// default fix: the per-peer SetDefaults pass must stay scoped to
// bgp.peers[] and never re-stamp the rest of the config. A user who
// writes settings.fdb_aging_seconds: 0 ("disabled") must keep the 0,
// not have it bounced back to the 300 default.
func TestLoad_ExplicitZeroSurvives(t *testing.T) {
	cfg, err := Load("settings:\n  fdb_aging_seconds: 0\n")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Setting.FdbAgingSeconds != 0 {
		t.Errorf("fdb_aging_seconds = %d, want 0 (explicit 0 = disabled must survive)",
			cfg.Setting.FdbAgingSeconds)
	}
}

// TestLoad_BGPAutoAdvertiseFields pins that the auto-advertise config surface
// round-trips through Load: the global next_hop / underlay fields, the per-VRF
// rd / redistribute / max_prefixes, and the locator defaults (which live on a
// slice-of-struct field, so the second SetDefaults pass must reach them).
func TestLoad_BGPAutoAdvertiseFields(t *testing.T) {
	const y = `
bgp:
  global:
    local_asn: 65100
    auto_advertise: true
    next_hop: "2001:db8:ff::1"
    underlay_redistribute: [connected]
    underlay_max_prefixes: 100
  locators:
    - name: LOC1
      prefix: "fd00:100::/48"
      block_len: 32
      node_len: 16
      function_len: 16
      argument_len: 64
  vrf_bindings:
    - vrf_name: vrf1
      rd: "65100:200"
      import_rts: ["65000:200"]
      export_rts: ["65000:200"]
      default_locator: LOC1
      redistribute: [connected, static]
      max_prefixes: 1000
`
	cfg, err := Load(y)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	g := cfg.BGP.Global
	if !g.AutoAdvertise {
		t.Error("AutoAdvertise = false, want true")
	}
	if g.NextHop != "2001:db8:ff::1" {
		t.Errorf("NextHop = %q", g.NextHop)
	}
	if len(g.UnderlayRedistribute) != 1 || g.UnderlayRedistribute[0] != "connected" {
		t.Errorf("UnderlayRedistribute = %v", g.UnderlayRedistribute)
	}
	if g.UnderlayMaxPrefixes != 100 {
		t.Errorf("UnderlayMaxPrefixes = %d, want 100", g.UnderlayMaxPrefixes)
	}
	if len(cfg.BGP.Locators) != 1 {
		t.Fatalf("Locators len = %d, want 1", len(cfg.BGP.Locators))
	}
	loc := cfg.BGP.Locators[0]
	if loc.Name != "LOC1" || loc.Prefix != "fd00:100::/48" {
		t.Errorf("locator = %+v", loc)
	}
	// Defaults reach the slice-of-struct locator via the second pass.
	if loc.Behavior != "classic" {
		t.Errorf("locator Behavior = %q, want classic (default)", loc.Behavior)
	}
	if loc.FunctionAutoStart != 16 {
		t.Errorf("locator FunctionAutoStart = %d, want 16 (default)", loc.FunctionAutoStart)
	}
	if loc.FunctionAutoEnd != 65534 {
		t.Errorf("locator FunctionAutoEnd = %d, want 65534 (default)", loc.FunctionAutoEnd)
	}
	if len(cfg.BGP.VrfBindings) != 1 {
		t.Fatalf("VrfBindings len = %d, want 1", len(cfg.BGP.VrfBindings))
	}
	b := cfg.BGP.VrfBindings[0]
	if b.RD != "65100:200" {
		t.Errorf("binding RD = %q", b.RD)
	}
	if len(b.Redistribute) != 2 {
		t.Errorf("binding Redistribute = %v", b.Redistribute)
	}
	if b.MaxPrefixes != 1000 {
		t.Errorf("binding MaxPrefixes = %d, want 1000", b.MaxPrefixes)
	}
}
