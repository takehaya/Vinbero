package config

import (
	"os"

	"github.com/mcuadros/go-defaults"
	"gopkg.in/yaml.v3"
)

// Config is the top-level configuration
type Config struct {
	InternalConfig InternalConfig `yaml:"internal,omitempty"`
	Setting        SettingConfig  `yaml:"settings,omitempty"`
	BGP            BGPConfig      `yaml:"bgp,omitempty"`
	Original       string
	Configpath     string
}

// BGPConfig is the optional in-process BGP speaker configuration. It is
// only consulted when vinberod is started with --bgp-enabled; an empty
// section leaves BGP off.
type BGPConfig struct {
	Global      BGPGlobalConfig    `yaml:"global,omitempty"`
	Peers       []BGPPeerConfig    `yaml:"peers,omitempty"`
	VrfBindings []VrfBindingConfig `yaml:"vrf_bindings,omitempty"`
}

// VrfBindingConfig is a VRF <-> route-target binding applied at startup,
// before the BGP session begins receiving. Configuring it here (rather than
// via VrfBgpBind after boot) avoids a race where an EVPN route arrives before
// its bridge-domain binding exists and is dropped. bd_id is the bridge domain
// for EVPN routes matching import_rts (0 for L3VPN-only bindings).
type VrfBindingConfig struct {
	VRFName        string   `yaml:"vrf_name,omitempty"`
	ImportRTs      []string `yaml:"import_rts,omitempty"`
	ExportRTs      []string `yaml:"export_rts,omitempty"`
	DefaultLocator string   `yaml:"default_locator,omitempty"`
	BDID           uint32   `yaml:"bd_id,omitempty"`
}

// BGPGlobalConfig is the speaker's own BGP identity.
type BGPGlobalConfig struct {
	LocalASN uint32 `yaml:"local_asn,omitempty"`
	RouterID string `yaml:"router_id,omitempty"`
	// ListenPort defaults to -1: the in-process speaker does not bind
	// TCP/179, so it coexists with a host BGP daemon. Set a real port
	// only when vinberod owns BGP on the box.
	ListenPort int32 `yaml:"listen_port,omitempty" default:"-1"`
	// SourceLocator names the locator whose prefix supplies the SRv6
	// encap source address for BGP-driven headend entries (see plan
	// §6-5). Unused until Phase 1d; accepted now so config files are
	// forward-compatible.
	SourceLocator string `yaml:"source_locator,omitempty"`
}

// BGPPeerConfig describes one BGP neighbor.
type BGPPeerConfig struct {
	Neighbor     string   `yaml:"neighbor,omitempty"`
	PeerASN      uint32   `yaml:"peer_asn,omitempty"`
	HoldTimeSec  uint32   `yaml:"hold_time_sec,omitempty" default:"90"`
	KeepaliveSec uint32   `yaml:"keepalive_sec,omitempty" default:"30"`
	Families     []string `yaml:"families,omitempty"` // vpnv4 / vpnv6 / ipv6_unicast / sr_policy_ipv6 / evpn
	// Passive stops this peer from dialing out; it only accepts the
	// neighbor's inbound connection. Set it on one end of each iBGP
	// full-mesh pair to avoid connection-collision flap.
	Passive bool `yaml:"passive,omitempty"`
}

// BpfConstants returns the set of read-only constants rewritten into every
// BPF object vinbero loads (main data plane and plugin ELFs). The keys
// match `const volatile` names in the C sources.
func (c *Config) BpfConstants() map[string]any {
	v := uint8(0)
	if c.Setting.EnableStats {
		v = 1
	}
	return map[string]any{"enable_stats": v}
}

type SettingConfig struct {
	Entries         EntriesConfig  `yaml:"entries,omitempty"`
	EnableStats     bool           `yaml:"enable_stats,omitempty" default:"false"`
	StatePath       string         `yaml:"state_path,omitempty"`                      // Path for resource state file (default: /var/lib/vinbero/state.json)
	FdbAgingSeconds int            `yaml:"fdb_aging_seconds,omitempty" default:"300"` // FDB entry aging timeout (0=disabled)
	PinMaps         PinMapsConfig  `yaml:"pin_maps,omitempty"`                        // Pin control-state BPF maps under /sys/fs/bpf so they survive a vinberod restart.
	Validate        ValidateConfig `yaml:"validate,omitempty"`                        // Plugin validator policy knobs.
}

// ValidateConfig knobs the plugin validator enforces on the server side.
// CLI `plugin validate` always runs in shift-left enforce regardless of
// these values — they only adjust the behaviour of `PluginRegister`.
type ValidateConfig struct {
	// RoEnforce selects how plugin writes into vinbero shared read-only
	// maps are handled at register time. "warn" (default during initial
	// rollout) logs the violation but still loads the plugin; "enforce"
	// hard-rejects the RPC. Empty string is treated as "warn".
	RoEnforce string `yaml:"ro_enforce,omitempty" default:"warn"`
}

// PinMapsConfig toggles pinning for the daemon's control-state BPF maps
// (sid_function_map, sid_aux_map, headend_*_map, fdb_map, bd_peer_map,
// bd_peer_reverse_map, dx2v_map). Ephemeral maps (stats, slot_stats,
// scratch, tailcall_ctx, PROG_ARRAY) are never pinned: their values
// either reset naturally at restart or hold program FDs that can't
// survive a new process.
type PinMapsConfig struct {
	Enabled bool   `yaml:"enabled,omitempty" default:"false"`
	Path    string `yaml:"path,omitempty" default:"/sys/fs/bpf/vinbero"`
}

// EntriesConfig holds the capacity settings for each entry type
type EntriesConfig struct {
	SidFunction EntryCapacityConfig `yaml:"sid_function,omitempty"`
	Headendv4   EntryCapacityConfig `yaml:"headendv4,omitempty"`
	Headendv6   EntryCapacityConfig `yaml:"headendv6,omitempty"`
	HeadendL2   EntryCapacityConfig `yaml:"headend_l2,omitempty"`
	Fdb         EntryCapacityConfig `yaml:"fdb,omitempty"`
	BdPeer      EntryCapacityConfig `yaml:"bd_peer,omitempty"`
	VlanTable   EntryCapacityConfig `yaml:"vlan_table,omitempty"`
	SrPolicy    EntryCapacityConfig `yaml:"sr_policy,omitempty"`
	MaxSegments int                 `yaml:"max_segments,omitempty" default:"10"`
}

// EntryCapacityConfig holds capacity setting for a single entry type
type EntryCapacityConfig struct {
	Capacity int `yaml:"capacity,omitempty" default:"1024"`
}

// LoadFile parses the given YAML file into a Config.
func LoadFile(filename string) (*Config, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	cfg, err := Load(string(content))
	if err != nil {
		return nil, err
	}
	cfg.Configpath = filename
	return cfg, nil
}

// Load parses the YAML input s into a Config.
func Load(s string) (*Config, error) {
	cfg := Config{}
	defaults.SetDefaults(&cfg)

	err := yaml.Unmarshal([]byte(s), &cfg)
	if err != nil {
		return nil, err
	}
	// bgp.peers[] elements do not exist during the pre-unmarshal
	// SetDefaults call, so their `default:` tags need a targeted second
	// pass. This is scoped to each peer element on purpose: a blanket
	// SetDefaults(&cfg) here would re-stamp every zero-valued field in
	// the whole config and clobber values a user set to zero
	// deliberately (e.g. settings.fdb_aging_seconds: 0 means "disabled").
	for i := range cfg.BGP.Peers {
		defaults.SetDefaults(&cfg.BGP.Peers[i])
	}
	cfg.Original = s
	return &cfg, nil
}
func FileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}
