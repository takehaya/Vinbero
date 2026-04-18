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
	Original       string
	Configpath     string
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
	cfg.Original = s
	return &cfg, nil
}
func FileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}
