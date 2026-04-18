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

type SettingConfig struct {
	Entries           EntriesConfig `yaml:"entries,omitempty"`
	EnableStats       bool          `yaml:"enable_stats,omitempty" default:"false"`
	StatePath         string        `yaml:"state_path,omitempty"`      // Path for resource state file (default: /var/lib/vinbero/state.json)
	FdbAgingSeconds   int           `yaml:"fdb_aging_seconds,omitempty" default:"300"` // FDB entry aging timeout (0=disabled)
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
