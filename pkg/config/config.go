package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the top-level configuration
type Config struct {
	InternalConfig InternalConfig `yaml:"internal,omitempty"`
	Setting        SettingConfig  `yaml:"settings,omitempty"`
	Original       string
	Configpath     string
}

type InternalConfig struct {
	LogFile     string   `yaml:"logfile,omitempty"`
	Development bool     `yaml:"development,omitempty"`
	Devices     []string `yaml:"devices,omitempty"`
}

type SettingConfig struct {
	Functions []FunctionsConfig `yaml:"functions,omitempty"`
	Transitv4 []Transitv4Config `yaml:"transitv4,omitempty"`
	Transitv6 []Transitv6Config `yaml:"transitv6,omitempty"`
}

type FunctionsConfig struct {
	Action      string `yaml:"action,omitempty"`
	TriggerAddr string `yaml:"triggerAddr,omitempty"`
	SAddr       string `yaml:"actionSrcAddr,omitempty"`
	DAddr       string `yaml:"actionDstAddr,omitempty"`
	Nexthop     string `yaml:"nexthop,omitempty"`
	Flaver      string `yaml:"flaver,omitempty"`
	V4AddrSPos  string `yaml:"v4AddrSPos,omitempty"`
	V4AddrDPos  string `yaml:"v4AddrDPos,omitempty"`
}

type Transitv4Config struct {
	Action      string   `yaml:"action,omitempty"`
	TriggerAddr string   `yaml:"triggerAddr,omitempty"`
	SAddr       string   `yaml:"actionSrcAddr,omitempty"`
	DAddr       string   `yaml:"actionDstAddr,omitempty"`
	Segments    []string `yaml:"segments,omitempty"`
}

type Transitv6Config struct {
	Action      string   `yaml:"action,omitempty"`
	TriggerAddr string   `yaml:"triggerAddr,omitempty"`
	SAddr       string   `yaml:"actionSrcAddr,omitempty"`
	DAddr       string   `yaml:"actionDstAddr,omitempty"`
	Segments    []string `yaml:"segments,omitempty"`
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
	cfg := &Config{}
	err := yaml.Unmarshal([]byte(s), cfg)
	if err != nil {
		return nil, err
	}
	cfg.Original = s
	return cfg, nil
}
func FileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}
