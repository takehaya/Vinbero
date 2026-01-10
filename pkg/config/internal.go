package config

import (
	"fmt"

	"github.com/cilium/ebpf/link"
)

type InternalConfig struct {
	LogFile    string       `yaml:"logfile,omitempty" default:"/var/log/vinbero.log"`
	BpfOptions BpfConfig    `yaml:"bpf_options,omitempty"`
	Devices    []string     `yaml:"devices,omitempty"`
	Logger     LoggerConfig `yaml:"logger,omitempty"`
}

type LoggerConfig struct {
	JSON      bool `yaml:"json,omitempty" default:"false"`       // if true, use JSON format
	NoColor   bool `yaml:"no_color,omitempty" default:"false"`   // if true, disable color output
	Verbose   int  `yaml:"verbose,omitempty" default:"0"`        // 0 is Info level, 1 or higher is Debug
	Quiet     bool `yaml:"quiet,omitempty" default:"false"`      // if true, raise to Warn level or higher
	AddCaller bool `yaml:"add_caller,omitempty" default:"false"` // if true, add caller information to logs
}

type BpfConfig struct {
	DeviceMode      string `yaml:"device_mode,omitempty" default:"driver"`
	LogLevel        int    `yaml:"log_level,omitempty" default:"2"`
	VerifierLogSize uint32 `yaml:"verifier_log_size,omitempty" default:"1073741823"`
}

func ConvToStrXDPAttachMode(name string) (link.XDPAttachFlags, error) {
	switch name {
	case "generic":
		return link.XDPGenericMode, nil
	case "driver":
		return link.XDPDriverMode, nil
	case "offload":
		return link.XDPOffloadMode, nil
	}
	return 0, fmt.Errorf("%s action not match", name)
}
