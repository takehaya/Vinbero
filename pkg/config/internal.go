package config

import (
	"fmt"

	"github.com/cilium/ebpf/link"
)

type InternalConfig struct {
	BpfOptions BpfConfig    `yaml:"bpf,omitempty"`
	Devices    []string     `yaml:"devices,omitempty"`
	Logger     LoggerConfig `yaml:"logger,omitempty"`
	Server     ServerConfig `yaml:"server,omitempty"`
}

type LoggerConfig struct {
	Level     string `yaml:"level,omitempty" default:"info"`       // debug, info, warn, error
	Format    string `yaml:"format,omitempty" default:"text"`      // text, json
	NoColor   bool   `yaml:"no_color,omitempty" default:"false"`   // disable color output
	AddCaller bool   `yaml:"add_caller,omitempty" default:"false"` // add caller information
}

type BpfConfig struct {
	DeviceMode string `yaml:"device_mode,omitempty" default:"driver"`
	// VerifierLogLevel asks the kernel for a verifier log on every program
	// load: 1 for instructions, 2 for branches. Off by default because the
	// log costs real time per load and cilium/ebpf already requests one on
	// its own when a program fails to verify. Turn it on to debug a load.
	VerifierLogLevel int `yaml:"verifier_log_level,omitempty" default:"0"`
	// VerifierLogSize is the starting size of that log buffer, per program.
	// It grows on demand, and is capped so a large value cannot commit
	// hundreds of megabytes up front.
	VerifierLogSize uint32 `yaml:"verifier_log_size,omitempty" default:"0"`
}

// ServerConfig holds the gRPC/Connect server configuration
type ServerConfig struct {
	BindAddress string `yaml:"bind,omitempty" default:"0.0.0.0:8080"`
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
