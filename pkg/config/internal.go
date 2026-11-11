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
	// load: 1 logs branches, 2 logs every instruction. Off by default
	// because the log costs real time per load and cilium/ebpf already
	// requests a branch-level one on its own when a program fails to
	// verify. Set it to 2 to get instruction-level detail in that failure.
	VerifierLogLevel int `yaml:"verifier_log_level,omitempty" default:"0"`
	// VerifierLogSize is the starting size of that log buffer, per program.
	// It grows on demand, and is capped so a large value cannot commit
	// hundreds of megabytes up front. Zero leaves the starting size to
	// cilium/ebpf.
	VerifierLogSize uint32 `yaml:"verifier_log_size,omitempty" default:"0"`
	// FibLookupTBID chooses how the outer header of a tenant AC's
	// encapsulation is looked up. "auto" (the default) looks it up in the
	// main table directly when the kernel's bpf_fib_lookup accepts
	// BPF_FIB_LOOKUP_TBID, which the daemon checks at load. "off" uses the
	// ingress-device lookup for every packet, as on a kernel without it,
	// and leaves the VRF tables without the unreachable default.
	FibLookupTBID string `yaml:"fib_lookup_tbid,omitempty" default:"auto"`
	// FibLookupTBIDOff is the outcome the daemon sets at load (not read
	// from the file): the tenant lookup falls back to the ingress device.
	FibLookupTBIDOff bool `yaml:"-"`
	// FibLookupGlobal chooses how the global VRF's (vrf 0) FIB lookups are
	// made. "rules" (the default) runs each as the kernel's full lookup,
	// ip rules included. "auto" has the daemon watch the namespace's ip
	// rules, local table, IPv4 default table and VRF tables, and run the
	// lookups of an address family as a direct lookup of the one table the
	// full lookup would end in while that gives the same answer
	// (pkg/fibmode); otherwise they stay the full lookup. "auto" needs
	// BPF_FIB_LOOKUP_TBID (fib_lookup_tbid), without which it is "rules".
	FibLookupGlobal string `yaml:"fib_lookup_global,omitempty" default:"rules"`
	// FibLookupGlobalAuto is the outcome the daemon sets at load (not read
	// from the file): the program may switch to the direct lookup.
	FibLookupGlobalAuto bool `yaml:"-"`
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
