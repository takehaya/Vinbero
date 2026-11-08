// Package cni implements the vinbero CNI plugin: it connects a pod to a
// Vinbero VRF over a veth pair, puts the host end on the XDP data plane
// through the local vinberod, and advertises the pod address as an L3VPN
// route by installing it into the VRF table.
package cni

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/containernetworking/cni/pkg/types"
)

const (
	// ModeL3 routes the pod address as a /32 in the VRF (L3VPN).
	ModeL3 = "l3"

	defaultServer     = "http://127.0.0.1:8080"
	defaultDeviceMode = "generic"
	defaultDataDir    = "/var/lib/vinbero/cni"

	// defaultMTU leaves room for the outer IPv6 header (40 bytes) and an
	// SRH carrying one SID (8 + 16 bytes) on a 1500-byte underlay.
	defaultMTU = 1500 - 40 - (8 + 16)
)

// RouteTarget is one route target of the VRF's BGP binding.
type RouteTarget struct {
	Family    string `json:"family"`
	RT        string `json:"rt"`
	Direction string `json:"direction,omitempty"`
}

// NetConf is the plugin's network configuration (the NetworkAttachmentDefinition
// spec.config under Multus).
type NetConf struct {
	types.NetConf

	// Server is the vinberod Connect RPC address, "host:port" or a URL.
	Server string `json:"server,omitempty"`
	Mode   string `json:"mode,omitempty"`
	// VRF and TableID name the kernel VRF the pod joins. The VRF is created
	// when missing; an existing one must use the same table.
	VRF     string `json:"vrf"`
	TableID uint32 `json:"tableId"`

	// RD, RTs and Locator describe the VRF's BGP binding. When set, the
	// plugin creates the binding if the VRF has none. When omitted, the
	// binding must come from the vinberod config or an operator.
	RD          string        `json:"rd,omitempty"`
	RTs         []RouteTarget `json:"rts,omitempty"`
	Locator     string        `json:"locator,omitempty"`
	MaxPrefixes uint32        `json:"maxPrefixes,omitempty"`

	// DeviceMode is the XDP attach mode of the host veth.
	DeviceMode string `json:"deviceMode,omitempty"`
	// MTU of both veth ends.
	MTU int `json:"mtu,omitempty"`
	// DataDir holds the per-attachment records DEL and CHECK read.
	DataDir string `json:"dataDir,omitempty"`
}

// ParseConf decodes and validates a network configuration and fills in the
// defaults.
func ParseConf(data []byte) (*NetConf, error) {
	c := &NetConf{}
	if err := json.Unmarshal(data, c); err != nil {
		return nil, fmt.Errorf("parse network configuration: %w", err)
	}
	if c.Server == "" {
		c.Server = defaultServer
	}
	if !strings.Contains(c.Server, "://") {
		c.Server = "http://" + c.Server
	}
	if c.Mode == "" {
		c.Mode = ModeL3
	}
	if c.DeviceMode == "" {
		c.DeviceMode = defaultDeviceMode
	}
	if c.MTU == 0 {
		c.MTU = defaultMTU
	}
	if c.DataDir == "" {
		c.DataDir = defaultDataDir
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *NetConf) validate() error {
	if c.Name == "" {
		return fmt.Errorf("name is required")
	}
	if c.Mode != ModeL3 {
		return fmt.Errorf("mode %q is not supported (only %q)", c.Mode, ModeL3)
	}
	if err := validIfname(c.VRF); err != nil {
		return fmt.Errorf("vrf: %w", err)
	}
	if c.VRF == "global" {
		return fmt.Errorf("vrf: %q is reserved for the underlay", c.VRF)
	}
	switch c.TableID {
	case 0:
		return fmt.Errorf("tableId is required")
	case 253, 254, 255:
		return fmt.Errorf("tableId %d is a reserved kernel table", c.TableID)
	}
	if c.IPAM.Type == "" {
		return fmt.Errorf("ipam.type is required")
	}
	switch c.DeviceMode {
	case "generic", "driver":
	default:
		return fmt.Errorf("deviceMode %q: want \"generic\" or \"driver\"", c.DeviceMode)
	}
	if c.MTU < 68 || c.MTU > 65535 {
		return fmt.Errorf("mtu %d out of range (68..65535)", c.MTU)
	}
	return c.validateBinding()
}

// validateBinding requires rd, rts and locator together: half a binding
// would advertise without a route target or a SID.
func (c *NetConf) validateBinding() error {
	if !c.WantsBinding() {
		if c.MaxPrefixes != 0 {
			return fmt.Errorf("maxPrefixes needs rd, rts and locator")
		}
		return nil
	}
	if c.RD == "" || len(c.RTs) == 0 || c.Locator == "" {
		return fmt.Errorf("rd, rts and locator must be set together")
	}
	for i, rt := range c.RTs {
		switch rt.Family {
		case "vpnv4", "vpnv6":
		default:
			return fmt.Errorf("rts[%d]: family %q: want \"vpnv4\" or \"vpnv6\"", i, rt.Family)
		}
		if rt.RT == "" {
			return fmt.Errorf("rts[%d]: rt is required", i)
		}
		switch rt.Direction {
		case "", "import", "export", "both":
		default:
			return fmt.Errorf("rts[%d]: direction %q: want import, export or both", i, rt.Direction)
		}
	}
	return nil
}

// WantsBinding reports whether the configuration carries a BGP binding.
func (c *NetConf) WantsBinding() bool {
	return c.RD != "" || len(c.RTs) > 0 || c.Locator != ""
}

// validIfname applies the kernel's interface name rules.
func validIfname(name string) error {
	switch {
	case name == "":
		return fmt.Errorf("name is required")
	case len(name) > 15:
		return fmt.Errorf("%q is longer than 15 bytes", name)
	case name == "." || name == "..":
		return fmt.Errorf("%q is not a valid interface name", name)
	case strings.ContainsAny(name, "/: \t\n"):
		return fmt.Errorf("%q contains '/', ':' or whitespace", name)
	}
	return nil
}
