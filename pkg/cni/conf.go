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
	// ModeL2 attaches the pod to an EVPN bridge domain: the pod gets an
	// on-link address and reaches the other nodes' pods of the same network
	// over an SRv6 L2 segment (End.DT2U/DT2M, MAC routes over BGP).
	ModeL2 = "l2"

	defaultServer     = "http://127.0.0.1:8080"
	defaultDeviceMode = "generic"
	defaultDataDir    = "/var/lib/vinbero/cni"

	// defaultMTU leaves room for the outer IPv6 header (40 bytes) and an
	// SRH carrying one SID (8 + 16 bytes) on a 1500-byte underlay.
	defaultMTU = 1500 - 40 - (8 + 16)
	// defaultMTUL2 leaves room, on top of the L3 headroom, for the inner
	// Ethernet header (14 bytes) that H.Encaps.L2 carries.
	defaultMTUL2 = defaultMTU - 14
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
	// when missing; an existing one must use the same table. TableID is for
	// the L3 kernel-device facet; an L2 bridge domain has no routing table,
	// so it must not be set in L2 mode.
	VRF     string `json:"vrf"`
	TableID uint32 `json:"tableId"`

	// Bridge and BdID name the pre-declared bridge domain the pod joins in
	// L2 mode. The bridge and its bd_id are declared in the node's vinberod
	// config; the plugin never creates or destroys them.
	Bridge string `json:"bridge,omitempty"`
	BdID   uint32 `json:"bdId,omitempty"`

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
		if c.Mode == ModeL2 {
			c.MTU = defaultMTUL2
		} else {
			c.MTU = defaultMTU
		}
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
	switch c.Mode {
	case ModeL3, ModeL2:
	default:
		return fmt.Errorf("mode %q is not supported (only %q or %q)", c.Mode, ModeL3, ModeL2)
	}
	if err := validIfname(c.VRF); err != nil {
		return fmt.Errorf("vrf: %w", err)
	}
	if c.VRF == "global" {
		return fmt.Errorf("vrf: %q is reserved for the underlay", c.VRF)
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
	if c.Mode == ModeL2 {
		return c.validateL2()
	}
	return c.validateL3()
}

// validateL3 checks the L3-mode fields: a routing table and an optional
// VPNv4/VPNv6 binding.
func (c *NetConf) validateL3() error {
	if c.Bridge != "" || c.BdID != 0 {
		return fmt.Errorf("bridge and bdId are only for mode %q", ModeL2)
	}
	switch c.TableID {
	case 0:
		return fmt.Errorf("tableId is required")
	case 253, 254, 255:
		return fmt.Errorf("tableId %d is a reserved kernel table", c.TableID)
	}
	return c.validateBinding()
}

// validateL2 checks the L2-mode fields: a pre-declared bridge domain and an
// optional EVPN binding. The bridge domain has no routing table.
func (c *NetConf) validateL2() error {
	if c.TableID != 0 {
		return fmt.Errorf("tableId is not used in mode %q (the bridge domain has no routing table)", ModeL2)
	}
	if err := validIfname(c.Bridge); err != nil {
		return fmt.Errorf("bridge: %w", err)
	}
	if c.BdID == 0 || c.BdID > 65535 {
		return fmt.Errorf("bdId %d out of range (1..65535)", c.BdID)
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
		switch {
		case c.Mode == ModeL2 && rt.Family == "evpn":
		case c.Mode != ModeL2 && (rt.Family == "vpnv4" || rt.Family == "vpnv6"):
		case c.Mode == ModeL2:
			return fmt.Errorf("rts[%d]: family %q: want \"evpn\" in mode %q", i, rt.Family, ModeL2)
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
	}
	// dev_valid_name: '/', ':' and every byte the kernel's isspace() accepts.
	for i := 0; i < len(name); i++ {
		switch name[i] {
		case '/', ':', ' ', '\t', '\n', '\v', '\f', '\r', 0xa0:
			return fmt.Errorf("%q contains '/', ':' or whitespace", name)
		}
	}
	return nil
}
