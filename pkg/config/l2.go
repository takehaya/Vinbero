package config

import (
	"fmt"
)

// BUM replication modes accepted in settings.l2. The numeric values are the
// BUM_MODE_* constants of src/l2vpn/bum_xdp.h.
const (
	BumModeTC  = "tc"
	BumModeXDP = "xdp"
)

const (
	BumModeValueInherit uint8 = 0
	BumModeValueTC      uint8 = 1
	BumModeValueXDP     uint8 = 2
)

// L2Config holds L2VPN data-plane settings.
type L2Config struct {
	// BumMode selects how BUM frames of a bridge domain are replicated:
	// "tc" (default) clones them in TC and floods locally through the
	// kernel bridge; "xdp" replicates them in XDP through a per-BD devmap
	// and keeps the bridge off the path. It applies to every BD that
	// bridge_domains does not override.
	BumMode string `yaml:"bum_mode,omitempty"`
	// BridgeDomains overrides BumMode per bridge domain.
	BridgeDomains []BridgeDomainL2Config `yaml:"bridge_domains,omitempty"`
}

// BridgeDomainL2Config is a per-BD override of the L2 settings.
type BridgeDomainL2Config struct {
	BdID    uint16 `yaml:"bd_id"`
	BumMode string `yaml:"bum_mode,omitempty"`
}

func bumModeValue(mode string) (uint8, error) {
	switch mode {
	case "":
		return BumModeValueInherit, nil
	case BumModeTC:
		return BumModeValueTC, nil
	case BumModeXDP:
		return BumModeValueXDP, nil
	case "auto":
		return 0, fmt.Errorf("bum_mode %q is not implemented yet (want %q or %q)", mode, BumModeTC, BumModeXDP)
	}
	return 0, fmt.Errorf("unknown bum_mode %q (want %q or %q)", mode, BumModeTC, BumModeXDP)
}

// Validate checks the mode strings and the attach-mode requirement.
//
// xdp mode needs generic XDP. One devmap egress program builds every remote
// copy, and it learns which peer a copy is for from the replication plan the
// ingress program left for the frame on that CPU. Generic XDP runs the
// devmap programs of a broadcast synchronously, right after the ingress
// program, so the plan to use is the CPU's latest. Native XDP defers them to
// the bulk-queue flush at the end of the NAPI poll, when the CPU's latest
// plan belongs to a later frame.
func (c *L2Config) Validate(deviceMode string) error {
	def, err := bumModeValue(c.BumMode)
	if err != nil {
		return fmt.Errorf("settings.l2: %w", err)
	}
	xdp := def == BumModeValueXDP
	seen := make(map[uint16]struct{}, len(c.BridgeDomains))
	for _, bd := range c.BridgeDomains {
		if bd.BdID == 0 {
			return fmt.Errorf("settings.l2.bridge_domains: bd_id must be non-zero")
		}
		if _, dup := seen[bd.BdID]; dup {
			return fmt.Errorf("settings.l2.bridge_domains: bd_id %d listed twice", bd.BdID)
		}
		seen[bd.BdID] = struct{}{}
		v, err := bumModeValue(bd.BumMode)
		if err != nil {
			return fmt.Errorf("settings.l2.bridge_domains[bd_id=%d]: %w", bd.BdID, err)
		}
		if v == BumModeValueXDP {
			xdp = true
		}
	}
	if xdp && deviceMode != "generic" {
		return fmt.Errorf("settings.l2: bum_mode %q requires internal.bpf.device_mode \"generic\" (got %q): "+
			"native XDP runs the devmap egress program at the end of the NAPI poll, when the per-CPU replication plan may already belong to a later frame",
			BumModeXDP, deviceMode)
	}
	return nil
}

// DefaultBumMode returns the BUM_MODE_* value for BDs without an override.
func (c *L2Config) DefaultBumMode() uint8 {
	if v, err := bumModeValue(c.BumMode); err == nil && v != BumModeValueInherit {
		return v
	}
	return BumModeValueTC
}

// BumModeOverrides returns the per-BD BUM_MODE_* values that are set.
func (c *L2Config) BumModeOverrides() map[uint16]uint8 {
	out := make(map[uint16]uint8, len(c.BridgeDomains))
	for _, bd := range c.BridgeDomains {
		if v, err := bumModeValue(bd.BumMode); err == nil && v != BumModeValueInherit {
			out[bd.BdID] = v
		}
	}
	return out
}

// EffectiveBumMode returns the BUM_MODE_* value bdID runs with.
func (c *L2Config) EffectiveBumMode(bdID uint16) uint8 {
	if v, ok := c.BumModeOverrides()[bdID]; ok {
		return v
	}
	return c.DefaultBumMode()
}

// AnyXDP reports whether any bridge domain can run in xdp mode.
func (c *L2Config) AnyXDP() bool {
	if c.DefaultBumMode() == BumModeValueXDP {
		return true
	}
	for _, v := range c.BumModeOverrides() {
		if v == BumModeValueXDP {
			return true
		}
	}
	return false
}
