package customcontroller

import (
	"fmt"
	"net/netip"

	"github.com/takehaya/vinbero/sdk/go/cplane/wire"
)

// Config describes routing and opaque endpoint data. Registration separately
// grants capabilities and scope; AuxRaw has meaning only to the Dplane plugin.
type Config struct {
	Behavior        uint32
	Locator         string
	Prefix          string
	VRF             string
	Slot            uint32
	NextHop         string
	DecapVRF        string
	HeadendPrefixes []netip.Prefix
	AuxRaw          []byte
}

func (c Config) allocates() bool { return c.Locator != "" && c.Slot != 0 }
func (c Config) advertises() bool {
	return c.allocates() && c.Prefix != "" && c.VRF != "" && c.NextHop != ""
}

func decodeConfig(data []byte) (Config, error) {
	cfg := Config{Behavior: 0xFE01}
	d := wire.NewDecoder(data)
	for d.Next() {
		switch d.Field {
		case 1:
			if d.Type != wire.Varint || d.Uint == 0 || d.Uint > 0xffff {
				return cfg, wire.ErrMalformed
			}
			cfg.Behavior = uint32(d.Uint)
		case 5:
			if d.Type != wire.Varint || d.Uint > 1<<32-1 {
				return cfg, wire.ErrMalformed
			}
			cfg.Slot = uint32(d.Uint)
		case 2, 3, 4, 7, 8, 9:
			if d.Type != wire.Bytes {
				return cfg, wire.ErrMalformed
			}
			value := string(d.Bytes)
			switch d.Field {
			case 2:
				cfg.Locator = value
			case 3:
				cfg.Prefix = value
			case 4:
				cfg.VRF = value
			case 7:
				cfg.NextHop = value
			case 8:
				cfg.DecapVRF = value
			case 9:
				prefix, err := netip.ParsePrefix(value)
				if err != nil || !prefix.Addr().Is4() {
					return cfg, fmt.Errorf("invalid IPv4 headend prefix %q", value)
				}
				cfg.HeadendPrefixes = append(cfg.HeadendPrefixes, prefix.Masked())
			}
		}
	}
	return cfg, d.Err()
}
