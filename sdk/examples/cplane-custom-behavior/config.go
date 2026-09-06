package main

import "github.com/takehaya/vinbero/sdk/go/cplane/wire"

// Configuration is private to this example. The host forwards these bytes
// unchanged; registration separately grants capabilities, scope and the claim.
type configuration struct {
	behavior uint32
	locator  string
	prefix   string
	vrf      string
	slot     uint32
	nextHop  string
	decapVRF string
}

func decodeConfig(data []byte) (configuration, error) {
	cfg := configuration{behavior: 0xFE01}
	d := wire.NewDecoder(data)
	for d.Next() {
		switch d.Field {
		case 1:
			if d.Type != wire.Varint || d.Uint == 0 || d.Uint > 0xffff {
				return cfg, wire.ErrMalformed
			}
			cfg.behavior = uint32(d.Uint)
		case 5:
			if d.Type != wire.Varint || d.Uint > 1<<32-1 {
				return cfg, wire.ErrMalformed
			}
			cfg.slot = uint32(d.Uint)
		case 2, 3, 4, 7, 8:
			if d.Type != wire.Bytes {
				return cfg, wire.ErrMalformed
			}
			value := string(d.Bytes)
			switch d.Field {
			case 2:
				cfg.locator = value
			case 3:
				cfg.prefix = value
			case 4:
				cfg.vrf = value
			case 7:
				cfg.nextHop = value
			case 8:
				cfg.decapVRF = value
			}
		}
	}
	return cfg, d.Err()
}
