package cplane

import (
	"fmt"
	"github.com/takehaya/vinbero/sdk/go/cplane/wire"
)

// InputConfig is the configure envelope explicitly selected by input API v1.
// Payload is the unchanged operator configuration for the plugin itself.
type InputConfig struct {
	Version  uint32
	Payload  []byte
	Codec    string
	Contexts []InputContext
}
type InputContext struct {
	Name     string
	Families []string
}

func DecodeInputConfig(data []byte, features uint64) (InputConfig, error) {
	var out InputConfig
	if features&(FeatureBGPPath|FeatureInputContexts) != FeatureBGPPath|FeatureInputContexts {
		return out, fmt.Errorf("context-filtered BGP inputs unavailable")
	}
	err := decodeMessage(data, func(d *wire.Decoder) bool {
		switch d.Field {
		case 1:
			if d.Type != wire.Varint || d.Uint > 1<<32-1 {
				return false
			}
			out.Version = uint32(d.Uint)
		case 2, 3, 4:
			if d.Type != wire.Bytes {
				return false
			}
			switch d.Field {
			case 2:
				out.Payload = append([]byte(nil), d.Bytes...)
			case 3:
				out.Codec = string(d.Bytes)
			case 4:
				var ctx InputContext
				if err := decodeMessage(d.Bytes, func(c *wire.Decoder) bool {
					switch c.Field {
					case 1:
						if c.Type != wire.Bytes {
							return false
						}
						ctx.Name = string(c.Bytes)
					case 2:
						if c.Type != wire.Bytes {
							return false
						}
						ctx.Families = append(ctx.Families, string(c.Bytes))
					}
					return true
				}); err != nil {
					return false
				}
				out.Contexts = append(out.Contexts, ctx)
			}
		}
		return true
	})
	if err != nil {
		return InputConfig{}, err
	}
	if out.Version != 1 || out.Codec != BGPPathCodec {
		return InputConfig{}, fmt.Errorf("unsupported input version %d or codec %q", out.Version, out.Codec)
	}
	seen := make(map[string]bool)
	for _, ctx := range out.Contexts {
		if ctx.Name == "" || seen[ctx.Name] || len(ctx.Families) == 0 {
			return InputConfig{}, fmt.Errorf("invalid input context %q", ctx.Name)
		}
		seen[ctx.Name] = true
	}
	return out, nil
}
