package cplane

import (
	"fmt"
	"net/netip"

	"github.com/takehaya/vinbero/sdk/go/cplane/wire"
)

// Grants is what the registration granted this plugin instance: its
// capabilities, delivered families, claimed behaviors and scope. A plugin
// reads it once from Configure (guest.Grants in WASM, the native adapter's
// host otherwise) to fill in values the operator already stated at
// registration. It is fixed for the life of the instance.
//
// Grants are advisory. The host checks every declaration against the same
// registration, so a plugin that ignores or misreads them can lose its
// declarations but never gain authority.
//
// An empty slice means nothing was granted on that axis, except Families,
// where empty means every family.
type Grants struct {
	Capabilities    []string
	Families        []string
	Behaviors       []uint32
	Locators        []string
	VRFs            []string
	HeadendPrefixes []netip.Prefix
	HeadendV4Slots  []uint32
	HeadendV6Slots  []uint32
	EndpointSlots   []uint32
}

// Capability names as the registration grants them.
const (
	CapabilityHeadend   = "headend"
	CapabilityAdvertise = "advertise"
	CapabilityLocalSID  = "local_sid"
	CapabilityMUP       = "mup"
	CapabilityEVPN      = "evpn"
)

// GrantsVersion is the PluginGrants layout DecodeGrants understands.
const GrantsVersion = 1

// Has reports whether the registration granted the named capability.
func (g Grants) Has(capability string) bool {
	for _, name := range g.Capabilities {
		if name == capability {
			return true
		}
	}
	return false
}

// DecodeGrants parses the host's PluginGrants message. It accepts both packed
// and unpacked repeated integers and skips fields added by newer hosts. Empty
// input decodes to the zero Grants, which describes a registration that
// granted nothing.
func DecodeGrants(data []byte) (Grants, error) {
	var g Grants
	if len(data) == 0 {
		return g, nil
	}
	var version uint64
	var prefixes []string
	err := decodeMessage(data, func(d *wire.Decoder) bool {
		switch d.Field {
		case 1:
			if d.Type != wire.Varint {
				return false
			}
			version = d.Uint
		case 2, 3, 5, 6, 7:
			if d.Type != wire.Bytes {
				return false
			}
			value := string(d.Bytes)
			switch d.Field {
			case 2:
				g.Capabilities = append(g.Capabilities, value)
			case 3:
				g.Families = append(g.Families, value)
			case 5:
				g.Locators = append(g.Locators, value)
			case 6:
				g.VRFs = append(g.VRFs, value)
			case 7:
				prefixes = append(prefixes, value)
			}
		case 4, 8, 9, 10:
			var target *[]uint32
			switch d.Field {
			case 4:
				target = &g.Behaviors
			case 8:
				target = &g.HeadendV4Slots
			case 9:
				target = &g.HeadendV6Slots
			case 10:
				target = &g.EndpointSlots
			}
			return appendUint32s(target, d)
		}
		return true
	})
	if err != nil {
		return Grants{}, fmt.Errorf("grants: %w", err)
	}
	if version != GrantsVersion {
		return Grants{}, fmt.Errorf("grants: unsupported version %d", version)
	}
	for _, value := range prefixes {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return Grants{}, fmt.Errorf("grants: headend prefix %q: %w", value, err)
		}
		g.HeadendPrefixes = append(g.HeadendPrefixes, prefix.Masked())
	}
	return g, nil
}

// appendUint32s reads one repeated uint32 field in either wire form.
func appendUint32s(target *[]uint32, d *wire.Decoder) bool {
	switch d.Type {
	case wire.Varint:
		if d.Uint > 1<<32-1 {
			return false
		}
		*target = append(*target, uint32(d.Uint))
		return true
	case wire.Bytes:
		data := d.Bytes
		for len(data) > 0 {
			var v uint64
			var shift uint
			for {
				if len(data) == 0 || shift > 28 {
					return false
				}
				b := data[0]
				data = data[1:]
				v |= uint64(b&0x7f) << shift
				if b < 0x80 {
					break
				}
				shift += 7
			}
			if v > 1<<32-1 {
				return false
			}
			*target = append(*target, uint32(v))
		}
		return true
	default:
		return false
	}
}
