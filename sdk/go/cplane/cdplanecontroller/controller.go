// Package cdplanecontroller adapts the custom Cplane/Dplane example's JSON
// configuration to shared routing and a versioned outer IPv6 source filter.
package cdplanecontroller

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"

	"github.com/takehaya/vinbero/sdk/go/cplane"
	"github.com/takehaya/vinbero/sdk/go/cplane/customcontroller"
)

type configuration struct {
	SchemaVersion int       `json:"schema_version"`
	Routing       *routing  `json:"routing"`
	Endpoint      *endpoint `json:"endpoint"`
}

type routing struct {
	Behavior        *uint32  `json:"behavior"`
	Locator         string   `json:"locator"`
	Prefix          string   `json:"prefix"`
	VRF             string   `json:"vrf"`
	Slot            uint32   `json:"slot"`
	NextHop         string   `json:"next_hop"`
	DecapVRF        string   `json:"decap_vrf"`
	HeadendPrefixes []string `json:"headend_prefixes"`
}

type endpoint struct {
	AllowedUnderlayPrefix string `json:"allowed_underlay_prefix"`
}

// New validates the entire JSON configuration before making declarations.
// Native and WASM call this same adapter; the host forwards configuration bytes.
func New(data []byte, client *cplane.Client, log func(cplane.LogLevel, string)) (*customcontroller.Controller, error) {
	config, err := decodeConfig(data)
	if err != nil {
		return nil, err
	}
	return customcontroller.NewWithConfig(config, client, log)
}

func decodeConfig(data []byte) (customcontroller.Config, error) {
	var input configuration
	var config customcontroller.Config
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return config, fmt.Errorf("configuration: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return config, fmt.Errorf("configuration: expected one JSON object")
	}
	// encoding/json accepts null for scalar fields. Reject it explicitly so
	// a misspecified policy cannot silently acquire a scalar's default value.
	tokens := json.NewDecoder(bytes.NewReader(data))
	for {
		token, err := tokens.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return config, fmt.Errorf("configuration: %w", err)
		}
		if token == nil {
			return config, fmt.Errorf("configuration: null values are not supported")
		}
	}
	if input.SchemaVersion != 1 {
		return config, fmt.Errorf("schema_version must be 1 (got %d)", input.SchemaVersion)
	}
	if input.Routing == nil {
		return config, fmt.Errorf("routing is required")
	}
	r := input.Routing
	config = customcontroller.Config{Behavior: 0xFE01, Locator: r.Locator,
		Prefix: r.Prefix, VRF: r.VRF, Slot: r.Slot, NextHop: r.NextHop, DecapVRF: r.DecapVRF}
	if r.Behavior != nil {
		if *r.Behavior == 0 || *r.Behavior > 0xffff {
			return config, fmt.Errorf("routing.behavior must be between 1 and 65535 (got %d)", *r.Behavior)
		}
		config.Behavior = *r.Behavior
	}
	for _, value := range r.HeadendPrefixes {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || !prefix.Addr().Is4() {
			return config, fmt.Errorf("routing.headend_prefixes: invalid IPv4 prefix %q", value)
		}
		config.HeadendPrefixes = append(config.HeadendPrefixes, prefix.Masked())
	}
	allocates := r.Locator != "" || r.Slot != 0
	if allocates {
		// The endpoint plugin PROG_ARRAY ABI reserves slots [32,64).
		// The host still validates ownership and the registration's narrower scope.
		if r.Locator == "" {
			return config, fmt.Errorf("routing.locator is required to allocate a SID")
		}
		if r.Slot < 32 || r.Slot >= 64 {
			return config, fmt.Errorf("routing.slot must be in [32,64) to allocate a SID (got %d)", r.Slot)
		}
		if r.DecapVRF == "" {
			return config, fmt.Errorf("routing.decap_vrf is required to allocate a SID")
		}
		if input.Endpoint == nil {
			return config, fmt.Errorf("endpoint.allowed_underlay_prefix is required to allocate a SID")
		}
	} else if input.Endpoint != nil || r.DecapVRF != "" {
		return config, fmt.Errorf("endpoint and routing.decap_vrf require routing.locator and routing.slot")
	}
	advertises := r.Prefix != "" || r.VRF != "" || r.NextHop != ""
	if advertises {
		if !allocates || r.Prefix == "" || r.VRF == "" || r.NextHop == "" {
			return config, fmt.Errorf("routing.prefix, routing.vrf and routing.next_hop must be supplied together with SID allocation")
		}
		prefix, err := netip.ParsePrefix(r.Prefix)
		if err != nil || !prefix.Addr().Is4() {
			return config, fmt.Errorf("routing.prefix: invalid IPv4 prefix %q", r.Prefix)
		}
		config.Prefix = prefix.Masked().String()
		nextHop, err := netip.ParseAddr(r.NextHop)
		if err != nil || !nextHop.Is6() || nextHop.Is4In6() || nextHop.Zone() != "" || !nextHop.IsGlobalUnicast() {
			return config, fmt.Errorf("routing.next_hop: expected a usable IPv6 address (got %q)", r.NextHop)
		}
		config.NextHop = nextHop.String()
	}
	if input.Endpoint != nil {
		prefix, err := netip.ParsePrefix(input.Endpoint.AllowedUnderlayPrefix)
		if err != nil {
			return config, fmt.Errorf("endpoint.allowed_underlay_prefix: invalid IPv6 prefix %q", input.Endpoint.AllowedUnderlayPrefix)
		}
		config.AuxRaw, err = EncodeEndpointAux(prefix)
		if err != nil {
			return config, err
		}
	}
	return config, nil
}

// EncodeEndpointAux encodes layout version 1, followed at offset 8 by the
// SDK's vinbero_ipv6_prefix_t (prefix length, seven padding bytes, address).
// All integer fields are bytes, so this layout is independent of host endian.
func EncodeEndpointAux(prefix netip.Prefix) ([]byte, error) {
	if !prefix.IsValid() || !prefix.Addr().Is6() || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" {
		return nil, fmt.Errorf("endpoint.allowed_underlay_prefix: expected an IPv6 prefix (got %q)", prefix)
	}
	prefix = prefix.Masked()
	aux := make([]byte, 32)
	aux[0], aux[8] = 1, byte(prefix.Bits())
	address := prefix.Addr().As16()
	copy(aux[16:], address[:])
	return aux, nil
}
