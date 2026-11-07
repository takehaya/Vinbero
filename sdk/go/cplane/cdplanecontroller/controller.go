// Package cdplanecontroller adapts the custom Cplane/Dplane example's JSON
// configuration to shared routing and a versioned outer IPv6 source filter.
package cdplanecontroller

import (
	"fmt"
	"net/netip"

	"github.com/takehaya/vinbero/sdk/go/cplane"
	"github.com/takehaya/vinbero/sdk/go/cplane/customcontroller"
	"github.com/takehaya/vinbero/sdk/go/cplane/jsonconfig"
)

type configuration struct {
	jsonconfig.Version
	Routing  *customcontroller.Routing `json:"routing"`
	Endpoint *endpoint                 `json:"endpoint"`
}

type endpoint struct {
	AllowedUnderlayPrefix string `json:"allowed_underlay_prefix"`
}

// New validates the entire JSON configuration before making declarations.
// Native and WASM call this same adapter; the host forwards configuration bytes
// and the adapter's host supplies the registration's grants.
func New(data []byte, grants cplane.Grants, client *cplane.Client, log func(cplane.LogLevel, string)) (*customcontroller.Controller, error) {
	config, err := decodeConfig(data, grants)
	if err != nil {
		return nil, err
	}
	return customcontroller.NewWithConfig(config, client, log)
}

// decodeConfig shares the routing object and its grant defaults with
// customcontroller. A local SID here always carries the endpoint policy and
// a built-in decap VRF, so both are required whenever one is allocated.
func decodeConfig(data []byte, grants cplane.Grants) (customcontroller.Config, error) {
	var input configuration
	if err := jsonconfig.Decode(data, 1, &input); err != nil {
		return customcontroller.Config{}, err
	}
	if input.Routing == nil {
		return customcontroller.Config{}, fmt.Errorf("routing is required")
	}
	config, err := input.Routing.Resolve(grants)
	if err != nil {
		return customcontroller.Config{}, err
	}
	if config.Locator == "" {
		if input.Endpoint != nil {
			return customcontroller.Config{}, fmt.Errorf("endpoint requires a local SID: set routing.decap_vrf, and routing.locator and routing.slot unless the registration grants one of each")
		}
		return config, nil
	}
	if config.DecapVRF == "" {
		return customcontroller.Config{}, fmt.Errorf("routing.decap_vrf is required to allocate a SID")
	}
	if input.Endpoint == nil {
		return customcontroller.Config{}, fmt.Errorf("endpoint.allowed_underlay_prefix is required to allocate a SID")
	}
	prefix, err := netip.ParsePrefix(input.Endpoint.AllowedUnderlayPrefix)
	if err != nil {
		return customcontroller.Config{}, fmt.Errorf("endpoint.allowed_underlay_prefix: invalid IPv6 prefix %q", input.Endpoint.AllowedUnderlayPrefix)
	}
	if config.AuxRaw, err = EncodeEndpointAux(prefix); err != nil {
		return customcontroller.Config{}, err
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
