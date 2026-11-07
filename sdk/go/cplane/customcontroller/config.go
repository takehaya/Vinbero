package customcontroller

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/takehaya/vinbero/sdk/go/cplane"
	"github.com/takehaya/vinbero/sdk/go/cplane/jsonconfig"
)

// DefaultBehavior is used when neither the configuration nor the
// registration's behavior claim names one.
const DefaultBehavior = 0xFE01

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

// Routing is the JSON "routing" object. Every key is optional: a value the
// registration already determines is taken from its grants.
type Routing struct {
	Behavior        *uint32  `json:"behavior"`
	Locator         string   `json:"locator"`
	Prefix          string   `json:"prefix"`
	VRF             string   `json:"vrf"`
	Slot            uint32   `json:"slot"`
	NextHop         string   `json:"next_hop"`
	DecapVRF        string   `json:"decap_vrf"`
	HeadendPrefixes []string `json:"headend_prefixes"`
}

type configuration struct {
	jsonconfig.Version
	Routing *Routing `json:"routing"`
}

// DecodeConfig reads the custom-behavior JSON configuration, schema version 1,
// and completes it from the registration's grants. Empty data is the same as
// {"schema_version":1}: a receiver whose behavior and prefixes come from the
// registration needs no configuration at all.
func DecodeConfig(data []byte, grants cplane.Grants) (Config, error) {
	var input configuration
	if len(data) > 0 {
		if err := jsonconfig.Decode(data, 1, &input); err != nil {
			return Config{}, err
		}
	}
	if input.Routing == nil {
		input.Routing = &Routing{}
	}
	return input.Routing.Resolve(grants)
}

// Resolve validates the routing object and fills unset values from grants.
//
//   - behavior defaults to the registration's only claimed behavior, or to
//     DefaultBehavior when it claims none;
//   - headend_prefixes default to the IPv4 prefixes of the headend scope;
//   - a local SID is allocated when locator, slot, decap_vrf or any
//     advertisement key is given, and locator and slot default to the only
//     granted locator and endpoint slot;
//   - an advertisement is made when prefix, vrf or next_hop is given, and
//     vrf defaults to the only granted VRF.
//
// A value the configuration gives must lie within the grant on its axis
// whenever the registration grants anything there. The check is advisory:
// it reports the conflict at Configure, and the host still enforces the
// registration on every declaration.
func (r Routing) Resolve(g cplane.Grants) (Config, error) {
	var c Config
	var err error
	if c.Behavior, err = r.behavior(g.Behaviors); err != nil {
		return Config{}, err
	}
	if c.HeadendPrefixes, err = headendPrefixes(r.HeadendPrefixes, g.HeadendPrefixes); err != nil {
		return Config{}, err
	}
	advertises := r.Prefix != "" || r.VRF != "" || r.NextHop != ""
	if !advertises && r.Locator == "" && r.Slot == 0 && r.DecapVRF == "" {
		return c, nil
	}
	if c.Locator, err = pick("routing.locator", r.Locator, g.Locators, "locator"); err != nil {
		return Config{}, err
	}
	if c.Slot, err = pick("routing.slot", r.Slot, g.EndpointSlots, "endpoint slot"); err != nil {
		return Config{}, err
	}
	// The endpoint plugin PROG_ARRAY ABI reserves slots [32,64).
	if c.Slot < 32 || c.Slot >= 64 {
		return Config{}, fmt.Errorf("routing.slot must be in [32,64) to allocate a SID (got %d)", c.Slot)
	}
	if r.DecapVRF != "" {
		if len(g.VRFs) > 0 && !contains(g.VRFs, r.DecapVRF) {
			return Config{}, fmt.Errorf("routing.decap_vrf %s is outside the registration's VRFs (%s)", r.DecapVRF, strings.Join(g.VRFs, ", "))
		}
		c.DecapVRF = r.DecapVRF
	}
	if !advertises {
		return c, nil
	}
	if c.VRF, err = pick("routing.vrf", r.VRF, g.VRFs, "VRF"); err != nil {
		return Config{}, err
	}
	if r.Prefix == "" || r.NextHop == "" {
		return Config{}, fmt.Errorf("routing.prefix and routing.next_hop are both required to advertise")
	}
	prefix, err := netip.ParsePrefix(r.Prefix)
	if err != nil || !prefix.Addr().Is4() {
		return Config{}, fmt.Errorf("routing.prefix: invalid IPv4 prefix %q", r.Prefix)
	}
	c.Prefix = prefix.Masked().String()
	nextHop, err := netip.ParseAddr(r.NextHop)
	if err != nil || !nextHop.Is6() || nextHop.Is4In6() || nextHop.Zone() != "" || !nextHop.IsGlobalUnicast() {
		return Config{}, fmt.Errorf("routing.next_hop: expected a usable IPv6 address (got %q)", r.NextHop)
	}
	c.NextHop = nextHop.String()
	return c, nil
}

func (r Routing) behavior(claimed []uint32) (uint32, error) {
	names := make([]string, len(claimed))
	for i, b := range claimed {
		names[i] = fmt.Sprintf("0x%04X", b)
	}
	if r.Behavior == nil {
		switch len(claimed) {
		case 0:
			return DefaultBehavior, nil
		case 1:
			return claimed[0], nil
		default:
			return 0, fmt.Errorf("routing.behavior is required: the registration claims several behaviors (%s)", strings.Join(names, ", "))
		}
	}
	b := *r.Behavior
	if b == 0 || b > 0xffff {
		return 0, fmt.Errorf("routing.behavior must be between 1 and 65535 (got %d)", b)
	}
	if len(claimed) > 0 {
		for _, c := range claimed {
			if c == b {
				return b, nil
			}
		}
		return 0, fmt.Errorf("routing.behavior 0x%04X is not claimed by the registration (claims %s)", b, strings.Join(names, ", "))
	}
	return b, nil
}

func headendPrefixes(configured []string, granted []netip.Prefix) ([]netip.Prefix, error) {
	var scope []netip.Prefix
	var names []string
	for _, p := range granted {
		if p.Addr().Is4() {
			scope = append(scope, p)
			names = append(names, p.String())
		}
	}
	if len(configured) == 0 {
		if len(granted) > 0 && len(scope) == 0 {
			return nil, fmt.Errorf("the headend scope grants no IPv4 prefix; this controller installs IPv4 headend entries")
		}
		return scope, nil
	}
	out := make([]netip.Prefix, 0, len(configured))
	for _, value := range configured {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || !prefix.Addr().Is4() {
			return nil, fmt.Errorf("routing.headend_prefixes: invalid IPv4 prefix %q", value)
		}
		prefix = prefix.Masked()
		if len(granted) > 0 && !within(scope, prefix) {
			if len(names) == 0 {
				names = []string{"no IPv4 prefix"}
			}
			return nil, fmt.Errorf("routing.headend_prefixes: %s is outside the headend scope (%s)", prefix, strings.Join(names, ", "))
		}
		out = append(out, prefix)
	}
	return out, nil
}

// pick returns the configured value, checked against the grant, or the only
// granted value when none is configured. The zero value means unset.
func pick[T comparable](key string, value T, granted []T, what string) (T, error) {
	var zero T
	list := make([]string, len(granted))
	for i, v := range granted {
		list[i] = fmt.Sprint(v)
	}
	if value != zero {
		if len(granted) > 0 && !contains(granted, value) {
			return zero, fmt.Errorf("%s %v is outside the registration's %ss (%s)", key, value, what, strings.Join(list, ", "))
		}
		return value, nil
	}
	switch len(granted) {
	case 1:
		return granted[0], nil
	case 0:
		return zero, fmt.Errorf("%s is required: the registration grants no %s", key, what)
	default:
		return zero, fmt.Errorf("%s is required: the registration grants several %ss (%s)", key, what, strings.Join(list, ", "))
	}
}

func contains[T comparable](values []T, value T) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

func within(scope []netip.Prefix, prefix netip.Prefix) bool {
	for _, allowed := range scope {
		if prefix.Bits() >= allowed.Bits() && allowed.Contains(prefix.Addr()) {
			return true
		}
	}
	return false
}
