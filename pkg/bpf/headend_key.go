package bpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// headendKeyVRFBits is the length of the vrf_id field at the front of the
// matched data of a headend key (HEADEND_KEY_VRF_BITS in xdp_prog.h). The
// VRF always matches in full, so a /p trigger prefix is stored with
// prefixlen headendKeyVRFBits + p.
const headendKeyVRFBits = 32

// headendLookupVRF is the VRF every headend entry is written to and read
// from through MapOperations. The data plane matches every packet in this
// VRF too (headend_vrf in process_l3), so the prefix-keyed API and the
// lookup agree. Writing and looking up per-VRF entries starts here.
const headendLookupVRF uint32 = 0

// ErrInvalidHeadendPrefix is returned for a trigger prefix that does not
// parse, or that belongs to the other address family than the map.
var ErrInvalidHeadendPrefix = errors.New("invalid headend trigger prefix")

// parseHeadendPrefix parses a trigger prefix of one address family: a CIDR
// or a bare address (a host prefix). Host bits are cleared. An IPv6
// headend refuses an IPv4 prefix and the other way round; an IPv4-mapped
// IPv6 address is IPv6.
func parseHeadendPrefix(cidr string, v6 bool) (netip.Prefix, error) {
	var (
		p   netip.Prefix
		err error
	)
	if strings.Contains(cidr, "/") {
		p, err = netip.ParsePrefix(cidr)
	} else {
		var a netip.Addr
		if a, err = netip.ParseAddr(cidr); err == nil && a.Zone() != "" {
			err = errors.New("zoned address")
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%w: %q is not a CIDR or IP address", ErrInvalidHeadendPrefix, cidr)
	}
	if v6 && !p.Addr().Is6() {
		return netip.Prefix{}, fmt.Errorf("%w: %q is not an IPv6 prefix", ErrInvalidHeadendPrefix, cidr)
	}
	if !v6 && !p.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("%w: %q is not an IPv4 prefix", ErrInvalidHeadendPrefix, cidr)
	}
	return p.Masked(), nil
}

// BuildHeadendV4Key returns the headend_v4_map / headend_v4_owner_map key
// for an IPv4 trigger prefix in VRF vrfID. Host bits are cleared and a bare
// address is taken as a /32. Anything that is not IPv4 is refused.
func BuildHeadendV4Key(vrfID uint32, cidr string) (*HeadendV4Key, error) {
	p, err := parseHeadendPrefix(cidr, false)
	if err != nil {
		return nil, err
	}
	key := &HeadendV4Key{Prefixlen: headendKeyVRFBits + uint32(p.Bits()), Addr: p.Addr().As4()}
	binary.BigEndian.PutUint32(key.Instance[:], vrfID)
	return key, nil
}

// BuildHeadendV6Key is the IPv6 counterpart of BuildHeadendV4Key; a bare
// address is a /128 and an IPv4 prefix or address is refused.
func BuildHeadendV6Key(vrfID uint32, cidr string) (*HeadendV6Key, error) {
	p, err := parseHeadendPrefix(cidr, true)
	if err != nil {
		return nil, err
	}
	key := &HeadendV6Key{Prefixlen: headendKeyVRFBits + uint32(p.Bits()), Addr: p.Addr().As16()}
	binary.BigEndian.PutUint32(key.Instance[:], vrfID)
	return key, nil
}

// headendV4KeyPrefix splits a headend v4 key into its VRF and the trigger
// prefix in CIDR form, the inverse of BuildHeadendV4Key.
func headendV4KeyPrefix(key *HeadendV4Key) (uint32, string) {
	return binary.BigEndian.Uint32(key.Instance[:]),
		netip.PrefixFrom(netip.AddrFrom4(key.Addr), int(key.Prefixlen-headendKeyVRFBits)).String()
}

// headendV6KeyPrefix is the IPv6 counterpart of headendV4KeyPrefix.
func headendV6KeyPrefix(key *HeadendV6Key) (uint32, string) {
	return binary.BigEndian.Uint32(key.Instance[:]),
		netip.PrefixFrom(netip.AddrFrom16(key.Addr), int(key.Prefixlen-headendKeyVRFBits)).String()
}
