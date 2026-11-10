package bpf

import (
	"encoding/binary"
	"fmt"
	"net"
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

// BuildHeadendV4Key returns the headend_v4_map / headend_v4_owner_map key
// for an IPv4 trigger prefix in VRF vrfID. Host bits are cleared and a bare
// address is taken as a /32.
func BuildHeadendV4Key(vrfID uint32, cidr string) (*HeadendV4Key, error) {
	ip, prefixLen, err := ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("not an IPv4 address: %s", cidr)
	}
	key := &HeadendV4Key{Prefixlen: headendKeyVRFBits + uint32(prefixLen)}
	binary.BigEndian.PutUint32(key.Instance[:], vrfID)
	copy(key.Addr[:], ip4)
	return key, nil
}

// BuildHeadendV6Key is the IPv6 counterpart of BuildHeadendV4Key. It accepts
// the same inputs as the SID keys of sid_function_map.
func BuildHeadendV6Key(vrfID uint32, cidr string) (*HeadendV6Key, error) {
	lpm, err := buildLpmKeyV6(cidr)
	if err != nil {
		return nil, err
	}
	key := &HeadendV6Key{Prefixlen: headendKeyVRFBits + lpm.Prefixlen, Addr: lpm.Addr}
	binary.BigEndian.PutUint32(key.Instance[:], vrfID)
	return key, nil
}

// headendV4KeyPrefix splits a headend v4 key into its VRF and the trigger
// prefix in CIDR form, the inverse of BuildHeadendV4Key.
func headendV4KeyPrefix(key *HeadendV4Key) (uint32, string) {
	return binary.BigEndian.Uint32(key.Instance[:]),
		fmt.Sprintf("%s/%d", net.IP(key.Addr[:]).String(), key.Prefixlen-headendKeyVRFBits)
}

// headendV6KeyPrefix is the IPv6 counterpart of headendV4KeyPrefix.
func headendV6KeyPrefix(key *HeadendV6Key) (uint32, string) {
	return binary.BigEndian.Uint32(key.Instance[:]),
		fmt.Sprintf("%s/%d", net.IP(key.Addr[:]).String(), key.Prefixlen-headendKeyVRFBits)
}
