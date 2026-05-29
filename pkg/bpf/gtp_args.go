package bpf

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// ComposeGTP4ArgsSID writes an RFC 9433 GTP4 Args.Mob.Session into baseSID at
// byte offset and returns the resulting SRv6 SID string. baseSID supplies the
// Locator:Function; bytes [offset, offset+9) are overwritten with
//
//	[gNB IPv4 (4)] [TEID big-endian (4)] [QFI&0x3F | RQI<<6 (1)]
//
// This is the userspace counterpart of args_mob_encode_gtp4 in
// src/core/srv6_gtp.h and is byte-for-byte identical to it, so a SID composed
// here decodes correctly in End.M.GTP4.E (which reads these bytes back from the
// SID destination address). The BGP MUP downlink applier uses it to turn a
// received T1ST (UE prefix + TEID + QFI + gNB endpoint) plus the interwork
// segment's locator:function into the headend's encapsulation SID.
//
// offset must be <= 7: the 9-byte Args.Mob.Session has to fit within the
// 16-byte SID. A larger offset, a non-IPv6 base, or a non-IPv4 endpoint return
// an error rather than silently truncating.
func ComposeGTP4ArgsSID(baseSID string, offset uint8, gnbIPv4 string, teid uint32, qfi, rqi uint8) (string, error) {
	if offset > 7 {
		return "", fmt.Errorf("args_offset %d exceeds 7 (9-byte GTP4 Args.Mob.Session must fit a 16-byte SID)", offset)
	}
	base, err := netip.ParseAddr(baseSID)
	if err != nil {
		return "", fmt.Errorf("parse base SID %q: %w", baseSID, err)
	}
	if !base.Is6() {
		return "", fmt.Errorf("base SID %q must be IPv6", baseSID)
	}
	gnb, err := netip.ParseAddr(gnbIPv4)
	if err != nil {
		return "", fmt.Errorf("parse gNB endpoint %q: %w", gnbIPv4, err)
	}
	if !gnb.Is4() {
		return "", fmt.Errorf("gNB endpoint %q must be IPv4", gnbIPv4)
	}

	sid := base.As16()
	v4 := gnb.As4()
	copy(sid[offset:offset+4], v4[:])
	binary.BigEndian.PutUint32(sid[offset+4:offset+8], teid)
	sid[offset+8] = (qfi & 0x3F) | ((rqi & 0x01) << 6)
	return netip.AddrFrom16(sid).String(), nil
}

// ComposeGTP6ArgsSID writes an RFC 9433 GTP6 Args.Mob.Session into baseSID at
// byte offset and returns the resulting SRv6 SID string. baseSID supplies the
// Locator:Function; bytes [offset, offset+5) are overwritten with
//
//	[TEID big-endian (4)] [QFI&0x3F | RQI<<6 (1)]
//
// Unlike GTP4 the gNB endpoint is NOT carried in the SID (a 16-byte IPv6 address
// would not fit the argument space); End.M.GTP6.E reads the outer IPv6 src/dst
// from its auxiliary entry instead, so the per-session SID encodes only TEID and
// QFI. This is the userspace counterpart of args_mob_encode_gtp6 in
// src/core/srv6_gtp.h and byte-for-byte identical to it.
//
// offset must be <= 11: the 5-byte Args.Mob.Session has to fit within the
// 16-byte SID. A larger offset or a non-IPv6 base returns an error.
func ComposeGTP6ArgsSID(baseSID string, offset uint8, teid uint32, qfi, rqi uint8) (string, error) {
	if offset > 11 {
		return "", fmt.Errorf("args_offset %d exceeds 11 (5-byte GTP6 Args.Mob.Session must fit a 16-byte SID)", offset)
	}
	base, err := netip.ParseAddr(baseSID)
	if err != nil {
		return "", fmt.Errorf("parse base SID %q: %w", baseSID, err)
	}
	if !base.Is6() {
		return "", fmt.Errorf("base SID %q must be IPv6", baseSID)
	}

	sid := base.As16()
	binary.BigEndian.PutUint32(sid[offset:offset+4], teid)
	sid[offset+4] = (qfi & 0x3F) | ((rqi & 0x01) << 6)
	return netip.AddrFrom16(sid).String(), nil
}
