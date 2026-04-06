#ifndef XDP_MAP_H
#define XDP_MAP_H
#include <linux/types.h>

#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/in.h>

#include "xdp_prog.h"

// SID Function map (IPv6 LPM Trie)
// Key: IPv6 prefix (trigger_prefix)
// Value: SID function configuration
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_key_v6);
    __type(value, struct sid_function_entry);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} sid_function_map SEC(".maps");

// Headend v4 map (IPv4 LPM Trie)
// Key: IPv4 prefix (trigger_prefix)
// Value: Headend configuration
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_key_v4);
    __type(value, struct headend_entry);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} headend_v4_map SEC(".maps");

// Headend v6 map (IPv6 LPM Trie)
// Key: IPv6 prefix (trigger_prefix)
// Value: Headend configuration
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_key_v6);
    __type(value, struct headend_entry);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} headend_v6_map SEC(".maps");

// End.B6 policy map (IPv6 LPM Trie)
// Key: IPv6 prefix (same trigger_prefix as sid_function_map)
// Value: Policy headend config (segments, src_addr, mode) for End.B6/End.B6.Encaps
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_key_v6);
    __type(value, struct headend_entry);
    __uint(max_entries, 256);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} end_b6_policy_map SEC(".maps");

// Headend L2 map (Hash)
// Key: VLAN ID (future: consider Bridge Domain with ifindex+VLAN)
// Value: Headend configuration (H.Encaps.L2)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct headend_l2_key);
    __type(value, struct headend_entry);
    __uint(max_entries, 1024);
} headend_l2_map SEC(".maps");

// FDB map (Hash) for End.DT2 L2VPN forwarding database
// Key: Bridge Domain ID + MAC address
// Value: output interface + flags
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct fdb_key);
    __type(value, struct fdb_entry);
    __uint(max_entries, 8192);
} fdb_map SEC(".maps");

// BD Peer map (Hash) for P2MP BUM flooding
// Key: Bridge Domain ID + peer index
// Value: headend_entry (SRv6 encap info for reaching that PE)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct bd_peer_key);
    __type(value, struct headend_entry);
    __uint(max_entries, 1024);
} bd_peer_map SEC(".maps");

// BD Peer reverse map: {bd_id, src_addr} → peer_index
// Populated by userspace alongside bd_peer_map.
// Used by End.DT2 for O(1) peer_index resolution during remote MAC learning.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct bd_peer_reverse_key);
    __type(value, struct bd_peer_reverse_val);
    __uint(max_entries, 1024);
} bd_peer_reverse_map SEC(".maps");

// https://github.com/cloudflare/xdpcap
// struct bpf_map_def SEC("maps") xdpcap_hook = XDPCAP_HOOK();
struct xdpcap_hook {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 5);
} xdpcap_hook SEC(".maps");

#endif // XDP_MAP_H
