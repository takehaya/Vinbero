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

// https://github.com/cloudflare/xdpcap
// struct bpf_map_def SEC("maps") xdpcap_hook = XDPCAP_HOOK();
struct xdpcap_hook {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 5);
} xdpcap_hook SEC(".maps");

#endif // XDP_MAP_H
