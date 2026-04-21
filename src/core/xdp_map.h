#ifndef XDP_MAP_H
#define XDP_MAP_H
#include <linux/types.h>

#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/in.h>

#include "core/xdp_prog.h"

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

// SID Auxiliary map (ARRAY)
// Key: u32 index (from sid_function_entry.aux_index)
// Value: Action-specific data (union, discriminated by action field)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct sid_aux_entry);
    __uint(max_entries, 512);
} sid_aux_map SEC(".maps");

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

// End.B6 policy: stored in sid_aux_map (b6_policy variant), no separate map needed.

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

// VLAN cross-connect map (Hash) for End.DX2V
// Key: table_id + VLAN ID
// Value: output interface index
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct dx2v_key);
    __type(value, struct dx2v_entry);
    __uint(max_entries, 1024);
} dx2v_map SEC(".maps");

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

// RFC 7432 Ethernet Segment master table.
// Populated by userspace via EthernetSegmentService.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct esi_key);
    __type(value, struct esi_entry);
    __uint(max_entries, 256);
} esi_map SEC(".maps");

// Peer ESI side table: (bd_id, index) → ESI. Paired with bd_peer_map.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct bd_peer_l2_ext_key);
    __type(value, struct bd_peer_l2_ext_val);
    __uint(max_entries, 1024);
} bd_peer_l2_ext_map SEC(".maps");

// Local AC source ESI side table: (ifindex, vlan_id) → ESI. Paired with headend_l2_map.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct headend_l2_key);
    __type(value, struct headend_l2_ext_val);
    __uint(max_entries, 1024);
} headend_l2_ext_map SEC(".maps");

// BD → local ES, materialised by userspace from HeadendL2.esi configuration.
// The DT2M RX DF check uses this to find "which ES does this BD attach to
// locally?" without iterating esi_map in BPF. Key is __u32-widened bd_id
// to match the rest of vinbero's BPF map-key convention.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32 /* bd_id */);
    __type(value, struct bd_local_esi_val);
    __uint(max_entries, 512);
} bd_local_esi_map SEC(".maps");

// Per-CPU scratch buffer for mid-packet editing (e.g., End.M.GTP6.D header save/restore).
// Used to work around BPF stack limit (512 bytes) by storing temporary data in map memory.
// Max size covers ETH(14) + IPv6(40) + SRH(8 + MAX_SEGMENTS*16 = 168) = 222 bytes.
#define SCRATCH_BUF_SIZE 224

struct scratch_buf {
    __u8 data[SCRATCH_BUF_SIZE];
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct scratch_buf);
    __uint(max_entries, 1);
} scratch_map SEC(".maps");

// ========== Tail Call Infrastructure ==========

#include "core/xdp_tailcall.h"

// Per-CPU context for passing data across tail calls (single element)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct tailcall_ctx);
    __uint(max_entries, 1);
} tailcall_ctx_map SEC(".maps");

// Endpoint PROG_ARRAY (localsid + nosrh unified, indexed by srv6_local_action)
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, ENDPOINT_PROG_MAX);
} sid_endpoint_progs SEC(".maps");

// Headend v4 PROG_ARRAY (indexed by srv6_headend_behavior)
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, HEADEND_PROG_MAX);
} headend_v4_progs SEC(".maps");

// Headend v6 PROG_ARRAY (indexed by srv6_headend_behavior)
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, HEADEND_PROG_MAX);
} headend_v6_progs SEC(".maps");

// Tail call helpers (must come after map definitions they reference)
#include "core/xdp_tailcall_helpers.h"

#endif // XDP_MAP_H
