#ifndef XDP_MAP_H
#define XDP_MAP_H
#include <linux/types.h>

#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/in.h>

#include "core/xdp_prog.h"
#include "core/srv6.h"  // struct aux_owner (paired with sid_aux_map persistence)

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

// aux_owner_map: per-idx owner tag for sid_aux_map. ARRAY map paired with
// sid_aux_map (same key=u32 idx, same max_entries) so the userspace
// allocator can persist owner identity across daemon restart. Key 0 is
// the "no aux" sentinel and never written.
//
// value layout matches struct aux_owner in src/core/srv6.h. Keep size
// at 64 bytes -- long enough for "plugin:v1:headend_v4:65535" plus a
// null terminator and rounded to a cache-friendly boundary.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct aux_owner));
    __uint(max_entries, 512);
} aux_owner_map SEC(".maps");

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

// MUP uplink F-TEID map (LPM Trie) for BGP MUP T2ST (draft-mpmz-bess-mup-safi).
// Key: {prefixlen, instance, outer GTP-U dst IPv4, TEID}. Value: headend_entry
// holding the direct SID segment list. The H.M.GTP4.D_TEID behavior, gated by a
// headend_v4_map entry on the N3/UPF endpoint prefix, parses the GTP-U TEID and
// looks this up to select the per-session direct SID (VPP-style F-TEID lookup).
// LPM_TRIE (not HASH) because BGP MUP T2ST carries the TEID as a variable-length
// prefix, so one route can aggregate a TEID range; the instance and endpoint
// occupy the high bits of the key so they are always fully matched before the
// TEID prefix.
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct mup_uplink_v4_key);
    __type(value, struct headend_entry);
    __uint(max_entries, 4096);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} mup_uplink_v4_map SEC(".maps");

// MUP uplink F-TEID map (LPM Trie) for BGP MUP T2ST over GTP6. IPv6 counterpart
// of mup_uplink_v4_map: keyed on {prefixlen, instance, GTP-U/IPv6 dst, TEID
// prefix}, read by the H.M.GTP6.D_TEID behavior to select the per-session
// direct SID.
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct mup_uplink_v6_key);
    __type(value, struct headend_entry);
    __uint(max_entries, 4096);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} mup_uplink_v6_map SEC(".maps");

// ========== Ingress VRF front door ==========
//
// {ifindex, vlan_id} -> vrf_id (ingress classification context). Resolved once
// at the XDP entry and carried to downstream handlers via tailcall_ctx.vrf_id.
// vrf_id 0 is the global/default VRF (underlay); tenant VRFs are 1..N. A miss
// (no entry) is distinguished from an explicit vrf 0 by the lookup returning
// NULL, so default-deny can drop unmapped ACs while explicit-vrf-0 (underlay)
// passes.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct ingress_ac_key);
    __type(value, __u32); // vrf_id
    __uint(max_entries, 4096);
} ingress_vrf_map SEC(".maps");

// Global ingress policy (single entry, key 0). Written by the control plane.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct ingress_policy);
    __uint(max_entries, 1);
} ingress_policy_map SEC(".maps");

// resolve_ingress_vrf returns INGRESS_VRF_CONTINUE (and sets *vrf_id_out) to let
// the packet proceed, or an XDP action (XDP_DROP / XDP_PASS) when the AC is
// unmapped under default-deny. The front-door hash lookup is skipped unless the
// policy is enabled, so the unconfigured path costs only one ARRAY lookup and
// does not double the per-packet {ifindex,vlan} hashing that try_l2_headend
// already does. XDP actions are 0..4, so -1 is an unambiguous "continue".
#define INGRESS_VRF_CONTINUE (-1)
static __always_inline int resolve_ingress_vrf(struct xdp_md *ctx, __u16 vlan_id, __u32 *vrf_id_out)
{
    *vrf_id_out = 0; // global VRF default; written on every return path so the caller never propagates a stale vrf_id
    __u32 pkey = 0;
    struct ingress_policy *pol = bpf_map_lookup_elem(&ingress_policy_map, &pkey);
    if (!pol || !pol->enabled)
        return INGRESS_VRF_CONTINUE; // front door off: everything is global VRF (back-compat)

    struct ingress_ac_key key = {};
    key.ifindex = ctx->ingress_ifindex;
    key.vlan_id = vlan_id;
    __u32 *vrf = bpf_map_lookup_elem(&ingress_vrf_map, &key);
    if (vrf) {
        *vrf_id_out = *vrf; // explicit entry (vrf 0 = global VRF included)
        return INGRESS_VRF_CONTINUE;
    }
    if (pol->default_deny)
        return pol->deny_action == INGRESS_DENY_PASS ? XDP_PASS : XDP_DROP;
    return INGRESS_VRF_CONTINUE; // miss, default-deny off: global VRF (vrf 0)
}

// SR Policy map: policy_id (headend_entry.policy_id) -> transport SID list.
// HASH so a policy update / withdraw is one O(1), atomic-per-value write
// regardless of how many routes steer onto it; a missing entry is the
// "fall back to bare service SID" signal for the XDP headend. This default
// is overridable from config via settings.entries.sr_policy.capacity
// (pkg/bpf/bpf.go), like the other control maps.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct sr_policy_value);
    __uint(max_entries, 1024);
} sr_policy_map SEC(".maps");

// ========== ECMP path groups ==========
//
// See the struct comments in xdp_prog.h for the three-map split. Defaults
// are overridable from config via settings.entries (pkg/bpf/bpf.go).

// group_id -> path count + weights. HASH so an update is one atomic
// whole-value replace and a withdrawn group is a clean miss.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct ecmp_group_info);
    __uint(max_entries, 4096);
} ecmp_group_map SEC(".maps");

// {group_id, path_index} -> one full path. Per-path values so the control
// plane can replace a single path atomically (RCU) without touching its
// siblings.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct ecmp_path_key);
    __type(value, struct headend_entry);
    __uint(max_entries, 32768);
} ecmp_path_map SEC(".maps");

// group_id -> liveness bitmap (bit i = path i up). Written only by the
// userspace prober; a miss means "no prober configured" and fails open to
// all-paths-live. Kept separate from ecmp_group_map so the prober's writes
// never race the control plane's group rewrites, and HASH (not ARRAY) so a
// userspace update is a contractually atomic value replace.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4096);
} ecmp_live_map SEC(".maps");

// Per-entry owner-tag tables, paired with sid_function_map / headend_v4_map /
// headend_v6_map. The keys match the corresponding main map's key type so
// userspace can read/write the owner alongside each entry. HASH (not
// LPM_TRIE) because we look up exact entries, not longest-prefix matches.
// Value matches struct aux_owner -- a 64-byte null-terminated tag like
// "rpc:v1" or "bgp:v1:asn=65000:rd=65000:100". BPF programs never read
// these maps; they exist only for userspace conflict detection and
// owner-scoped flush.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct lpm_key_v6);
    __type(value, struct aux_owner);
    __uint(max_entries, 1024);
} sid_function_owner_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct lpm_key_v4);
    __type(value, struct aux_owner);
    __uint(max_entries, 1024);
} headend_v4_owner_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct lpm_key_v6);
    __type(value, struct aux_owner);
    __uint(max_entries, 1024);
} headend_v6_owner_map SEC(".maps");

// Owner tags for ECMP groups, keyed by group_id. Same userspace-only role
// as the other owner maps: conflict detection, owner-scoped flush, and
// group-id allocator persistence across daemon restart.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct aux_owner);
    __uint(max_entries, 4096);
} ecmp_group_owner_map SEC(".maps");

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

// Headend L2 PROG_ARRAY (indexed by srv6_headend_behavior; only the L2
// variants -- H_ENCAPS_L2 / H_ENCAPS_L2_RED -- are populated. Reuses
// HEADEND_PROG_MAX so plugin slots line up with L3 (16-31).
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, HEADEND_PROG_MAX);
} headend_l2_progs SEC(".maps");

// Tail call helpers (must come after map definitions they reference)
#include "core/xdp_tailcall_helpers.h"

#endif // XDP_MAP_H
