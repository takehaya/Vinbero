#ifndef XDP_PROG_H
#define XDP_PROG_H
#include <linux/types.h>

#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/in.h>

#ifdef VINBERO_DEBUG
#define DEBUG_PRINT(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define DEBUG_PRINT(fmt, ...) (void)0
#endif

// AF_INET/AF_INET6 are not available in BPF programs, define it manually
#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10
#endif

// Protocol numbers for encapsulation
#ifndef IPPROTO_IPIP
#define IPPROTO_IPIP 4   // IPv4 in IPv6
#endif

#ifndef IPPROTO_IPV6
#define IPPROTO_IPV6 41  // IPv6 in IPv6
#endif

// Boundary check macro
#define CHECK_BOUND(ptr, end, size) \
    if ((void *)(ptr) + (size) > (void *)(end)) return XDP_PASS

// Advance pointer with boundary check
#define ADVANCE_PTR(ptr, end, size, ret) \
    do { \
        if ((void *)(ptr) + (size) > (void *)(end)) return ret; \
        ptr = (void *)(ptr) + (size); \
    } while (0)

// Re-derive Ethernet + IPv6 header pointers after bpf_xdp_adjust_head.
// All packet pointers are invalidated after adjust_head; this macro
// re-fetches ctx->data/data_end, casts and bounds-checks both headers.
// Returns XDP_PASS if bounds checks fail.
#define REDERIVE_ETH_IP6(ctx, l3_off, eth, ip6h)              \
    do {                                                        \
        void *_data = (void *)(long)(ctx)->data;                \
        void *_data_end = (void *)(long)(ctx)->data_end;        \
        (eth) = (struct ethhdr *)_data;                         \
        if ((void *)((eth) + 1) > _data_end) return XDP_PASS;  \
        (ip6h) = (struct ipv6hdr *)(_data + (l3_off));          \
        if ((void *)((ip6h) + 1) > _data_end) return XDP_PASS; \
    } while (0)

// Same as REDERIVE_ETH_IP6 but for IPv4 header.
#define REDERIVE_ETH_IP4(ctx, l3_off, eth, iph)                \
    do {                                                        \
        void *_data = (void *)(long)(ctx)->data;                \
        void *_data_end = (void *)(long)(ctx)->data_end;        \
        (eth) = (struct ethhdr *)_data;                         \
        if ((void *)((eth) + 1) > _data_end) return XDP_PASS;  \
        (iph) = (struct iphdr *)(_data + (l3_off));             \
        if ((void *)((iph) + 1) > _data_end) return XDP_PASS;  \
    } while (0)

#define MAX_SEGMENTS 10
#define IPV4_ADDR_LEN 4
#define IPV6_ADDR_LEN 16

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

// VLAN header structure (802.1Q)
struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

#ifndef IPPROTO_ETHERNET
#define IPPROTO_ETHERNET 143  // Ethernet in SRv6 (RFC 8986)
#endif

// LPM key for IPv4 prefix matching
struct lpm_key_v4 {
    __u32 prefixlen;              // Prefix length (0-32)
    __u8 addr[IPV4_ADDR_LEN];     // IPv4 address (4 bytes)
} __attribute__((packed));

// LPM key for IPv6 prefix matching
struct lpm_key_v6 {
    __u32 prefixlen;              // Prefix length (0-128)
    __u8 addr[IPV6_ADDR_LEN];     // IPv6 address (16 bytes)
} __attribute__((packed));

// Key for L2 headend map (port + VLAN)
struct headend_l2_key {
    __u32 ifindex;                // Ingress port ifindex
    __u16 vlan_id;                // VLAN ID (0 = untagged)
    __u8 _pad[2];
} __attribute__((packed));

// Key for the ingress VRF front door: {port, VLAN} -> vrf_id. First-class
// ingress classification context, distinct from headend_l2_key (which resolves
// straight to an L2 encap entry). vrf_id 0 is the global/default VRF (underlay).
struct ingress_ac_key {
    __u32 ifindex;                // Ingress port ifindex
    __u16 vlan_id;                // VLAN ID (0 = untagged)
    __u8 _pad[2];
} __attribute__((packed));

// Global ingress policy (single entry, index 0). enabled gates the front-door
// lookup so the common unconfigured path skips the hash lookup. default_deny
// makes an unmapped AC handled per deny_action instead of falling into vrf 0.
#define INGRESS_DENY_DROP 0
#define INGRESS_DENY_PASS 1
struct ingress_policy {
    __u8 enabled;       // 1 = front door active (>=1 entry or default_deny set)
    __u8 default_deny;  // 1 = unmapped AC is denied instead of falling to vrf 0
    __u8 deny_action;   // INGRESS_DENY_DROP / INGRESS_DENY_PASS
    __u8 _pad;
} __attribute__((packed));

// Key for VLAN cross-connect table (End.DX2V)
struct dx2v_key {
    __u16 table_id;    // VLAN table ID (user-configured scope)
    __u16 vlan_id;     // Inner VLAN ID from decapsulated L2 frame
} __attribute__((packed));

// Value for VLAN cross-connect table (End.DX2V)
struct dx2v_entry {
    __u32 oif;         // Output interface index
} __attribute__((packed));

// Headend entry (for H.Encaps, H.Insert, etc.)
// Defined before sid_aux_entry so it can be embedded as b6_policy variant.
struct headend_entry {
    __u8 mode;                              // srv6_headend_behavior enum
    __u8 num_segments;                      // Number of segments (1-10)
    // Keep policy_id 4-byte aligned so the bpf2go-generated Go struct (which
    // cannot represent an unaligned __u32 in a packed layout) matches this C
    // layout byte-for-byte; without this pad Go inserts 2 bytes here and every
    // following field is offset by 2 across the maps.go memcpy.
    __u16 _pad_policy;
    __u32 policy_id;                        // SR Policy steering ref (0 = none)
    __u8 src_addr[IPV6_ADDR_LEN];           // Outer IPv6 source address
    __u8 dst_addr[IPV6_ADDR_LEN];           // Unused for H.Encaps (reserved)
    __u8 segments[MAX_SEGMENTS][IPV6_ADDR_LEN]; // SID list; with policy_id != 0 holds only the per-route service SID(s)
    __u16 bd_id;                            // Bridge Domain ID (for H.Encaps.L2)
    __u8 args_offset;                       // Args byte offset within SID (RFC 9433 Args.Mob.Session)
    __u8 flood_exclude;                     // 1 = skip this peer in the BUM flood (RT2 unicast End.DT2U); 0 = flooded (default: manual bd_peer / RT3 End.DT2M)
    // ECMP group escape (0 = single-path entry, exactly the pre-ECMP
    // behavior). When set, the dispatcher hashes the inner flow and swaps
    // this entry for ecmp_path_map[{group_id, selected}] before the tail
    // call; this entry's own segments then serve as the fallback path when
    // the group is momentarily unresolvable (update skew). Placed last at
    // offset 204 so the field is 4-byte aligned (see _pad_policy comment)
    // and every existing zero-initialized entry stays single-path.
    __u32 group_id;
} __attribute__((packed));

// Sentinel for headend_entry.args_offset meaning "do not patch Args.Mob.Session".
// Used by the F-TEID uplink behavior (H.M.GTP4.D_TEID): when the resolved
// mup_uplink_v4_map entry targets a plain direct segment (End.DT4), the TEID is
// only the lookup key and must not be written into the outgoing SID. A real
// offset (0..7) re-enables patching for the End.M.GTP4.E-to-UPF variant.
#define MUP_ARGS_OFFSET_NONE 0xFF

// Key for mup_uplink_v4_map (BGP MUP T2ST / F-TEID uplink lookup, draft-mpmz-bess-mup-safi).
// LPM_TRIE key: prefixlen counts MSB-first across instance (32 bits), endpoint
// (32 bits), then the TEID bits, so instance and endpoint are always fully
// matched and the TEID is matched as a *prefix*. BGP MUP T2ST carries the TEID
// as a variable-length prefix (EndpointAddressLength = 32 + TEID-bits for
// IPv4), so a single route can aggregate a TEID range. prefixlen ranges 64
// (instance + endpoint only / any TEID) .. 96 (exact TEID). The instance is the
// vrf_id resolved from the ingress AC (ingress_vrf_map, carried in
// tailcall_ctx.vrf_id; 0 = global VRF), so two VRFs can install the same
// {endpoint, TEID} without colliding. instance, endpoint and teid bytes are
// network byte order so the on-wire MSB aligns to the start of the matched prefix.
struct mup_uplink_v4_key {
    __u32 prefixlen;                // 64..96 (instance 32 + endpoint 32 + TEID prefix bits)
    __u8  instance[4];              // vrf_id, big-endian, always fully matched (0 = global VRF)
    __u8  endpoint[IPV4_ADDR_LEN];  // outer GTP-U destination (N3 / UPF endpoint), full /32
    __u8  teid[4];                  // GTP-U TEID, network byte order, MSB-aligned prefix
} __attribute__((packed));

// Key for mup_uplink_v6_map (BGP MUP T2ST / F-TEID uplink lookup over GTP6).
// IPv6 counterpart of mup_uplink_v4_key: the endpoint is the full /128 GTP-U/IPv6
// outer destination and prefixlen ranges 160 (instance + endpoint only / any
// TEID) .. 192 (exact TEID). instance, endpoint and teid bytes are network byte order so the
// on-wire MSB aligns to the start of the matched prefix.
struct mup_uplink_v6_key {
    __u32 prefixlen;                // 160..192 (instance 32 + endpoint 128 + TEID prefix bits)
    __u8  instance[4];              // vrf_id, big-endian, always fully matched (0 = global VRF)
    __u8  endpoint[IPV6_ADDR_LEN];  // outer GTP-U/IPv6 destination (N3 / UPF endpoint), full /128
    __u8  teid[4];                  // GTP-U TEID, network byte order, MSB-aligned prefix
} __attribute__((packed));

// SR Policy transport segment list, shared by every route that steers onto
// this policy (keyed by headend_entry.policy_id). The XDP headend prepends
// these transport SIDs to the route's own service SID (RFC 9252 §8); a
// lookup miss means the policy is absent/withdrawn, so the route falls back
// to its bare service SID. Written by the BGP applier, one entry per policy.
struct sr_policy_value {
    __u8 len;                                  // transport SID count (1..MAX_SEGMENTS-1)
    __u8 _pad[3];
    __u8 segs[MAX_SEGMENTS][IPV6_ADDR_LEN];    // transport SIDs (active candidate)
} __attribute__((packed));

// ========== Service programming (draft-ietf-spring-srv6-service-programming) ==========
//
// SR-unaware service proxies (End.AS / End.AD / End.AM) split each proxy
// segment into two directions: the forward direction rides the ordinary
// sid_endpoint_progs dispatch, while the return direction (service ->
// SRv6) enters through service_ingress_map keyed on the IFACE-IN
// attachment circuit. The return-side tail call uses a dedicated
// service_return_progs PROG_ARRAY indexed by the constants below, so the
// endpoint slot space and its plugin partition stay untouched.

#define SVC_RET_AS 0   // End.AS return: re-encap from the static entry below
#define SVC_RET_AD 1   // End.AD return: re-encap from ad_cache_map
#define SVC_RET_AM 2   // End.AM return: de-masquerade from the in-packet SRH
#define SERVICE_RETURN_PROG_MAX 8

// inner_type_mask bits (which payloads the IFACE-IN may carry)
#define SVC_INNER_IPV4     (1 << 0)
#define SVC_INNER_IPV6     (1 << 1)
#define SVC_INNER_ETHERNET (1 << 2)

// sid_aux_entry.service.flags bits (forward direction)
#define SVC_AUX_F_STATIC_MAC (1 << 0)  // dmac/smac pre-resolved; else FIB on inner DA

// Key for service_ingress_map: the IFACE-IN attachment circuit. Same shape
// as headend_l2_key / ingress_ac_key but a distinct type: a proxy IFACE-IN
// is a dedicated point-to-point circuit owned by exactly one proxy segment.
struct service_ingress_key {
    __u32 ifindex;                // IFACE-IN ifindex
    __u16 vlan_id;                // VLAN ID (0 = untagged)
    __u8 _pad[2];
} __attribute__((packed));

// Value for service_ingress_map. behavior selects the service_return_progs
// slot; inner_type_mask gates which ethertypes the circuit accepts (a
// mismatch is a drop -- the IFACE-IN is a dedicated circuit, not a trunk).
// encap holds the End.AS static CACHE (outer src + segment list) embedded
// directly so the return path resolves everything in one lookup and can
// hand &entry->encap straight to tailcall_ctx_write_headend; End.AD / AM
// leave it zeroed. sid records the owning proxy SID for control-plane
// cleanup and List/Get display consistency.
struct service_ingress_entry {
    __u8  behavior;               // SVC_RET_AS / SVC_RET_AD / SVC_RET_AM
    __u8  inner_type_mask;        // SVC_INNER_* bits
    __u16 _pad;
    __u8  sid[IPV6_ADDR_LEN];     // owning proxy SID
    struct headend_entry encap;   // End.AS static CACHE (offset 20, 4-byte aligned)
} __attribute__((packed));

// End.AD dynamic cache: the forward direction stores the outer IPv6 + SRH
// here (already SL-decremented and DA-updated, i.e. ready to prepend
// verbatim) and the return direction restores it. Keyed by the IFACE-IN
// circuit per the draft: the cache tracks the chain position of the one
// proxy segment bound to that circuit, not per-flow state.
#define AD_CACHE_HDR_MAX (40 + 8 + MAX_SEGMENTS * 16)  // outer IPv6 + max SRH = 208
struct ad_cache_val {
    __u64 seq;                    // seqlock: odd = a writer is mid-update.
                                  // 64-bit because the BPF v1 ISA only has
                                  // 64-bit atomic compare-and-swap.
                                  // The forward (writer) and return (reader)
                                  // directions of one circuit can run on
                                  // different CPUs, and the 208-byte hdr copy
                                  // is not atomic; a reader that observes an
                                  // even seq, copies, then re-reads the same
                                  // seq saw a consistent row, otherwise it
                                  // drops the packet instead of replaying a
                                  // torn (but still well-formed, hence
                                  // mis-delivered) header.
    __u16 hdr_len;                // valid bytes in hdr (48..AD_CACHE_HDR_MAX)
    __u8  hop_limit;              // outer hop limit at cache time (update-margin check)
    __u8  valid;                  // 0 until the first forward packet seeds the cache
    __u8  hdr[AD_CACHE_HDR_MAX];  // outer IPv6 header + SRH, flow label zeroed
    // Deliberately NOT packed: seq must be naturally aligned for the
    // atomic compare-and-swap in svc_ad_cache_seed. The field order
    // (u32, u16, u8, u8, then the byte array) already packs to 8 bytes of
    // header with no padding, so dropping packed does not change the
    // layout — it only lets the compiler see seq as 4-byte aligned.
};

// ========== ECMP path groups ==========
//
// A headend_entry whose group_id is non-zero resolves to one of up to
// ECMP_MAX_PATHS alternative paths. The group definition is split across
// three maps so each writer touches its own value atomically:
//   ecmp_group_map: group_id -> ecmp_group_info (path count + weights)
//   ecmp_path_map:  {group_id, path_index} -> headend_entry (one full path)
//   ecmp_live_map:  group_id -> __u64 liveness bitmap (prober owned)
// The dispatcher hashes the inner flow, picks a live path by weighted
// hash-modulo (UCMP-capable), and feeds the chosen entry into the ordinary
// tail-call path. A liveness flip is a single 8-byte value replace, so the
// prober reroutes flows without rewriting the group.

#define ECMP_MAX_PATHS 8
#define ECMP_GROUP_NONE 0          // headend_entry.group_id sentinel

// Group definition (control-plane owned). weight[i] == 0 marks an unused
// slot; equal weights degenerate to plain ECMP. Updates replace the whole
// value (HASH map), so num_paths and weights always change together.
struct ecmp_group_info {
    __u8  num_paths;               // 1..ECMP_MAX_PATHS
    __u8  flags;                   // reserved. bit0 is earmarked FAIL_CLOSED
                                   // (an all-dead liveness bitmap drops
                                   // instead of failing open -- needed for
                                   // single-active EVPN aliasing); flag 0
                                   // means fail-open. Other bits: future
                                   // selection algorithms.
    __u16 _pad;
    __u16 weight[ECMP_MAX_PATHS];  // per-path UCMP weight
} __attribute__((packed));

// Per-path key, same {id, index} idiom as bd_peer_key.
struct ecmp_path_key {
    __u32 group_id;
    __u32 path_index;              // 0..ECMP_MAX_PATHS-1
} __attribute__((packed));

// Capacity of the plugin_raw variant in sid_aux_entry, and the pinned size
// of the whole union. Chosen larger than every behavior variant (the
// biggest is headend_entry / b6_policy, 208 bytes) so plugin_raw is the
// layout anchor: the union stays a fixed 256 bytes and behavior variants
// can grow (up to this cap) without rippling the map value size or the
// plugin ABI. A _Static_assert below guards the invariant. Mirrored on the
// Go side as bpf.SidAuxPluginRawMax. Bumping this is a plugin ABI change
// (plugins must be recompiled).
#define SID_AUX_PLUGIN_RAW_MAX 256

// SID Function entry – generic fields (LPM trie value, kept small).
// aux_index == 0 is the sentinel for "no aux data"; action-specific fields
// (including VRF ifindex for End.T/DT*) live in sid_aux_entry variants.
struct sid_function_entry {
    __u8 action;                  // srv6_local_action enum
    __u8 flavor;                  // srv6_local_flavor enum (PSP, USP, USD)
    __u16 aux_index;              // Index into sid_aux_map (0 = no aux)
} __attribute__((packed));

// SID Auxiliary entry – action-specific fields (ARRAY map value)
// Discriminated by sid_function_entry.action. Size is pinned at
// SID_AUX_PLUGIN_RAW_MAX by the plugin_raw variant (see below), so adding
// or growing a behavior variant does not change the map value size as long
// as it stays within the cap.
struct sid_aux_entry {
    union {
        // End.X, End.DX2: nexthop address (DX2 stores OIF in first 4 bytes)
        struct {
            __u8 nexthop[IPV6_ADDR_LEN];
        } nexthop;                                         // 16 bytes

        // End.DT2: L2 bridge domain parameters
        struct {
            __u16 bd_id;
            __u16 _pad;
            __u32 bridge_ifindex;
        } l2;                                              // 8 bytes

        // End.DX2V: VLAN cross-connect table parameters
        struct {
            __u16 table_id;
            __u16 _pad;
        } dx2v;                                            // 4 bytes

        // End.M.GTP4.E: GTP-U to IPv4
        struct {
            __u8 args_offset;
            __u8 gtp_v4_src_addr[IPV4_ADDR_LEN];
            __u8 v4src_from_outer; // 1 = extract the GTP-U IPv4 source from the
                                   // outer IPv6 SA at v4src_position (RFC 9433
                                   // §6.6); 0 = use gtp_v4_src_addr. A separate
                                   // flag (not a zero sentinel) so position 0
                                   // stays expressible.
            __u8 v4src_position;   // bit offset 0..96 into the outer IPv6 SA
            __u8 _pad;
        } gtp4e;                                           // 8 bytes

        // End.M.GTP6.D: GTP-U IPv6 decode
        struct {
            __u8 args_offset;
            __u8 _pad[7];
        } gtp6d;                                           // 8 bytes

        // End.M.GTP6.E: GTP-U to IPv6
        struct {
            __u8 args_offset;
            __u8 _pad[7];
            __u8 src_addr[IPV6_ADDR_LEN];
            __u8 dst_addr[IPV6_ADDR_LEN];
        } gtp6e;                                           // 40 bytes

        // End.B6/End.B6.Encaps: policy headend configuration
        // Replaces the former end_b6_policy_map (LPM trie).
        struct headend_entry b6_policy;                    // 208 bytes

        // End.T/DT4/DT6/DT46: VRF-aware FIB lookup target.
        struct {
            __u32 vrf_ifindex;
        } l3vrf;                                           // 4 bytes

        // End.AS/AD forward direction (service programming proxy).
        // inner_type is a single SVC_INNER_* bit: the one payload type the
        // proxy segment carries (the draft's INNER-TYPE, not a mask).
        // With SVC_AUX_F_STATIC_MAC the control plane pre-resolved the
        // service MAC (draft NH-ADDR) and the IFACE-OUT source MAC, so the
        // forward path rewrites both and redirects; without it the inner
        // DA is resolved through the FIB (the operator routes it via
        // IFACE-OUT). iface_in mirrors the paired return circuit for
        // cleanup and display only — the forward path never reads it.
        struct {
            __u32 iface_out;         // OIF towards the service
            __u32 iface_in;          // paired IFACE-IN (control plane only)
            __u16 vlan_in;           // paired IFACE-IN VLAN (control plane only)
            __u8  inner_type;        // SVC_INNER_IPV4 / _IPV6 / _ETHERNET
            __u8  flags;             // SVC_AUX_F_*
            __u8  dmac[ETH_ALEN];    // service MAC, valid with STATIC_MAC
            __u8  smac[ETH_ALEN];    // IFACE-OUT source MAC, valid with STATIC_MAC
            __u8  hop_limit_margin;  // End.AD cache update margin (AS: unused)
            __u8  _pad;
        } service;                                         // 26 bytes

        // End.AN: NF-catalog metadata for the SR-aware service behind
        // this SID. The data plane never reads it (End.AN forwards
        // exactly like End); it exists so SidFunctionList doubles as the
        // service registration point for NF discovery.
        struct {
            char service_name[64];   // null-terminated ASCII
        } an_meta;                                         // 64 bytes

        // uN / uA / uT (NEXT-C-SID, RFC 9800): shift parameters. nexthop
        // sits at offset 0 with the same layout as the nexthop variant so
        // uA's classic End.X fall-through reads either view. uT reuses the
        // same aliasing the other way: it has no nexthop, so the control
        // plane writes the VRF ifindex into the leading 4 bytes and the
        // data plane reads it through the l3vrf view (uN leaves them zero,
        // which is l3vrf's ingress fallback). block_len_bytes is the
        // locator block length in bytes (LBL/8; F3216 => 4).
        struct {
            __u8 nexthop[IPV6_ADDR_LEN];
            __u8 block_len_bytes;
            __u8 _pad[3];
        } usid;                                            // 20 bytes

        // Plugin-defined raw payload. Sized larger than every behavior
        // variant so it is the union's layout anchor (pins the union size).
        // Plugin code interprets this via VINBERO_PLUGIN_AUX_CAST after
        // verifying sizeof(target_type) <= sizeof(plugin_raw) at compile time.
        __u8 plugin_raw[SID_AUX_PLUGIN_RAW_MAX];
    };
} __attribute__((packed));

// plugin_raw must remain the largest variant so the union size is pinned;
// if a behavior variant ever outgrows the cap, bump SID_AUX_PLUGIN_RAW_MAX.
_Static_assert(sizeof(struct headend_entry) <= SID_AUX_PLUGIN_RAW_MAX,
               "headend_entry must fit the sid_aux plugin_raw anchor");
// The union size is plugin ABI: adding a variant must not grow it.
_Static_assert(sizeof(struct sid_aux_entry) == SID_AUX_PLUGIN_RAW_MAX,
               "sid_aux_entry union must stay pinned at the plugin_raw size");

// Key for FDB map: Bridge Domain ID + MAC address
struct fdb_key {
    __u16 bd_id;                   // Bridge Domain ID
    __u8 mac[ETH_ALEN];            // 6 bytes
} __attribute__((packed));         // 8 bytes total

// RFC 7432 Ethernet Segment Identifier length (Type 0-5).
#define ESI_LEN 10

// Value for FDB map: supports local and remote entries
struct fdb_entry {
    __u32 oif;                     // Local: output interface index, Remote: 0
    __u8 is_remote;                // 0=local, 1=remote (use bd_peer_map)
    __u8 is_static;                // 1=static (never aged out), 0=dynamic (BPF-learned)
    __u16 peer_index;              // bd_peer_map index (when is_remote=1)
    __u16 bd_id;                   // BD ID for bd_peer_map lookup (when is_remote=1)
    __u8 _pad[2];
    __u64 last_seen;               // bpf_ktime_get_ns() timestamp (0=static entry)
    __u8 esi[ESI_LEN];             // Remote only: ES this MAC was learned from (all-zero = single-homing)
    __u8 _pad_esi[2];
} __attribute__((packed));         // 32 bytes total

// Maximum number of remote PEs per Bridge Domain for BUM flooding
#define MAX_BUM_NEXTHOPS 8

// Sentinel value for "peer index not found" (find_peer_index_by_src)
#define BD_PEER_INDEX_INVALID 0xFFFF

// Key for bd_peer_map: Bridge Domain ID + peer index
struct bd_peer_key {
    __u16 bd_id;
    __u16 index;                   // 0..MAX_BUM_NEXTHOPS-1
} __attribute__((packed));

// Value: headend_entry (reuses existing struct for segments, src_addr, etc.)

// Reverse-lookup key for bd_peer_reverse_map: {bd_id, src_addr} → peer_index
// Used by End.DT2 to resolve peer_index in O(1) instead of iterating bd_peer_map.
struct bd_peer_reverse_key {
    __u16 bd_id;
    __u8 src_addr[IPV6_ADDR_LEN];    // Remote PE source address
    __u8 _pad[2];
} __attribute__((packed));

// Reverse-lookup value: peer index + ESI the peer attaches to (all-zero = single-homing).
// Co-locating ESI here lets the receiving side do split-horizon filtering in a
// single hash lookup.
struct bd_peer_reverse_val {
    __u16 index;
    __u8 esi[ESI_LEN];
    __u8 _pad[4];
} __attribute__((packed));

// RFC 7432 Ethernet Segment master table key.
struct esi_key {
    __u8 esi[ESI_LEN];
    __u8 _pad[6];
} __attribute__((packed));

// RFC 7432 Ethernet Segment master table value.
// local_pe_src_addr is captured on EsCreate (not hard-coded via const volatile)
// so one BPF image can serve any number of SIDs without a reload.
struct esi_entry {
    __u8 local_attached;           // 1 if this PE attaches to the ES
    __u8 redundancy_mode;          // enum esi_redundancy_mode
    __u8 _pad[6];
    __u8 df_pe_src_addr[IPV6_ADDR_LEN];    // current DF (all-zero = not configured)
    __u8 local_pe_src_addr[IPV6_ADDR_LEN]; // this PE's H.Encaps.L2 source for this ES
} __attribute__((packed));

enum esi_redundancy_mode {
    ESI_REDUNDANCY_MODE_UNSPECIFIED   = 0,
    ESI_REDUNDANCY_MODE_SINGLE_HOMING = 1,
    ESI_REDUNDANCY_MODE_ALL_ACTIVE    = 2,
    ESI_REDUNDANCY_MODE_SINGLE_ACTIVE = 3,
};

// Side table: (bd_id, peer index) → peer's ESI. Keeps ESI out of
// bd_peer_map's HeadendEntry value so that struct stays shared with L3
// headend maps.
struct bd_peer_l2_ext_key {
    __u16 bd_id;
    __u16 index;
} __attribute__((packed));

struct bd_peer_l2_ext_val {
    __u8 esi[ESI_LEN];
    __u8 _pad[6];
} __attribute__((packed));

// Side table: (ifindex, vlan_id) → local AC's source ESI.
// Reuses headend_l2_key so Go-side updates parallel headend_l2_map.
struct headend_l2_ext_val {
    __u8 esi[ESI_LEN];
    __u8 _pad[6];
} __attribute__((packed));

// BD → local ES lookup for DF judgement. Populated from HeadendL2 side-table
// whenever an HeadendL2 carries an ESI; BPF reads this on the DT2M RX path
// to decide "is this PE the DF for this BD's local ES?". One local ES per BD
// today; multi-ES-per-BD is a future extension.
struct bd_local_esi_val {
    __u8 esi[ESI_LEN];
    __u8 _pad[6];
} __attribute__((packed));

#endif // XDP_PROG_H
