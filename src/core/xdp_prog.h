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
    __u8 _pad[2];                           // Padding for alignment
    __u8 src_addr[IPV6_ADDR_LEN];           // Outer IPv6 source address
    __u8 dst_addr[IPV6_ADDR_LEN];           // Unused for H.Encaps (reserved)
    __u8 segments[MAX_SEGMENTS][IPV6_ADDR_LEN]; // SID list (up to 10 segments)
    __u16 bd_id;                            // Bridge Domain ID (for H.Encaps.L2)
    __u8 args_offset;                       // Args byte offset within SID (RFC 9433 Args.Mob.Session)
    __u8 _pad_gtp;
} __attribute__((packed));

// Capacity of the plugin_raw variant in sid_aux_entry. Mirrored on the Go
// side as bpf.SidAuxPluginRawMax.
#define SID_AUX_PLUGIN_RAW_MAX 196

// SID Function entry – generic fields (LPM trie value, kept small).
// aux_index == 0 is the sentinel for "no aux data"; action-specific fields
// (including VRF ifindex for End.T/DT*) live in sid_aux_entry variants.
struct sid_function_entry {
    __u8 action;                  // srv6_local_action enum
    __u8 flavor;                  // srv6_local_flavor enum (PSP, USP, USD)
    __u16 aux_index;              // Index into sid_aux_map (0 = no aux)
} __attribute__((packed));

// SID Auxiliary entry – action-specific fields (ARRAY map value)
// Discriminated by sid_function_entry.action.
// Max size = headend_entry (196 bytes) for End.B6/B6.Encaps policy.
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
            __u8 _pad[3];
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
        struct headend_entry b6_policy;                    // 196 bytes

        // End.T/DT4/DT6/DT46: VRF-aware FIB lookup target.
        struct {
            __u32 vrf_ifindex;
        } l3vrf;                                           // 4 bytes

        // Plugin-defined raw payload. Sized to the largest union variant so
        // that existing behavior variants remain the layout anchor. Plugin
        // code interprets this via VINBERO_PLUGIN_AUX_CAST after verifying
        // sizeof(target_type) <= sizeof(plugin_raw) at compile time.
        __u8 plugin_raw[SID_AUX_PLUGIN_RAW_MAX];
    };
} __attribute__((packed));

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
