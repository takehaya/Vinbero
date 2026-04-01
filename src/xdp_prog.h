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

#define MAX_SEGMENTS 10
#define IPV4_ADDR_LEN 4
#define IPV6_ADDR_LEN 16

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

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

// SID Function entry (for SRv6 Endpoint functions)
struct sid_function_entry {
    __u8 action;                  // srv6_local_action enum
    __u8 flavor;                  // srv6_local_flavor enum
    __u8 src_addr[IPV6_ADDR_LEN]; // actionSrcAddr
    __u8 dst_addr[IPV6_ADDR_LEN]; // actionDstAddr
    __u8 nexthop[IPV6_ADDR_LEN];  // Next hop address
    __u8 arg_src_offset;          // Bit offset for source in SID Args
    __u8 arg_dst_offset;          // Bit offset for destination in SID Args
    __u32 vrf_ifindex;            // VRF interface index (for End.DT4/DT6/DT46)
    __u16 bd_id;                  // Bridge Domain ID (for End.DT2)
    __u16 _pad_sid;
    __u32 bridge_ifindex;         // Bridge device ifindex (for End.DT2 FDB miss → redirect)
} __attribute__((packed));

// Key for FDB map: Bridge Domain ID + MAC address
struct fdb_key {
    __u16 bd_id;                   // Bridge Domain ID
    __u8 mac[ETH_ALEN];            // 6 bytes
} __attribute__((packed));         // 8 bytes total

// Value for FDB map: supports local and remote entries
struct fdb_entry {
    __u32 oif;                     // Local: output interface index, Remote: 0
    __u8 is_remote;                // 0=local, 1=remote (use bd_peer_map)
    __u8 _pad;
    __u16 peer_index;              // bd_peer_map index (when is_remote=1)
    __u16 bd_id;                   // BD ID for bd_peer_map lookup (when is_remote=1)
    __u8 _pad2[2];
} __attribute__((packed));         // 12 bytes total

// Headend entry (for H.Encaps, H.Insert, etc.)
struct headend_entry {
    __u8 mode;                              // srv6_headend_behavior enum
    __u8 num_segments;                      // Number of segments (1-10)
    __u8 _pad[2];                           // Padding for alignment
    __u8 src_addr[IPV6_ADDR_LEN];           // Outer IPv6 source address
    __u8 dst_addr[IPV6_ADDR_LEN];           // Unused for H.Encaps (reserved)
    __u8 segments[MAX_SEGMENTS][IPV6_ADDR_LEN]; // SID list (up to 10 segments)
    __u16 bd_id;                            // Bridge Domain ID (for H.Encaps.L2)
} __attribute__((packed));

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

// Reverse-lookup value: peer index within the BD
struct bd_peer_reverse_val {
    __u16 index;
} __attribute__((packed));

#endif // XDP_PROG_H
