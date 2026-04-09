#ifndef SRV6_HEADEND_UTILS_H
#define SRV6_HEADEND_UTILS_H

#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/in6.h>
#include <bpf/bpf_endian.h>
#include "core/xdp_prog.h"

// ========================================================================
// IPv6 Header Builder
// ========================================================================

// Build outer IPv6 header for SRv6 encapsulation/insertion.
// Sets version=6, traffic class=0, flow label=0, hop limit=64.
static __always_inline void build_outer_ipv6(
    struct ipv6hdr *ip6h,
    __u8 nexthdr,
    __u16 payload_len,
    const void *src_addr,
    const void *dst_addr)
{
    ip6h->version = 6;
    ip6h->priority = 0;
    ip6h->flow_lbl[0] = 0;
    ip6h->flow_lbl[1] = 0;
    ip6h->flow_lbl[2] = 0;
    ip6h->payload_len = bpf_htons(payload_len);
    ip6h->nexthdr = nexthdr;
    ip6h->hop_limit = 64;
    __builtin_memcpy(&ip6h->saddr, src_addr, sizeof(struct in6_addr));
    __builtin_memcpy(&ip6h->daddr, dst_addr, sizeof(struct in6_addr));
}

// ========================================================================
// VLAN Tag Save/Restore Helpers
// ========================================================================

// Save VLAN tag(s) between Ethernet header and L3 header.
// saved_vlan must be __u32[2] (8 bytes for up to QinQ).
static __always_inline void save_vlan_tags(
    __u32 *saved_vlan,
    void *eth,
    void *data_end,
    __u16 l3_offset)
{
    saved_vlan[0] = 0;
    saved_vlan[1] = 0;
    if (l3_offset > ETH_HLEN) {
        void *vlan_ptr = eth + ETH_HLEN;
        if (vlan_ptr + 4 <= data_end)
            __builtin_memcpy(&saved_vlan[0], vlan_ptr, 4);
        if (l3_offset > ETH_HLEN + 4 && vlan_ptr + 8 <= data_end)
            __builtin_memcpy(&saved_vlan[1], vlan_ptr + 4, 4);
    }
}

// Restore VLAN tag(s) after Ethernet header.
// Returns 0 on success, -1 on bounds failure.
static __always_inline int restore_vlan_tags(
    __u32 *saved_vlan,
    void *eth,
    void *data_end,
    __u16 l3_offset)
{
    if (l3_offset > ETH_HLEN) {
        void *vlan_ptr = eth + ETH_HLEN;
        if (vlan_ptr + 4 > data_end) return -1;
        __builtin_memcpy(vlan_ptr, &saved_vlan[0], 4);
        if (l3_offset > ETH_HLEN + 4) {
            if (vlan_ptr + 8 > data_end) return -1;
            __builtin_memcpy(vlan_ptr + 4, &saved_vlan[1], 4);
        }
    }
    return 0;
}

// ========================================================================
// Segment Copy Utilities
// ========================================================================

// Copy segments to SRH in reverse order (RFC 8754)
// Input: [S1, S2, S3] -> SRH storage: [S3, S2, S1]
// Returns 0 on success, -1 on failure
static __always_inline int copy_segments_to_srh(
    void *srh_segments,
    void *data_end,
    __u8 segments[MAX_SEGMENTS][16],
    __u8 num_segments)
{
    // Validate segment count
    if (num_segments < 1 || num_segments > MAX_SEGMENTS)
        return -1;

    // Copy segments in reverse order using unrolled loop
    // Per-iteration bounds check required for BPF verifier
    #pragma unroll
    for (__u8 i = 0; i < MAX_SEGMENTS; i++) {
        if (i < num_segments) {
            void *dst = srh_segments + (i * 16);
            // BPF verifier requires per-iteration boundary check
            if (dst + 16 > data_end)
                return -1;
            __builtin_memcpy(dst, &segments[num_segments - 1 - i], 16);
        }
    }
    return 0;
}

// Copy segments to SRH in reverse order, omitting segments[0] (Reduced SRH)
// For H.Encaps.Red: segments[0] is already in IPv6 DA, copy segments[1..N-1] reversed
// Input: [S1, S2, S3] -> SRH storage: [S3, S2] (S1 omitted)
// num_segments must be >= 2 (caller ensures this)
static __always_inline int copy_segments_to_srh_reduced(
    void *srh_segments,
    void *data_end,
    __u8 segments[MAX_SEGMENTS][16],
    __u8 num_segments)
{
    if (num_segments < 2 || num_segments > MAX_SEGMENTS)
        return -1;

    __u8 reduced_count = num_segments - 1;

    #pragma unroll
    for (__u8 i = 0; i < MAX_SEGMENTS; i++) {
        if (i < reduced_count) {
            void *dst = srh_segments + (i * 16);
            if (dst + 16 > data_end)
                return -1;
            __u8 idx = num_segments - 1 - i;
            if (idx >= MAX_SEGMENTS)
                return -1;
            __builtin_memcpy(dst, &segments[idx], 16);
        }
    }
    return 0;
}

// Copy a specific segment by index from SRH to destination
// Used by process_end to update DA with segments[new_sl]
// Returns 0 on success, -1 on failure
static __always_inline int copy_segment_by_index(
    void *dst,
    void *seg_base,
    void *data_end,
    __u8 index)
{
    // Validate index (0-9 for MAX_SEGMENTS=10)
    if (index >= MAX_SEGMENTS)
        return -1;

    // Boundary check: need to access seg_base + (index+1)*16
    if (seg_base + ((index + 1) * 16) > data_end)
        return -1;

    // Copy the segment at the specified index
    __builtin_memcpy(dst, seg_base + (index * 16), 16);
    return 0;
}

#endif // SRV6_HEADEND_UTILS_H
