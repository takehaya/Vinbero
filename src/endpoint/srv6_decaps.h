#ifndef SRV6_DECAPS_H
#define SRV6_DECAPS_H

#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>

#include "core/srv6.h"

// Calculate total headers to strip for decapsulation (L2 + IPv6 + SRH)
// l3_offset: distance from packet start to IPv6 header (14, 18, or 22 for VLAN)
// Returns: number of bytes to strip from front
static __always_inline int calc_decap_strip_len(struct ipv6_sr_hdr *srh, __u16 l3_offset)
{
    // L2 header (14/18/22 bytes) + IPv6 header (40 bytes) + SRH header (8 + hdrlen*8 bytes)
    return l3_offset + sizeof(struct ipv6hdr) + 8 + (srh->hdrlen * 8);
}

// Strip outer L2+IPv6+SRH headers, expose inner packet while preserving Ethernet header
// This is the inverse operation of H.Encaps
//
// The decapsulation process (VLAN-tagged example):
// Before: [Ethernet][VLAN?][Outer IPv6][SRH][Inner IP][Payload]
// After:  [Ethernet][Inner IP][Payload]
// Note: VLAN tag is part of the outer tunnel and is discarded.
//
// Parameters:
//   ctx: XDP context
//   srh: Pointer to SRH (must be valid before call)
//   expected_inner_proto: Expected inner protocol (IPPROTO_IPIP or IPPROTO_IPV6)
//   l3_offset: Distance from packet start to IPv6 header (14, 18, or 22)
//
// Returns: 0 on success, -1 on failure
// Note: After success, caller must re-fetch all pointers (data, data_end, eth, etc.)
static __always_inline int srv6_decap(
    struct xdp_md *ctx,
    struct ipv6_sr_hdr *srh,
    __u8 expected_inner_proto,
    __u16 l3_offset)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    if (srh->nexthdr != expected_inner_proto)
        return -1;

    // Save original Ethernet header (14 bytes, MACs will be rewritten by FIB)
    struct ethhdr saved_eth;
    __builtin_memcpy(&saved_eth, eth, sizeof(struct ethhdr));

    // Strip (L2 + Outer IPv6 + SRH) — includes VLAN tag if present
    int strip_len = calc_decap_strip_len(srh, l3_offset);
    if (bpf_xdp_adjust_head(ctx, strip_len))
        return -1;

    // Re-expand by ETH_HLEN (always 14 — output is untagged Ethernet)
    if (bpf_xdp_adjust_head(ctx, -(int)ETH_HLEN))
        return -1;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    __builtin_memcpy(eth, &saved_eth, sizeof(struct ethhdr));
    return 0;
}

// Decapsulate without SRH (for Reduced SRH single-segment case)
// Strips outer L2 + IPv6 header only (no SRH to strip)
// VLAN tag (if present) is discarded as part of the outer tunnel.
// Returns: 0 on success, -1 on failure
static __always_inline int srv6_decap_nosrh(
    struct xdp_md *ctx,
    __u8 expected_inner_proto,
    __u8 actual_nexthdr,
    __u16 l3_offset)
{
    if (actual_nexthdr != expected_inner_proto)
        return -1;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    struct ethhdr saved_eth;
    __builtin_memcpy(&saved_eth, eth, sizeof(struct ethhdr));

    int strip_len = l3_offset + sizeof(struct ipv6hdr);

    if (bpf_xdp_adjust_head(ctx, strip_len))
        return -1;

    // Re-expand by ETH_HLEN (always 14 — output is untagged)
    if (bpf_xdp_adjust_head(ctx, -(int)ETH_HLEN))
        return -1;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    __builtin_memcpy(eth, &saved_eth, sizeof(struct ethhdr));
    return 0;
}

// Decapsulate L2 frame without SRH
// Strips outer L2 + IPv6, exposes inner L2 frame
// Returns: 0 on success, -1 on failure
static __always_inline int srv6_decap_l2_nosrh(
    struct xdp_md *ctx,
    __u8 actual_nexthdr,
    __u16 l3_offset)
{
    if (actual_nexthdr != IPPROTO_ETHERNET)
        return -1;

    int strip_len = l3_offset + sizeof(struct ipv6hdr);
    if (bpf_xdp_adjust_head(ctx, strip_len))
        return -1;

    return 0;
}

#endif // SRV6_DECAPS_H
