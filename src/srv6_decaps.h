#ifndef SRV6_DECAPS_H
#define SRV6_DECAPS_H

#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>

#include "srv6.h"

// Calculate total headers to strip for decapsulation (Ethernet + IPv6 + SRH)
// Returns: number of bytes to strip from front
static __always_inline int calc_decap_strip_len(struct ipv6_sr_hdr *srh)
{
    // Ethernet (14 bytes) + IPv6 header (40 bytes) + SRH header (8 + hdrlen*8 bytes)
    // hdrlen is in 8-octet units, excluding first 8 bytes
    return ETH_HLEN + sizeof(struct ipv6hdr) + 8 + (srh->hdrlen * 8);
}

// Strip outer IPv6+SRH headers, expose inner packet while preserving Ethernet header
// This is the inverse operation of H.Encaps
//
// The decapsulation process:
// Before: [Ethernet][Outer IPv6][SRH][Inner IP][Payload]
// After:  [Ethernet][Inner IP][Payload]
//
// Implementation steps:
// 1. Save original Ethernet header
// 2. Strip (Ethernet + Outer IPv6 + SRH) using bpf_xdp_adjust_head(+)
// 3. Expand head by ETH_HLEN using bpf_xdp_adjust_head(-)
// 4. Restore saved Ethernet header
//
// Parameters:
//   ctx: XDP context
//   srh: Pointer to SRH (must be valid before call)
//   expected_inner_proto: Expected inner protocol (IPPROTO_IPIP or IPPROTO_IPV6)
//
// Returns: 0 on success, -1 on failure
// Note: After success, caller must re-fetch all pointers (data, data_end, eth, etc.)
static __always_inline int srv6_decap(
    struct xdp_md *ctx,
    struct ipv6_sr_hdr *srh,
    __u8 expected_inner_proto)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // 1. Validate Ethernet header access
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return -1;
    }

    // 2. Verify inner protocol matches expected
    if (srh->nexthdr != expected_inner_proto) {
        return -1;
    }

    // 3. Save original Ethernet header (MACs will be rewritten by FIB lookup)
    struct ethhdr saved_eth;
    __builtin_memcpy(&saved_eth, eth, sizeof(struct ethhdr));

    // 4. Calculate total strip length (Eth + Outer IPv6 + SRH)
    int strip_len = calc_decap_strip_len(srh);

    // 5. Shrink packet head - removes (Eth + Outer IPv6 + SRH) from front
    // After this, ctx->data points to Inner IP header
    if (bpf_xdp_adjust_head(ctx, strip_len)) {
        return -1;
    }

    // 6. Expand head to add space for Ethernet header
    // After this, ctx->data points to where we'll write the Ethernet header
    if (bpf_xdp_adjust_head(ctx, -(int)ETH_HLEN)) {
        return -1;
    }

    // 7. Re-fetch pointers after adjust_head
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    // 8. Validate we have enough space for Ethernet header
    eth = data;
    if ((void *)(eth + 1) > data_end) {
        return -1;
    }

    // 9. Restore the saved Ethernet header
    // Note: EtherType will be updated by caller (for DX4) or remains IPv6 (for DX6)
    __builtin_memcpy(eth, &saved_eth, sizeof(struct ethhdr));

    return 0;
}

#endif // SRV6_DECAPS_H
