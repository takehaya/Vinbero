#ifndef SRV6_INSERT_H
#define SRV6_INSERT_H

#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "xdp_prog.h"
#include "srv6.h"
#include "srv6_headend_utils.h"
#include "srv6_fib.h"

// H.Insert core implementation (RFC 8986 Section 4.1)
//
// Inserts SRH into an existing IPv6 packet (no outer encapsulation).
// The original IPv6 DA is saved as the last segment in the SRH.
// SRH segment list: [D, SN, ..., S2, S1] (total = num_segments + 1)
// IPv6 DA = segments[0] (S1, first policy segment)
//
// Parameters:
//   ctx: XDP context
//   saved_eth: Pre-saved Ethernet header
//   saved_ip6h: Pre-saved IPv6 header (original DA, nexthdr, payload_len)
//   entry: Headend entry with policy segments (max 9 for H.Insert)
//
// Returns: XDP action
static __always_inline int do_h_insert_core(
    struct xdp_md *ctx,
    struct ethhdr *saved_eth,
    struct ipv6hdr *saved_ip6h,
    struct headend_entry *entry)
{
    // Total SRH entries = policy segments + original DA
    int total_segments = entry->num_segments + 1;
    if (total_segments > MAX_SEGMENTS)
        return XDP_DROP;

    int srh_len = 8 + (16 * total_segments);

    // Expand packet: prepend SRH space (Eth + IPv6 will be restored from saved copies)
    if (bpf_xdp_adjust_head(ctx, -srh_len)) {
        DEBUG_PRINT("H.Insert: bpf_xdp_adjust_head failed\n");
        return XDP_DROP;
    }

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *new_eth = data;
    CHECK_BOUND(new_eth, data_end, sizeof(*new_eth));

    struct ipv6hdr *new_ip6h = (struct ipv6hdr *)(new_eth + 1);
    CHECK_BOUND(new_ip6h, data_end, sizeof(*new_ip6h));

    struct ipv6_sr_hdr *srh = (struct ipv6_sr_hdr *)(new_ip6h + 1);
    // Minimum SRH size: 8 (header) + 32 (2 segments min) = 40 bytes
    CHECK_BOUND(srh, data_end, 40);
    CHECK_BOUND(srh, data_end, srh_len);

    // Restore Ethernet header
    __builtin_memcpy(new_eth, saved_eth, sizeof(struct ethhdr));

    // Restore and modify IPv6 header
    __builtin_memcpy(new_ip6h, saved_ip6h, sizeof(struct ipv6hdr));
    new_ip6h->nexthdr = IPPROTO_ROUTING;
    new_ip6h->payload_len = bpf_htons(bpf_ntohs(saved_ip6h->payload_len) + srh_len);
    __builtin_memcpy(&new_ip6h->daddr, &entry->segments[0], sizeof(struct in6_addr));

    // Build SRH: nexthdr = original IPv6 nexthdr
    srh->nexthdr = saved_ip6h->nexthdr;
    srh->hdrlen = (srh_len >> 3) - 1;
    srh->type = IPV6_SRCRT_TYPE_4;
    srh->segments_left = entry->num_segments;
    srh->first_segment = entry->num_segments;
    srh->flags = 0;
    srh->tag = 0;

    // Copy segments: [D, SN, ..., S2, S1] (original DA at index 0, policy reversed)
    void *srh_segments = (void *)srh + 8;

    // Write original DA at SRH segment[0] (bounds guaranteed by CHECK_BOUND above: 40 >= 24)
    __builtin_memcpy(srh_segments, &saved_ip6h->daddr, 16);

    // Write policy segments at SRH segment[1..N] using existing verified copy function
    if (copy_segments_to_srh(srh_segments + 16, data_end,
                              entry->segments, entry->num_segments) != 0) {
        DEBUG_PRINT("H.Insert: Failed to copy segments\n");
        return XDP_DROP;
    }

    // FIB lookup and redirect
    __u32 ifindex;
    int fib_result = srv6_fib_lookup_and_update(ctx, new_ip6h, new_eth, &ifindex, ctx->ingress_ifindex);

    switch (fib_result) {
    case FIB_RESULT_REDIRECT:
        DEBUG_PRINT("H.Insert: Success, redirect to ifindex %d\n", ifindex);
        return bpf_redirect(ifindex, 0);
    case FIB_RESULT_DROP:
        return XDP_DROP;
    default:
        return XDP_PASS;
    }
}

// H.Insert.Red core implementation (RFC 8986 Section 4.1 + Reduced SRH)
//
// Same as H.Insert but omits S1 (segments[0]) from the SRH.
// SRH always exists (to store original DA).
//
// N=1: Falls back to normal H.Insert (S1 in SRH needed for SL>0 processing)
// N>=2: SRH = [D, SN, ..., S2] (S1 omitted), SL=N-1
//
// Returns: XDP action
static __always_inline int do_h_insert_red_core(
    struct xdp_md *ctx,
    struct ethhdr *saved_eth,
    struct ipv6hdr *saved_ip6h,
    struct headend_entry *entry)
{
    // N=1: fallback to normal H.Insert (SL=0 at S1 cannot restore original DA)
    if (entry->num_segments == 1) {
        return do_h_insert_core(ctx, saved_eth, saved_ip6h, entry);
    }

    if (entry->num_segments < 2 || entry->num_segments > MAX_SEGMENTS)
        return XDP_DROP;

    // SRH entries = num_segments (original DA + policy segments except S1)
    int srh_entries = entry->num_segments;
    int srh_len = 8 + (16 * srh_entries);

    if (bpf_xdp_adjust_head(ctx, -srh_len)) {
        DEBUG_PRINT("H.Insert.Red: bpf_xdp_adjust_head failed\n");
        return XDP_DROP;
    }

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *new_eth = data;
    CHECK_BOUND(new_eth, data_end, sizeof(*new_eth));

    struct ipv6hdr *new_ip6h = (struct ipv6hdr *)(new_eth + 1);
    CHECK_BOUND(new_ip6h, data_end, sizeof(*new_ip6h));

    struct ipv6_sr_hdr *srh = (struct ipv6_sr_hdr *)(new_ip6h + 1);
    // Minimum SRH: 8 (header) + 32 (2 entries: DA + 1 policy seg) = 40 bytes
    CHECK_BOUND(srh, data_end, 40);
    CHECK_BOUND(srh, data_end, srh_len);

    // Restore Ethernet header
    __builtin_memcpy(new_eth, saved_eth, sizeof(struct ethhdr));

    // Restore and modify IPv6 header
    __builtin_memcpy(new_ip6h, saved_ip6h, sizeof(struct ipv6hdr));
    new_ip6h->nexthdr = IPPROTO_ROUTING;
    new_ip6h->payload_len = bpf_htons(bpf_ntohs(saved_ip6h->payload_len) + srh_len);
    __builtin_memcpy(&new_ip6h->daddr, &entry->segments[0], sizeof(struct in6_addr));

    // Build SRH: nexthdr = original IPv6 nexthdr
    srh->nexthdr = saved_ip6h->nexthdr;
    srh->hdrlen = (srh_len >> 3) - 1;
    srh->type = IPV6_SRCRT_TYPE_4;
    srh->segments_left = entry->num_segments;
    srh->first_segment = entry->num_segments - 1;
    srh->flags = 0;
    srh->tag = 0;

    // Copy segments: [D, SN, ..., S2] (S1 omitted, original DA at index 0)
    void *srh_segments = (void *)srh + 8;

    // Write original DA at SRH segment[0] (bounds guaranteed by CHECK_BOUND: 40 >= 24)
    __builtin_memcpy(srh_segments, &saved_ip6h->daddr, 16);

    // Write policy segments[1..N-1] at SRH segment[1..] using reduced copy
    if (copy_segments_to_srh_reduced(srh_segments + 16, data_end,
                                      entry->segments, entry->num_segments) != 0) {
        DEBUG_PRINT("H.Insert.Red: Failed to copy segments\n");
        return XDP_DROP;
    }

    // FIB lookup and redirect
    __u32 ifindex;
    int fib_result = srv6_fib_lookup_and_update(ctx, new_ip6h, new_eth, &ifindex, ctx->ingress_ifindex);

    switch (fib_result) {
    case FIB_RESULT_REDIRECT:
        DEBUG_PRINT("H.Insert.Red: Success, redirect to ifindex %d\n", ifindex);
        return bpf_redirect(ifindex, 0);
    case FIB_RESULT_DROP:
        return XDP_DROP;
    default:
        return XDP_PASS;
    }
}

#endif // SRV6_INSERT_H
