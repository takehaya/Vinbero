#ifndef SRV6_ENCAPS_L2_H
#define SRV6_ENCAPS_L2_H

#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "core/xdp_prog.h"
#include "core/srv6.h"
#include "headend/srv6_headend_utils.h"
#include "core/srv6_fib.h"

// H.Encaps.L2: Prepend [Outer Eth][Outer IPv6][SRH] before the L2 frame (RFC 8986 Section 5.1)
static __noinline int do_h_encaps_l2(
    struct xdp_md *ctx,
    struct headend_entry *entry,
    __u16 l2_frame_len)
{
    if (entry->num_segments < 1 || entry->num_segments > MAX_SEGMENTS) {
        return XDP_DROP;
    }

    int srh_len = 8 + (16 * entry->num_segments);
    int new_headers_len = sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + srh_len;

    if (bpf_xdp_adjust_head(ctx, -(new_headers_len))) {
        return XDP_DROP;
    }

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *new_eth = data;
    CHECK_BOUND(new_eth, data_end, sizeof(*new_eth));

    struct ipv6hdr *outer_ip6h = (struct ipv6hdr *)(new_eth + 1);
    CHECK_BOUND(outer_ip6h, data_end, sizeof(*outer_ip6h));

    struct ipv6_sr_hdr *srh = (struct ipv6_sr_hdr *)(outer_ip6h + 1);
    CHECK_BOUND(srh, data_end, 8);
    CHECK_BOUND(srh, data_end, srh_len);

    __builtin_memset(new_eth->h_dest, 0, ETH_ALEN);
    __builtin_memset(new_eth->h_source, 0, ETH_ALEN);
    new_eth->h_proto = bpf_htons(ETH_P_IPV6);

    build_outer_ipv6(outer_ip6h, IPPROTO_ROUTING, srh_len + l2_frame_len,
                     entry->src_addr, &entry->segments[0]);

    srh->nexthdr = IPPROTO_ETHERNET;
    srh->hdrlen = (srh_len >> 3) - 1;
    srh->type = IPV6_SRCRT_TYPE_4;
    srh->segments_left = entry->num_segments - 1;
    srh->first_segment = entry->num_segments - 1;
    srh->flags = 0;
    srh->tag = 0;

    void *srh_segments = (void *)srh + 8;
    if (copy_segments_to_srh(srh_segments, data_end, entry->segments, entry->num_segments) != 0) {
        return XDP_DROP;
    }

    __u32 ifindex;
    int fib_result = srv6_fib_lookup_and_update(ctx, outer_ip6h, new_eth, &ifindex, ctx->ingress_ifindex);
    // After encap, must not return XDP_PASS (stale pointers in caller)
    int action = fib_result_to_xdp_action(fib_result, ifindex);
    return (action == XDP_PASS) ? XDP_DROP : action;
}

// H.Encaps.L2.Red single-segment: no SRH, just outer Eth + IPv6 + inner L2
static __always_inline int do_h_encaps_l2_red_1seg(
    struct xdp_md *ctx,
    struct headend_entry *entry,
    __u16 l2_frame_len)
{
    int new_headers_len = sizeof(struct ethhdr) + sizeof(struct ipv6hdr);

    if (bpf_xdp_adjust_head(ctx, -(new_headers_len)))
        return XDP_DROP;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *new_eth = data;
    CHECK_BOUND(new_eth, data_end, sizeof(*new_eth));

    struct ipv6hdr *outer_ip6h = (struct ipv6hdr *)(new_eth + 1);
    CHECK_BOUND(outer_ip6h, data_end, sizeof(*outer_ip6h));

    __builtin_memset(new_eth->h_dest, 0, ETH_ALEN);
    __builtin_memset(new_eth->h_source, 0, ETH_ALEN);
    new_eth->h_proto = bpf_htons(ETH_P_IPV6);

    build_outer_ipv6(outer_ip6h, IPPROTO_ETHERNET, l2_frame_len,
                     entry->src_addr, &entry->segments[0]);

    __u32 ifindex;
    int fib_result = srv6_fib_lookup_and_update(ctx, outer_ip6h, new_eth, &ifindex, ctx->ingress_ifindex);
    int action = fib_result_to_xdp_action(fib_result, ifindex);
    return (action == XDP_PASS) ? XDP_DROP : action;
}

// H.Encaps.L2.Red multi-segment: reduced SRH with N-1 entries
static __always_inline int do_h_encaps_l2_red_multi(
    struct xdp_md *ctx,
    struct headend_entry *entry,
    __u16 l2_frame_len)
{
    if (entry->num_segments < 2 || entry->num_segments > MAX_SEGMENTS)
        return XDP_DROP;

    // Use constant SRH sizes to help older kernel verifiers track bounds.
    // entry->num_segments is in [2, 10], so reduced_count is in [1, 9].
    __u8 reduced_count = entry->num_segments - 1;
    // Explicit re-check so verifier on kernel 6.1 knows reduced_count >= 1
    if (reduced_count < 1 || reduced_count > 9)
        return XDP_DROP;
    int srh_len = 8 + (16 * (int)reduced_count);
    int new_headers_len = (int)sizeof(struct ethhdr) + (int)sizeof(struct ipv6hdr) + srh_len;

    if (bpf_xdp_adjust_head(ctx, -(new_headers_len)))
        return XDP_DROP;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *new_eth = data;
    CHECK_BOUND(new_eth, data_end, sizeof(*new_eth));

    struct ipv6hdr *outer_ip6h = (struct ipv6hdr *)(new_eth + 1);
    CHECK_BOUND(outer_ip6h, data_end, sizeof(*outer_ip6h));

    struct ipv6_sr_hdr *srh = (struct ipv6_sr_hdr *)(outer_ip6h + 1);
    CHECK_BOUND(srh, data_end, 8);
    CHECK_BOUND(srh, data_end, srh_len);

    __builtin_memset(new_eth->h_dest, 0, ETH_ALEN);
    __builtin_memset(new_eth->h_source, 0, ETH_ALEN);
    new_eth->h_proto = bpf_htons(ETH_P_IPV6);

    build_outer_ipv6(outer_ip6h, IPPROTO_ROUTING, srh_len + l2_frame_len,
                     entry->src_addr, &entry->segments[0]);

    srh->nexthdr = IPPROTO_ETHERNET;
    srh->hdrlen = (srh_len >> 3) - 1;
    srh->type = IPV6_SRCRT_TYPE_4;
    srh->segments_left = reduced_count;
    srh->first_segment = reduced_count - 1;
    srh->flags = 0;
    srh->tag = 0;

    void *srh_segments = (void *)srh + 8;
    if (copy_segments_to_srh_reduced(srh_segments, data_end, entry->segments, entry->num_segments) != 0)
        return XDP_DROP;

    __u32 ifindex;
    int fib_result = srv6_fib_lookup_and_update(ctx, outer_ip6h, new_eth, &ifindex, ctx->ingress_ifindex);
    int action = fib_result_to_xdp_action(fib_result, ifindex);
    return (action == XDP_PASS) ? XDP_DROP : action;
}

// H.Encaps.L2.Red dispatcher
static __noinline int do_h_encaps_l2_red(
    struct xdp_md *ctx,
    struct headend_entry *entry,
    __u16 l2_frame_len)
{
    if (entry->num_segments < 1 || entry->num_segments > MAX_SEGMENTS)
        return XDP_DROP;

    if (entry->num_segments == 1)
        return do_h_encaps_l2_red_1seg(ctx, entry, l2_frame_len);

    return do_h_encaps_l2_red_multi(ctx, entry, l2_frame_len);
}

#endif // SRV6_ENCAPS_L2_H
