#ifndef SRV6_ENCAPS_RED_H
#define SRV6_ENCAPS_RED_H

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

// H.Encaps.Red single-segment: no SRH, just outer IPv6 with nexthdr = inner_proto
static __always_inline int do_h_encaps_red_1seg(
    struct xdp_md *ctx,
    struct ethhdr *saved_eth,
    struct headend_entry *entry,
    __u8 inner_proto,
    __u16 inner_total_len)
{
    int new_headers_len = sizeof(struct ipv6hdr);

    if (bpf_xdp_adjust_head(ctx, -(new_headers_len)))
        return XDP_DROP;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *new_eth = data;
    CHECK_BOUND(new_eth, data_end, sizeof(*new_eth));

    struct ipv6hdr *outer_ip6h = (struct ipv6hdr *)(new_eth + 1);
    CHECK_BOUND(outer_ip6h, data_end, sizeof(*outer_ip6h));

    outer_ip6h->version = 6;
    outer_ip6h->priority = 0;
    outer_ip6h->flow_lbl[0] = 0;
    outer_ip6h->flow_lbl[1] = 0;
    outer_ip6h->flow_lbl[2] = 0;
    outer_ip6h->payload_len = bpf_htons(inner_total_len);
    outer_ip6h->nexthdr = inner_proto;
    outer_ip6h->hop_limit = 64;

    __builtin_memcpy(&outer_ip6h->saddr, entry->src_addr, sizeof(struct in6_addr));
    __builtin_memcpy(&outer_ip6h->daddr, &entry->segments[0], sizeof(struct in6_addr));

    __builtin_memcpy(new_eth, saved_eth, sizeof(struct ethhdr));
    new_eth->h_proto = bpf_htons(ETH_P_IPV6);

    __u32 ifindex;
    int fib_result = srv6_fib_lookup_and_update(ctx, outer_ip6h, new_eth, &ifindex, ctx->ingress_ifindex);

    switch (fib_result) {
    case FIB_RESULT_REDIRECT:
        return bpf_redirect(ifindex, 0);
    case FIB_RESULT_DROP:
        return XDP_DROP;
    default:
        return XDP_PASS;
    }
}

// H.Encaps.Red multi-segment: reduced SRH with N-1 entries (S1 omitted)
static __always_inline int do_h_encaps_red_multi(
    struct xdp_md *ctx,
    struct ethhdr *saved_eth,
    struct headend_entry *entry,
    __u8 inner_proto,
    __u16 inner_total_len)
{
    if (entry->num_segments < 2 || entry->num_segments > MAX_SEGMENTS)
        return XDP_DROP;

    __u8 reduced_count = entry->num_segments - 1;
    if (reduced_count < 1 || reduced_count > 9)
        return XDP_DROP;
    int srh_len = 8 + (16 * (int)reduced_count);
    int new_headers_len = (int)sizeof(struct ipv6hdr) + srh_len;

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

    outer_ip6h->version = 6;
    outer_ip6h->priority = 0;
    outer_ip6h->flow_lbl[0] = 0;
    outer_ip6h->flow_lbl[1] = 0;
    outer_ip6h->flow_lbl[2] = 0;
    outer_ip6h->payload_len = bpf_htons(srh_len + inner_total_len);
    outer_ip6h->nexthdr = IPPROTO_ROUTING;
    outer_ip6h->hop_limit = 64;

    __builtin_memcpy(&outer_ip6h->saddr, entry->src_addr, sizeof(struct in6_addr));
    __builtin_memcpy(&outer_ip6h->daddr, &entry->segments[0], sizeof(struct in6_addr));

    srh->nexthdr = inner_proto;
    srh->hdrlen = (srh_len >> 3) - 1;
    srh->type = IPV6_SRCRT_TYPE_4;
    srh->segments_left = reduced_count;
    srh->first_segment = reduced_count - 1;
    srh->flags = 0;
    srh->tag = 0;

    void *srh_segments = (void *)srh + 8;
    if (copy_segments_to_srh_reduced(srh_segments, data_end, entry->segments, entry->num_segments) != 0)
        return XDP_DROP;

    __builtin_memcpy(new_eth, saved_eth, sizeof(struct ethhdr));
    new_eth->h_proto = bpf_htons(ETH_P_IPV6);

    __u32 ifindex;
    int fib_result = srv6_fib_lookup_and_update(ctx, outer_ip6h, new_eth, &ifindex, ctx->ingress_ifindex);

    switch (fib_result) {
    case FIB_RESULT_REDIRECT:
        return bpf_redirect(ifindex, 0);
    case FIB_RESULT_DROP:
        return XDP_DROP;
    default:
        return XDP_PASS;
    }
}

// H.Encaps.Red core dispatcher (RFC 8986 Section 5.1.1)
static __always_inline int do_h_encaps_red_core(
    struct xdp_md *ctx,
    struct ethhdr *saved_eth,
    struct headend_entry *entry,
    __u8 inner_proto,
    __u16 inner_total_len)
{
    if (entry->num_segments == 1)
        return do_h_encaps_red_1seg(ctx, saved_eth, entry, inner_proto, inner_total_len);

    return do_h_encaps_red_multi(ctx, saved_eth, entry, inner_proto, inner_total_len);
}

#endif // SRV6_ENCAPS_RED_H
