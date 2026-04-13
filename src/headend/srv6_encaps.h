#ifndef SRV6_ENCAPS_H
#define SRV6_ENCAPS_H

#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "core/xdp_prog.h"
#include "core/srv6.h"
#include "headend/srv6_headend_utils.h"
#include <linux/ip.h>
#include "core/srv6_fib.h"

// Unified H.Encaps / H.Encaps.Red core implementation (RFC 8986 Section 5.1)
//
// When reduced=false (H.Encaps):
//   Full SRH with N segments. segments_left = N-1, first_segment = N-1.
//
// When reduced=true (H.Encaps.Red):
//   N=1: No SRH, outer IPv6 nexthdr = inner_proto directly.
//   N>=2: Reduced SRH with N-1 entries (S1 omitted).
//         segments_left = N-1, first_segment = N-2.
//
// Returns: XDP action (XDP_REDIRECT, XDP_DROP, or XDP_PASS)
static __always_inline int do_h_encaps_impl(
    struct xdp_md *ctx,
    struct ethhdr *saved_eth,
    struct headend_entry *entry,
    __u8 inner_proto,
    __u16 inner_total_len,
    __u16 l3_offset,
    bool reduced)
{
    bool no_srh = reduced && (entry->num_segments == 1);
    int srh_entries = 0;
    int srh_len = 0;

    if (!no_srh) {
        srh_entries = reduced ? entry->num_segments - 1 : entry->num_segments;
        if (srh_entries < 1 || srh_entries > MAX_SEGMENTS)
            return XDP_DROP;
        srh_len = 8 + (16 * srh_entries);
    }

    int new_headers_len = (int)sizeof(struct ipv6hdr) + srh_len;

    // Make room for new headers, reclaiming VLAN tag space
    int vlan_len = l3_offset - ETH_HLEN;
    if (bpf_xdp_adjust_head(ctx, -(new_headers_len - vlan_len)))
        return XDP_DROP;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *new_eth = data;
    CHECK_BOUND(new_eth, data_end, sizeof(*new_eth));

    struct ipv6hdr *outer_ip6h = (struct ipv6hdr *)(new_eth + 1);
    CHECK_BOUND(outer_ip6h, data_end, sizeof(*outer_ip6h));

    // Build outer IPv6 header
    build_outer_ipv6(outer_ip6h,
                     no_srh ? inner_proto : IPPROTO_ROUTING,
                     srh_len + inner_total_len,
                     entry->src_addr, &entry->segments[0]);

    // Build SRH (if present)
    if (!no_srh) {
        struct ipv6_sr_hdr *srh = (struct ipv6_sr_hdr *)(outer_ip6h + 1);
        CHECK_BOUND(srh, data_end, 8);
        CHECK_BOUND(srh, data_end, srh_len);

        srh->nexthdr = inner_proto;
        srh->hdrlen = (srh_len >> 3) - 1;
        srh->type = IPV6_SRCRT_TYPE_4;
        srh->segments_left = reduced ? srh_entries : srh_entries - 1;
        srh->first_segment = srh_entries - 1;
        srh->flags = 0;
        srh->tag = 0;

        void *srh_segments = (void *)srh + 8;
        int ret;
        if (reduced)
            ret = copy_segments_to_srh_reduced(srh_segments, data_end,
                                               entry->segments, entry->num_segments);
        else
            ret = copy_segments_to_srh(srh_segments, data_end,
                                       entry->segments, entry->num_segments);
        if (ret != 0)
            return XDP_DROP;
    }

    // Restore Ethernet header
    __builtin_memcpy(new_eth, saved_eth, sizeof(struct ethhdr));
    new_eth->h_proto = bpf_htons(ETH_P_IPV6);

    // FIB lookup and redirect
    __u32 ifindex;
    int fib_result = srv6_fib_lookup_and_update(ctx, outer_ip6h, new_eth, &ifindex, ctx->ingress_ifindex);
    return fib_result_to_xdp_action(fib_result, ifindex);
}

// Thin wrappers preserving existing function signatures for callers
static __always_inline int do_h_encaps_core(
    struct xdp_md *ctx, struct ethhdr *saved_eth, struct headend_entry *entry,
    __u8 inner_proto, __u16 inner_total_len, __u16 l3_offset)
{
    return do_h_encaps_impl(ctx, saved_eth, entry, inner_proto, inner_total_len, l3_offset, false);
}

static __always_inline int do_h_encaps_red_core(
    struct xdp_md *ctx, struct ethhdr *saved_eth, struct headend_entry *entry,
    __u8 inner_proto, __u16 inner_total_len, __u16 l3_offset)
{
    return do_h_encaps_impl(ctx, saved_eth, entry, inner_proto, inner_total_len, l3_offset, true);
}

// ========================================================================
// IPv4/IPv6 Wrapper Functions
// ========================================================================

// H.Encaps for IPv4 (RFC 8986 Section 5.1)
static __always_inline int do_h_encaps_v4(
    struct xdp_md *ctx, struct ethhdr *eth, struct iphdr *iph,
    struct headend_entry *entry, __u16 l3_offset)
{
    if (entry->num_segments < 1 || entry->num_segments > MAX_SEGMENTS)
        return XDP_DROP;

    struct ethhdr saved_eth;
    __builtin_memcpy(&saved_eth, eth, sizeof(struct ethhdr));
    return do_h_encaps_core(ctx, &saved_eth, entry, IPPROTO_IPIP,
                            bpf_ntohs(iph->tot_len), l3_offset);
}

// H.Encaps for IPv6 (RFC 8986 Section 5.1)
static __always_inline int do_h_encaps_v6(
    struct xdp_md *ctx, struct ethhdr *eth, struct ipv6hdr *inner_ip6h,
    struct headend_entry *entry, __u16 l3_offset)
{
    if (entry->num_segments < 1 || entry->num_segments > MAX_SEGMENTS)
        return XDP_DROP;

    struct ethhdr saved_eth;
    __builtin_memcpy(&saved_eth, eth, sizeof(struct ethhdr));
    return do_h_encaps_core(ctx, &saved_eth, entry, IPPROTO_IPV6,
                            40 + bpf_ntohs(inner_ip6h->payload_len), l3_offset);
}

// H.Encaps.Red for IPv4 (RFC 8986 Section 5.1.1)
static __always_inline int do_h_encaps_red_v4(
    struct xdp_md *ctx, struct ethhdr *eth, struct iphdr *iph,
    struct headend_entry *entry, __u16 l3_offset)
{
    if (entry->num_segments < 1 || entry->num_segments > MAX_SEGMENTS)
        return XDP_DROP;

    struct ethhdr saved_eth;
    __builtin_memcpy(&saved_eth, eth, sizeof(struct ethhdr));
    return do_h_encaps_red_core(ctx, &saved_eth, entry, IPPROTO_IPIP,
                                bpf_ntohs(iph->tot_len), l3_offset);
}

// H.Encaps.Red for IPv6 (RFC 8986 Section 5.1.1)
static __always_inline int do_h_encaps_red_v6(
    struct xdp_md *ctx, struct ethhdr *eth, struct ipv6hdr *inner_ip6h,
    struct headend_entry *entry, __u16 l3_offset)
{
    if (entry->num_segments < 1 || entry->num_segments > MAX_SEGMENTS)
        return XDP_DROP;

    struct ethhdr saved_eth;
    __builtin_memcpy(&saved_eth, eth, sizeof(struct ethhdr));
    return do_h_encaps_red_core(ctx, &saved_eth, entry, IPPROTO_IPV6,
                                40 + bpf_ntohs(inner_ip6h->payload_len), l3_offset);
}

#endif // SRV6_ENCAPS_H
