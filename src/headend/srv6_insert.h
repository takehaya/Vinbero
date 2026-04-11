#ifndef SRV6_INSERT_H
#define SRV6_INSERT_H

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

// H.Insert core implementation (RFC 8986 Section 4.1)
//
// Inserts SRH into an existing IPv6 packet (no outer encapsulation).
// The original IPv6 DA is saved as the last segment in the SRH.
//
// When reduced=false (H.Insert):
//   SRH segment list: [D, SN, ..., S2, S1] (total = num_segments + 1)
//   segments_left = num_segments, first_segment = num_segments
//
// When reduced=true (H.Insert.Red):
//   SRH segment list: [D, SN, ..., S2] (S1 omitted, total = num_segments)
//   segments_left = num_segments, first_segment = num_segments - 1
//   N=1 falls back to non-reduced (caller handles this)
//
// Returns: XDP action
static __always_inline int do_h_insert_impl(
    struct xdp_md *ctx,
    struct ethhdr *saved_eth,
    __u32 *saved_vlan,
    struct ipv6hdr *saved_ip6h,
    struct headend_entry *entry,
    __u16 l3_offset,
    bool reduced)
{
    int srh_entries = reduced ? entry->num_segments : entry->num_segments + 1;
    if (srh_entries > MAX_SEGMENTS)
        return XDP_DROP;

    int srh_len = 8 + (16 * srh_entries);

    if (bpf_xdp_adjust_head(ctx, -srh_len))
        return XDP_DROP;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *new_eth = data;
    CHECK_BOUND(new_eth, data_end, sizeof(*new_eth));

    struct ipv6hdr *new_ip6h = (struct ipv6hdr *)(data + l3_offset);
    CHECK_BOUND(new_ip6h, data_end, sizeof(*new_ip6h));

    struct ipv6_sr_hdr *srh = (struct ipv6_sr_hdr *)((void *)new_ip6h + sizeof(*new_ip6h));
    CHECK_BOUND(srh, data_end, 40);
    CHECK_BOUND(srh, data_end, srh_len);

    // Restore L2 headers (Eth + VLAN)
    __builtin_memcpy(new_eth, saved_eth, sizeof(struct ethhdr));
    if (restore_vlan_tags(saved_vlan, (void *)new_eth, data_end, l3_offset) != 0)
        return XDP_DROP;

    // Restore and modify IPv6 header
    __builtin_memcpy(new_ip6h, saved_ip6h, sizeof(struct ipv6hdr));
    new_ip6h->nexthdr = IPPROTO_ROUTING;
    new_ip6h->payload_len = bpf_htons(bpf_ntohs(saved_ip6h->payload_len) + srh_len);
    __builtin_memcpy(&new_ip6h->daddr, &entry->segments[0], sizeof(struct in6_addr));

    // Build SRH
    srh->nexthdr = saved_ip6h->nexthdr;
    srh->hdrlen = (srh_len >> 3) - 1;
    srh->type = IPV6_SRCRT_TYPE_4;
    srh->segments_left = entry->num_segments;
    srh->first_segment = reduced ? entry->num_segments - 1 : entry->num_segments;
    srh->flags = 0;
    srh->tag = 0;

    // Write original DA at SRH segment[0]
    void *srh_segments = (void *)srh + 8;
    __builtin_memcpy(srh_segments, &saved_ip6h->daddr, 16);

    // Write policy segments at SRH segment[1..]
    int ret;
    if (reduced)
        ret = copy_segments_to_srh_reduced(srh_segments + 16, data_end,
                                            entry->segments, entry->num_segments);
    else
        ret = copy_segments_to_srh(srh_segments + 16, data_end,
                                    entry->segments, entry->num_segments);
    if (ret != 0)
        return XDP_DROP;

    // FIB lookup and redirect
    __u32 ifindex;
    int fib_result = srv6_fib_lookup_and_update(ctx, new_ip6h, new_eth, &ifindex, ctx->ingress_ifindex);

    switch (fib_result) {
    case FIB_RESULT_REDIRECT:
        return bpf_redirect(ifindex, 0);
    case FIB_RESULT_DROP:
        return XDP_DROP;
    default:
        return XDP_PASS;
    }
}

// H.Insert (non-reduced)
static __always_inline int do_h_insert_core(
    struct xdp_md *ctx,
    struct ethhdr *saved_eth,
    __u32 *saved_vlan,
    struct ipv6hdr *saved_ip6h,
    struct headend_entry *entry,
    __u16 l3_offset)
{
    return do_h_insert_impl(ctx, saved_eth, saved_vlan, saved_ip6h, entry, l3_offset, false);
}

// H.Insert.Red (reduced)
// N=1 falls back to non-reduced (SL=0 at S1 cannot restore original DA)
static __always_inline int do_h_insert_red_core(
    struct xdp_md *ctx,
    struct ethhdr *saved_eth,
    __u32 *saved_vlan,
    struct ipv6hdr *saved_ip6h,
    struct headend_entry *entry,
    __u16 l3_offset)
{
    if (entry->num_segments == 1)
        return do_h_insert_impl(ctx, saved_eth, saved_vlan, saved_ip6h, entry, l3_offset, false);

    if (entry->num_segments < 2 || entry->num_segments > MAX_SEGMENTS)
        return XDP_DROP;

    return do_h_insert_impl(ctx, saved_eth, saved_vlan, saved_ip6h, entry, l3_offset, true);
}

// ========================================================================
// Wrapper Functions (save headers, then call core)
// ========================================================================

// H.Insert for IPv6 (RFC 8986 Section 4.1)
static __always_inline int do_h_insert_v6(
    struct xdp_md *ctx,
    struct ethhdr *eth,
    struct ipv6hdr *ip6h,
    struct headend_entry *entry,
    __u16 l3_offset)
{
    if (entry->num_segments < 1 || entry->num_segments > MAX_SEGMENTS - 1)
        return XDP_DROP;

    struct ethhdr saved_eth;
    __builtin_memcpy(&saved_eth, eth, sizeof(struct ethhdr));
    __u32 saved_vlan[2];
    save_vlan_tags(saved_vlan, (void *)eth, (void *)(long)ctx->data_end, l3_offset);
    struct ipv6hdr saved_ip6h;
    __builtin_memcpy(&saved_ip6h, ip6h, sizeof(struct ipv6hdr));

    return do_h_insert_core(ctx, &saved_eth, saved_vlan, &saved_ip6h, entry, l3_offset);
}

// H.Insert.Red for IPv6 (RFC 8986 Section 4.1 + Reduced)
static __always_inline int do_h_insert_red_v6(
    struct xdp_md *ctx,
    struct ethhdr *eth,
    struct ipv6hdr *ip6h,
    struct headend_entry *entry,
    __u16 l3_offset)
{
    if (entry->num_segments < 1 || entry->num_segments > MAX_SEGMENTS)
        return XDP_DROP;

    struct ethhdr saved_eth;
    __builtin_memcpy(&saved_eth, eth, sizeof(struct ethhdr));
    __u32 saved_vlan[2];
    save_vlan_tags(saved_vlan, (void *)eth, (void *)(long)ctx->data_end, l3_offset);
    struct ipv6hdr saved_ip6h;
    __builtin_memcpy(&saved_ip6h, ip6h, sizeof(struct ipv6hdr));

    return do_h_insert_red_core(ctx, &saved_eth, saved_vlan, &saved_ip6h, entry, l3_offset);
}

#endif // SRV6_INSERT_H
