#ifndef SRV6_ENCAPS_H
#define SRV6_ENCAPS_H

#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "core/xdp_prog.h"
#include "core/xdp_map.h" // sr_policy_map, used by resolve_sr_policy (explicit, not include-order dependent)
#include "core/srv6_ecmp.h" // ecmp_flow_label (outer flow-label entropy)
#include "core/srv6.h"
#include "headend/srv6_headend_utils.h"
#include <linux/ip.h>
#include "core/srv6_fib.h"

// resolve_sr_policy applies color-based SR Policy steering (RFC 9252 §8).
// When entry->policy_id is set and sr_policy_map has a transport list for
// it, it builds an effective headend_entry in *out whose segment list is
// <transport SIDs> ++ <entry's service SID(s)> and returns out. Otherwise
// (no steering, lookup miss = withdrawn policy, or composed list too long)
// it returns entry unchanged so the route encaps to its bare service SID
// -- the fallback path. The transport is shared per policy in the map, so
// a policy change is one map write and never rewrites this route's entry.
static __always_inline struct headend_entry *resolve_sr_policy(
    struct headend_entry *entry, struct headend_entry *out)
{
    if (entry->policy_id == 0)
        return entry;
    // A malformed service SID list (num_segments out of range) must not be
    // composed: with num_segments==0 the transport alone would form a valid
    // composed entry whose service SID is missing, and that bypasses the
    // caller's num_segments check. Return the entry unchanged so do_h_encaps_*
    // validates the original count and DROPs it.
    if (entry->num_segments < 1 || entry->num_segments > MAX_SEGMENTS)
        return entry;
    __u32 pid = entry->policy_id;
    struct sr_policy_value *pol = bpf_map_lookup_elem(&sr_policy_map, &pid);
    if (!pol)
        return entry; // policy absent/withdrawn -> bare service SID
    __u8 tlen = pol->len;
    if (tlen < 1 || tlen > MAX_SEGMENTS)
        return entry;
    __u16 total = (__u16)tlen + (__u16)entry->num_segments;
    if (total < 1 || total > MAX_SEGMENTS)
        return entry; // composed list would overflow the SRH -> fall back

    __builtin_memset(out, 0, sizeof(*out));
    out->mode = entry->mode;
    out->policy_id = 0; // composed entry is terminal; never re-resolve
    out->num_segments = (__u8)total;
    __builtin_memcpy(out->src_addr, entry->src_addr, IPV6_ADDR_LEN);

    // Destination index k is constant per unrolled iteration (stack-safe);
    // the service-segment source index is a bounded variable read from the
    // entry's segment array (same idiom as copy_segments_to_srh).
    #pragma unroll
    for (__u8 k = 0; k < MAX_SEGMENTS; k++) {
        if (k < tlen) {
            __builtin_memcpy(out->segments[k], pol->segs[k], IPV6_ADDR_LEN);
        } else if (k < total) {
            __u8 sidx = k - tlen;
            if (sidx < MAX_SEGMENTS)
                __builtin_memcpy(out->segments[k], entry->segments[sidx], IPV6_ADDR_LEN);
        }
    }
    return out;
}

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

    // Build outer IPv6 header. The flow label carries the dispatcher's
    // inner flow hash (0 for End.B6.Encaps, whose dispatch does not hash).
    build_outer_ipv6(outer_ip6h,
                     no_srh ? inner_proto : IPPROTO_ROUTING,
                     srh_len + inner_total_len,
                     entry->src_addr, &entry->segments[0],
                     headend_ctx_flow_label(0));

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

// Args struct for noinline subprogram (BPF functions support max 5 register args)
struct h_encaps_args {
    __u8 inner_proto;
    bool reduced;
    __u16 inner_total_len;
    __u16 l3_offset;
};

// Noinline subprogram to limit verifier scope.
// End.B6.Encaps calls both core and red_core; inlining both into the same
// tail call target exceeds the verifier's state tracking on kernel 6.1.
static __noinline int __do_h_encaps_subprog(
    struct xdp_md *ctx, struct ethhdr *saved_eth, struct headend_entry *entry,
    struct h_encaps_args *args)
{
    return do_h_encaps_impl(ctx, saved_eth, entry, args->inner_proto,
                            args->inner_total_len, args->l3_offset, args->reduced);
}

// Inline wrappers preserving existing 6-arg signatures for callers
static __always_inline int do_h_encaps_core(
    struct xdp_md *ctx, struct ethhdr *saved_eth, struct headend_entry *entry,
    __u8 inner_proto, __u16 inner_total_len, __u16 l3_offset)
{
    struct h_encaps_args args = { inner_proto, false, inner_total_len, l3_offset };
    return __do_h_encaps_subprog(ctx, saved_eth, entry, &args);
}

static __always_inline int do_h_encaps_red_core(
    struct xdp_md *ctx, struct ethhdr *saved_eth, struct headend_entry *entry,
    __u8 inner_proto, __u16 inner_total_len, __u16 l3_offset)
{
    struct h_encaps_args args = { inner_proto, true, inner_total_len, l3_offset };
    return __do_h_encaps_subprog(ctx, saved_eth, entry, &args);
}

// ========================================================================
// IPv4/IPv6 Wrapper Functions
// ========================================================================

// H.Encaps for IPv4 (RFC 8986 Section 5.1)
static __always_inline int do_h_encaps_v4(
    struct xdp_md *ctx, struct ethhdr *eth, struct iphdr *iph,
    struct headend_entry *entry, __u16 l3_offset)
{
    struct headend_entry composed;
    entry = resolve_sr_policy(entry, &composed);
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
    struct headend_entry composed;
    entry = resolve_sr_policy(entry, &composed);
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
    struct headend_entry composed;
    entry = resolve_sr_policy(entry, &composed);
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
    struct headend_entry composed;
    entry = resolve_sr_policy(entry, &composed);
    if (entry->num_segments < 1 || entry->num_segments > MAX_SEGMENTS)
        return XDP_DROP;

    struct ethhdr saved_eth;
    __builtin_memcpy(&saved_eth, eth, sizeof(struct ethhdr));
    return do_h_encaps_red_core(ctx, &saved_eth, entry, IPPROTO_IPV6,
                                40 + bpf_ntohs(inner_ip6h->payload_len), l3_offset);
}

#endif // SRV6_ENCAPS_H
