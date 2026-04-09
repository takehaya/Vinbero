#ifndef SRV6_ENDPOINT_DECAP_H
#define SRV6_ENDPOINT_DECAP_H

#include "endpoint/srv6_endpoint_core.h"

// ========================================================================
// Decapsulation Helpers
// ========================================================================

// Decap + FIB redirect for inner IPv4.
// SL check → strip outer headers → set EtherType → FIB redirect.
// XDP_PASS is converted to XDP_DROP (packet structure changed after decap).
static __always_inline int decap_and_fib_v4(
    struct xdp_md *ctx,
    struct ipv6_sr_hdr *srh,
    __u32 fib_ifindex,
    __u16 l3_offset)
{
    if (srh->segments_left != 0)
        return XDP_PASS;

    if (srv6_decap(ctx, srh, IPPROTO_IPIP, l3_offset) != 0)
        return XDP_DROP;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_DROP;
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return XDP_DROP;

    eth->h_proto = bpf_htons(ETH_P_IP);
    STATS_INC(STATS_SRV6_END, 0);

    int action = srv6_fib_redirect_v4(ctx, iph, eth, fib_ifindex);
    return (action == XDP_PASS) ? XDP_DROP : action;
}

// Decap + FIB redirect for inner IPv6.
static __always_inline int decap_and_fib_v6(
    struct xdp_md *ctx,
    struct ipv6_sr_hdr *srh,
    __u32 fib_ifindex,
    __u16 l3_offset)
{
    if (srh->segments_left != 0)
        return XDP_PASS;

    if (srv6_decap(ctx, srh, IPPROTO_IPV6, l3_offset) != 0)
        return XDP_DROP;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_DROP;
    struct ipv6hdr *inner_ip6h = (void *)(eth + 1);
    if ((void *)(inner_ip6h + 1) > data_end) return XDP_DROP;

    STATS_INC(STATS_SRV6_END, 0);

    int action = srv6_fib_redirect(ctx, inner_ip6h, eth, fib_ifindex);
    return (action == XDP_PASS) ? XDP_DROP : action;
}

// ========================================================================
// Decapsulation Endpoint Functions (End.DX2/4/6, End.DT4/6/46)
// ========================================================================

// End.DX4: Decap to IPv4 cross-connect (RFC 8986 Section 4.6)
static __always_inline int process_end_dx4(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ipv6_sr_hdr *srh,
    struct sid_function_entry *entry,
    __u16 l3_offset)
{
    return decap_and_fib_v4(ctx, srh, ctx->ingress_ifindex, l3_offset);
}

// End.DX6: Decap to IPv6 cross-connect (RFC 8986 Section 4.5)
static __always_inline int process_end_dx6(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ipv6_sr_hdr *srh,
    struct sid_function_entry *entry,
    __u16 l3_offset)
{
    return decap_and_fib_v6(ctx, srh, ctx->ingress_ifindex, l3_offset);
}

// End.DX2: Decap to L2 cross-connect (RFC 8986 Section 4.10)
// Different pattern: strips to inner L2 frame, redirects to specified OIF.
static __always_inline int process_end_dx2(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ipv6_sr_hdr *srh,
    struct sid_function_entry *entry,
    __u16 l3_offset)
{
    if (srh->segments_left != 0) {
        DEBUG_PRINT("End.DX2: SL != 0, passing\n");
        return XDP_PASS;
    }

    if (srh->nexthdr != IPPROTO_ETHERNET) {
        DEBUG_PRINT("End.DX2: nexthdr is not Ethernet (%d)\n", srh->nexthdr);
        return XDP_DROP;
    }

    __u32 oif;
    __builtin_memcpy(&oif, entry->nexthop, sizeof(__u32));
    if (oif == 0) {
        DEBUG_PRINT("End.DX2: OIF not configured\n");
        return XDP_DROP;
    }

    int strip_len = calc_decap_strip_len(srh, l3_offset);
    if (bpf_xdp_adjust_head(ctx, strip_len)) {
        DEBUG_PRINT("End.DX2: bpf_xdp_adjust_head failed\n");
        return XDP_DROP;
    }

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *inner_eth = data;
    if ((void *)(inner_eth + 1) > data_end) {
        return XDP_DROP;
    }

    DEBUG_PRINT("End.DX2: Decapsulated, redirect to ifindex %d\n", oif);
    STATS_INC(STATS_SRV6_END, 0);
    return bpf_redirect(oif, 0);
}

// End.DT4: Decap to IPv4 with VRF table lookup (RFC 8986 Section 4.8)
static __always_inline int process_end_dt4(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ipv6_sr_hdr *srh,
    struct sid_function_entry *entry,
    __u16 l3_offset)
{
    __u32 fib_ifindex = entry->vrf_ifindex ? entry->vrf_ifindex : ctx->ingress_ifindex;
    return decap_and_fib_v4(ctx, srh, fib_ifindex, l3_offset);
}

// End.DT6: Decap to IPv6 with VRF table lookup (RFC 8986 Section 4.7)
static __always_inline int process_end_dt6(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ipv6_sr_hdr *srh,
    struct sid_function_entry *entry,
    __u16 l3_offset)
{
    __u32 fib_ifindex = entry->vrf_ifindex ? entry->vrf_ifindex : ctx->ingress_ifindex;
    return decap_and_fib_v6(ctx, srh, fib_ifindex, l3_offset);
}

// End.DT46: Dispatch to DT4 or DT6 based on inner protocol (RFC 8986 Section 4.9)
static __always_inline int process_end_dt46(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ipv6_sr_hdr *srh,
    struct sid_function_entry *entry,
    __u16 l3_offset)
{
    // Detect inner protocol and dispatch (SL check is done by callee)
    __u8 inner_proto = srh->nexthdr;

    if (inner_proto == IPPROTO_IPIP) {
        DEBUG_PRINT("End.DT46: Inner protocol is IPv4, dispatching to DT4\n");
        return process_end_dt4(ctx, ip6h, srh, entry, l3_offset);
    } else if (inner_proto == IPPROTO_IPV6) {
        DEBUG_PRINT("End.DT46: Inner protocol is IPv6, dispatching to DT6\n");
        return process_end_dt6(ctx, ip6h, srh, entry, l3_offset);
    }

    DEBUG_PRINT("End.DT46: Unsupported inner protocol %d\n", inner_proto);
    return XDP_DROP;
}

#endif // SRV6_ENDPOINT_DECAP_H
