#ifndef SRV6_ENDPOINT_DECAP_H
#define SRV6_ENDPOINT_DECAP_H

#include "endpoint/srv6_endpoint_core.h"

// ========================================================================
// Decapsulation Endpoint Functions (End.DX2/4/6, End.DT4/6/46)
// ========================================================================

// End.DX4: Decapsulation with IPv4 cross-connect
// RFC 8986 Section 4.6
static __always_inline int process_end_dx4(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ipv6_sr_hdr *srh,
    struct sid_function_entry *entry)
{
    // 1. RFC 8986: SL must be 0 for DX4
    if (srh->segments_left != 0) {
        DEBUG_PRINT("End.DX4: SL != 0, passing\n");
        return XDP_PASS;
    }

    // 2. Strip outer IPv6+SRH, expose inner IPv4
    if (srv6_decap(ctx, srh, IPPROTO_IPIP) != 0) {
        DEBUG_PRINT("End.DX4: Decapsulation failed\n");
        return XDP_DROP;
    }

    // 3. Re-fetch pointers after adjust_head
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // 4. Validate Ethernet + IPv4 headers
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_DROP;
    }

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return XDP_DROP;
    }

    // 5. Set EtherType to IPv4
    eth->h_proto = bpf_htons(ETH_P_IP);

    // 6. FIB lookup on inner IPv4 and redirect
    DEBUG_PRINT("End.DX4: Decapsulated, forwarding inner IPv4\n");
    STATS_INC(STATS_SRV6_END, 0);

    // After decapsulation, we must not return XDP_PASS because:
    // 1. Packet structure has changed (IPv4 instead of IPv6+SRH)
    // 2. Old pointers in caller are invalidated
    // So if FIB lookup fails (XDP_PASS), convert to XDP_DROP
    int action = srv6_fib_redirect_v4(ctx, iph, eth, ctx->ingress_ifindex);
    if (action == XDP_PASS) {
        DEBUG_PRINT("End.DX4: FIB lookup failed, dropping\n");
        return XDP_DROP;
    }
    return action;
}

// End.DX6: Decapsulation with IPv6 cross-connect
// RFC 8986 Section 4.5
static __always_inline int process_end_dx6(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ipv6_sr_hdr *srh,
    struct sid_function_entry *entry)
{
    // 1. RFC 8986: SL must be 0 for DX6
    if (srh->segments_left != 0) {
        DEBUG_PRINT("End.DX6: SL != 0, passing\n");
        return XDP_PASS;
    }

    // 2. Strip outer IPv6+SRH, expose inner IPv6
    if (srv6_decap(ctx, srh, IPPROTO_IPV6) != 0) {
        DEBUG_PRINT("End.DX6: Decapsulation failed\n");
        return XDP_DROP;
    }

    // 3. Re-fetch pointers after adjust_head
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // 4. Validate Ethernet + IPv6 headers
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_DROP;
    }

    struct ipv6hdr *inner_ip6h = (void *)(eth + 1);
    if ((void *)(inner_ip6h + 1) > data_end) {
        return XDP_DROP;
    }

    // 5. EtherType is already IPv6 (unchanged)

    // 6. FIB lookup on inner IPv6 and redirect
    DEBUG_PRINT("End.DX6: Decapsulated, forwarding inner IPv6\n");
    STATS_INC(STATS_SRV6_END, 0);

    // After decapsulation, we must not return XDP_PASS because:
    // 1. Packet structure has changed (inner IPv6 only, outer IPv6+SRH stripped)
    // 2. Old pointers in caller are invalidated
    // So if FIB lookup fails (XDP_PASS), convert to XDP_DROP
    int action = srv6_fib_redirect(ctx, inner_ip6h, eth, ctx->ingress_ifindex);
    if (action == XDP_PASS) {
        DEBUG_PRINT("End.DX6: FIB lookup failed, dropping\n");
        return XDP_DROP;
    }
    return action;
}

// End.DX2: Decapsulation with L2 cross-connect
// RFC 8986 Section 4.10
// Strips outer Ethernet + IPv6 + SRH, exposes inner L2 frame,
// and redirects to a specified output interface (OIF).
// OIF is stored as __u32 in the first 4 bytes of entry->nexthop.
static __always_inline int process_end_dx2(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ipv6_sr_hdr *srh,
    struct sid_function_entry *entry)
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

    int strip_len = calc_decap_strip_len(srh);
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

// End.DT4: Decapsulation with IPv4 table lookup
// RFC 8986 Section 4.8
// Like End.DX4 but uses VRF-aware FIB lookup via entry->vrf_ifindex
static __always_inline int process_end_dt4(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ipv6_sr_hdr *srh,
    struct sid_function_entry *entry)
{
    // 1. RFC 8986: SL must be 0 for DT4
    if (srh->segments_left != 0) {
        DEBUG_PRINT("End.DT4: SL != 0, passing\n");
        return XDP_PASS;
    }

    // 2. Strip outer IPv6+SRH, expose inner IPv4
    if (srv6_decap(ctx, srh, IPPROTO_IPIP) != 0) {
        DEBUG_PRINT("End.DT4: Decapsulation failed\n");
        return XDP_DROP;
    }

    // 3. Re-fetch pointers after adjust_head
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // 4. Validate Ethernet + IPv4 headers
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_DROP;
    }

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return XDP_DROP;
    }

    // 5. Set EtherType to IPv4
    eth->h_proto = bpf_htons(ETH_P_IP);

    // 6. FIB lookup with VRF ifindex (0 falls back to ingress ifindex)
    __u32 fib_ifindex = entry->vrf_ifindex ? entry->vrf_ifindex : ctx->ingress_ifindex;
    DEBUG_PRINT("End.DT4: Decapsulated, FIB ifindex=%d\n", fib_ifindex);
    STATS_INC(STATS_SRV6_END, 0);

    int action = srv6_fib_redirect_v4(ctx, iph, eth, fib_ifindex);
    // After decapsulation, must not return XDP_PASS
    if (action == XDP_PASS) {
        DEBUG_PRINT("End.DT4: FIB lookup failed, dropping\n");
        return XDP_DROP;
    }
    return action;
}

// End.DT6: Decapsulation with IPv6 table lookup
// RFC 8986 Section 4.7
// Like End.DX6 but uses VRF-aware FIB lookup via entry->vrf_ifindex
static __always_inline int process_end_dt6(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ipv6_sr_hdr *srh,
    struct sid_function_entry *entry)
{
    // 1. RFC 8986: SL must be 0 for DT6
    if (srh->segments_left != 0) {
        DEBUG_PRINT("End.DT6: SL != 0, passing\n");
        return XDP_PASS;
    }

    // 2. Strip outer IPv6+SRH, expose inner IPv6
    if (srv6_decap(ctx, srh, IPPROTO_IPV6) != 0) {
        DEBUG_PRINT("End.DT6: Decapsulation failed\n");
        return XDP_DROP;
    }

    // 3. Re-fetch pointers after adjust_head
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // 4. Validate Ethernet + IPv6 headers
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_DROP;
    }

    struct ipv6hdr *inner_ip6h = (void *)(eth + 1);
    if ((void *)(inner_ip6h + 1) > data_end) {
        return XDP_DROP;
    }

    // 5. EtherType is already IPv6 (unchanged)

    // 6. FIB lookup with VRF ifindex (0 falls back to ingress ifindex)
    __u32 fib_ifindex = entry->vrf_ifindex ? entry->vrf_ifindex : ctx->ingress_ifindex;
    DEBUG_PRINT("End.DT6: Decapsulated, FIB ifindex=%d\n", fib_ifindex);
    STATS_INC(STATS_SRV6_END, 0);

    int action = srv6_fib_redirect(ctx, inner_ip6h, eth, fib_ifindex);
    // After decapsulation, must not return XDP_PASS
    if (action == XDP_PASS) {
        DEBUG_PRINT("End.DT6: FIB lookup failed, dropping\n");
        return XDP_DROP;
    }
    return action;
}

// End.DT46: Decapsulation with IP (v4 or v6) table lookup
// RFC 8986 Section 4.9
// Detects inner protocol from SRH nexthdr, dispatches to DT4 or DT6
static __always_inline int process_end_dt46(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ipv6_sr_hdr *srh,
    struct sid_function_entry *entry)
{
    // Detect inner protocol and dispatch (SL check is done by callee)
    __u8 inner_proto = srh->nexthdr;

    if (inner_proto == IPPROTO_IPIP) {
        DEBUG_PRINT("End.DT46: Inner protocol is IPv4, dispatching to DT4\n");
        return process_end_dt4(ctx, ip6h, srh, entry);
    } else if (inner_proto == IPPROTO_IPV6) {
        DEBUG_PRINT("End.DT46: Inner protocol is IPv6, dispatching to DT6\n");
        return process_end_dt6(ctx, ip6h, srh, entry);
    }

    DEBUG_PRINT("End.DT46: Unsupported inner protocol %d\n", inner_proto);
    return XDP_DROP;
}

#endif // SRV6_ENDPOINT_DECAP_H
