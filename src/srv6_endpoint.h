#ifndef SRV6_ENDPOINT_H
#define SRV6_ENDPOINT_H

#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

#include "xdp_prog.h"
#include "srv6.h"
#include "srv6_headend_utils.h"
#include "srv6_fib.h"
#include "srv6_decaps.h"
#include "xdp_stats.h"

// Endpoint processing context - shared by all endpoint functions
struct endpoint_ctx {
    struct xdp_md *ctx;
    struct ipv6hdr *ip6h;
    struct ipv6_sr_hdr *srh;
    struct sid_function_entry *entry;
    void *data_end;
    __u8 segments_left;
    __u8 new_sl;
};

// Initialize endpoint context and perform common SL checks
// Returns:
//   0: Success, context initialized
//  -1: SL=0, pass to upper layer (not an error)
//  -2: Invalid SL, should drop
static __always_inline int endpoint_init(
    struct endpoint_ctx *ectx,
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ipv6_sr_hdr *srh,
    struct sid_function_entry *entry)
{
    ectx->ctx = ctx;
    ectx->ip6h = ip6h;
    ectx->srh = srh;
    ectx->entry = entry;
    ectx->data_end = (void *)(long)ctx->data_end;
    ectx->segments_left = srh->segments_left;

    // RFC 8986: If SL=0, pass to upper layer
    if (ectx->segments_left == 0) {
        return -1;
    }

    // Decrement SL
    ectx->new_sl = ectx->segments_left - 1;

    // Verify bounds
    if (ectx->new_sl > srh->first_segment || ectx->new_sl > 9) {
        return -2;
    }

    return 0;
}

// Update Destination Address with Segment List[new_sl]
// Common operation for End, End.X, End.T, etc.
static __always_inline int endpoint_update_da(struct endpoint_ctx *ectx)
{
    void *seg_base = (void *)ectx->srh + 8;
    if (copy_segment_by_index(&ectx->ip6h->daddr, seg_base, ectx->data_end, ectx->new_sl) != 0) {
        return -1;
    }
    ectx->srh->segments_left = ectx->new_sl;
    return 0;
}

// Perform FIB lookup and redirect (common for End, End.T)
static __always_inline int endpoint_fib_redirect(struct endpoint_ctx *ectx)
{
    void *data = (void *)(long)ectx->ctx->data;
    void *data_end = (void *)(long)ectx->ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end) {
        return XDP_DROP;
    }

    __u32 ifindex;
    int fib_result = srv6_fib_lookup_and_update(ectx->ctx, ectx->ip6h, eth, &ifindex);

    switch (fib_result) {
    case FIB_RESULT_REDIRECT:
        STATS_INC(STATS_SRV6_END, 0);
        return bpf_redirect(ifindex, 0);
    case FIB_RESULT_DROP:
        return XDP_DROP;
    default:
        return XDP_PASS;
    }
}

// ========================================================================
// Endpoint Function Implementations
// ========================================================================

// End: Basic SRv6 endpoint operation
// RFC 8986 Section 4.1
static __always_inline int process_end(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ipv6_sr_hdr *srh,
    struct sid_function_entry *entry)
{
    struct endpoint_ctx ectx;
    int ret = endpoint_init(&ectx, ctx, ip6h, srh, entry);

    if (ret == -1) {
        DEBUG_PRINT("End: SL is 0, passing to upper layer\n");
        return XDP_PASS;
    }
    if (ret == -2) {
        DEBUG_PRINT("End: Invalid SL\n");
        return XDP_DROP;
    }

    if (endpoint_update_da(&ectx) != 0) {
        DEBUG_PRINT("End: Failed to update DA\n");
        return XDP_DROP;
    }

    DEBUG_PRINT("End: Updated DA, new SL=%d\n", ectx.new_sl);
    return endpoint_fib_redirect(&ectx);
}

// End.X: Layer-3 cross-connect to specified nexthop
// RFC 8986 Section 4.2
static __always_inline int process_end_x(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ipv6_sr_hdr *srh,
    struct sid_function_entry *entry)
{
    struct endpoint_ctx ectx;
    int ret = endpoint_init(&ectx, ctx, ip6h, srh, entry);
    if (ret == -1) return XDP_PASS;
    if (ret == -2) return XDP_DROP;

    if (endpoint_update_da(&ectx) != 0) {
        return XDP_DROP;
    }

    // TODO: Implement L3 cross-connect to entry->nexthop
    // Instead of FIB lookup, forward directly to nexthop
    DEBUG_PRINT("End.X: Not yet implemented\n");
    return XDP_PASS;
}

// End.T: Lookup in specific routing table
// RFC 8986 Section 4.3
static __always_inline int process_end_t(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ipv6_sr_hdr *srh,
    struct sid_function_entry *entry)
{
    struct endpoint_ctx ectx;
    int ret = endpoint_init(&ectx, ctx, ip6h, srh, entry);
    if (ret == -1) return XDP_PASS;
    if (ret == -2) return XDP_DROP;

    if (endpoint_update_da(&ectx) != 0) {
        return XDP_DROP;
    }

    // TODO: Implement VRF/table-specific FIB lookup
    DEBUG_PRINT("End.T: Not yet implemented\n");
    return XDP_PASS;
}

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
    int action = srv6_fib_redirect_v4(ctx, iph, eth);
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
    int action = srv6_fib_redirect(ctx, inner_ip6h, eth);
    if (action == XDP_PASS) {
        DEBUG_PRINT("End.DX6: FIB lookup failed, dropping\n");
        return XDP_DROP;
    }
    return action;
}

// End.DT4: Decapsulation with IPv4 table lookup
// RFC 8986 Section 4.8
static __always_inline int process_end_dt4(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ipv6_sr_hdr *srh,
    struct sid_function_entry *entry)
{
    // TODO: Implement IPv4 decap + table lookup
    DEBUG_PRINT("End.DT4: Not yet implemented\n");
    return XDP_PASS;
}

// End.DT6: Decapsulation with IPv6 table lookup
// RFC 8986 Section 4.7
static __always_inline int process_end_dt6(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ipv6_sr_hdr *srh,
    struct sid_function_entry *entry)
{
    // TODO: Implement IPv6 decap + table lookup
    DEBUG_PRINT("End.DT6: Not yet implemented\n");
    return XDP_PASS;
}

// End.DT46: Decapsulation with IP (v4 or v6) table lookup
// RFC 8986 Section 4.9
static __always_inline int process_end_dt46(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ipv6_sr_hdr *srh,
    struct sid_function_entry *entry)
{
    // TODO: Implement dual-stack decap + table lookup
    DEBUG_PRINT("End.DT46: Not yet implemented\n");
    return XDP_PASS;
}

#endif // SRV6_ENDPOINT_H
