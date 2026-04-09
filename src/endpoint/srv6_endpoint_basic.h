#ifndef SRV6_ENDPOINT_BASIC_H
#define SRV6_ENDPOINT_BASIC_H

#include "endpoint/srv6_endpoint_core.h"

// ========================================================================
// Basic Endpoint Function Implementations (End, End.X, End.T)
// ========================================================================

// End: Basic SRv6 endpoint operation
// RFC 8986 Section 4.1
// Supports flavors: PSP (strip SRH at penultimate), USP (strip SRH at ultimate),
//                   USD (decapsulate at ultimate)
static __always_inline int process_end(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ipv6_sr_hdr *srh,
    struct sid_function_entry *entry,
    __u16 l3_offset)
{
    struct endpoint_ctx ectx;
    int ret = endpoint_init(&ectx, ctx, ip6h, srh, entry, l3_offset);

    if (ret == -1) {
        // SL=0: check USD and USP flavors
        if (entry->flavor == SRV6_LOCAL_FLAVOR_USD) {
            return endpoint_handle_usd(ctx, ip6h, srh, entry, l3_offset);
        } else if (entry->flavor == SRV6_LOCAL_FLAVOR_USP) {
            return endpoint_handle_usp(ctx, ip6h, srh, entry, ctx->ingress_ifindex, l3_offset);
        }
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

    // PSP: strip SRH when new_sl becomes 0 (penultimate segment)
    if (ectx.new_sl == 0 && (entry->flavor == SRV6_LOCAL_FLAVOR_PSP)) {
        DEBUG_PRINT("End+PSP: Stripping SRH at penultimate\n");
        if (endpoint_strip_srh(&ectx) != 0) {
            return XDP_DROP;
        }
    }

    DEBUG_PRINT("End: Updated DA, new SL=%d\n", ectx.new_sl);
    return endpoint_fib_redirect(&ectx, ectx.ctx->ingress_ifindex);
}

// End.X: Layer-3 cross-connect to specified nexthop
// RFC 8986 Section 4.2
// Like End but uses entry->nexthop for FIB lookup instead of the updated DA
// Supports flavors: PSP, USP, USD
static __always_inline int process_end_x(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ipv6_sr_hdr *srh,
    struct sid_function_entry *entry,
    __u16 l3_offset)
{
    struct endpoint_ctx ectx;
    int ret = endpoint_init(&ectx, ctx, ip6h, srh, entry, l3_offset);
    if (ret == -1) {
        if (entry->flavor == SRV6_LOCAL_FLAVOR_USD) {
            return endpoint_handle_usd(ctx, ip6h, srh, entry, l3_offset);
        } else if (entry->flavor == SRV6_LOCAL_FLAVOR_USP) {
            return endpoint_handle_usp(ctx, ip6h, srh, entry, ctx->ingress_ifindex, l3_offset);
        }
        return XDP_PASS;
    }
    if (ret == -2) return XDP_DROP;

    if (endpoint_update_da(&ectx) != 0) {
        return XDP_DROP;
    }

    if (ectx.new_sl == 0 && (entry->flavor == SRV6_LOCAL_FLAVOR_PSP)) {
        DEBUG_PRINT("End.X+PSP: Stripping SRH at penultimate\n");
        if (endpoint_strip_srh(&ectx) != 0) {
            return XDP_DROP;
        }
    }

    DEBUG_PRINT("End.X: Updated DA, new SL=%d, forwarding via nexthop\n", ectx.new_sl);
    return endpoint_fib_redirect_nexthop(&ectx);
}

// End.T: Lookup in specific routing table
// RFC 8986 Section 4.3
// Like End but uses entry->vrf_ifindex for VRF-aware FIB lookup
// Supports flavors: PSP, USP, USD
static __always_inline int process_end_t(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ipv6_sr_hdr *srh,
    struct sid_function_entry *entry,
    __u16 l3_offset)
{
    __u32 fib_ifindex = entry->vrf_ifindex ? entry->vrf_ifindex : ctx->ingress_ifindex;

    struct endpoint_ctx ectx;
    int ret = endpoint_init(&ectx, ctx, ip6h, srh, entry, l3_offset);
    if (ret == -1) {
        if (entry->flavor == SRV6_LOCAL_FLAVOR_USD) {
            return endpoint_handle_usd(ctx, ip6h, srh, entry, l3_offset);
        } else if (entry->flavor == SRV6_LOCAL_FLAVOR_USP) {
            return endpoint_handle_usp(ctx, ip6h, srh, entry, fib_ifindex, l3_offset);
        }
        return XDP_PASS;
    }
    if (ret == -2) return XDP_DROP;

    if (endpoint_update_da(&ectx) != 0) {
        return XDP_DROP;
    }

    if (ectx.new_sl == 0 && (entry->flavor == SRV6_LOCAL_FLAVOR_PSP)) {
        DEBUG_PRINT("End.T+PSP: Stripping SRH at penultimate\n");
        if (endpoint_strip_srh(&ectx) != 0) {
            return XDP_DROP;
        }
    }

    DEBUG_PRINT("End.T: Updated DA, new SL=%d, FIB ifindex=%d\n", ectx.new_sl, fib_ifindex);
    return endpoint_fib_redirect(&ectx, fib_ifindex);
}

#endif // SRV6_ENDPOINT_BASIC_H
