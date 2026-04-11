#ifndef SRV6_ENDPOINT_BASIC_H
#define SRV6_ENDPOINT_BASIC_H

#include "endpoint/srv6_endpoint_core.h"

// ========================================================================
// Basic Endpoint Function Implementations (End, End.X, End.T)
// All share the common pipeline via endpoint_common_processing(),
// differing only in FIB redirect method.
// ========================================================================

// End: Forward to next segment via FIB on updated DA (RFC 8986 Section 4.1)
static __always_inline int process_end(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ipv6_sr_hdr *srh,
    struct sid_function_entry *entry,
    __u16 l3_offset)
{
    struct endpoint_ctx ectx;
    int action = endpoint_common_processing(&ectx, ctx, ip6h, srh, entry,
                                            l3_offset, ctx->ingress_ifindex);
    if (action >= 0) return action;
    return endpoint_fib_redirect(&ectx, ctx->ingress_ifindex);
}

// End.X: Cross-connect to specified nexthop (RFC 8986 Section 4.2)
static __always_inline int process_end_x(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ipv6_sr_hdr *srh,
    struct sid_function_entry *entry,
    struct sid_aux_entry *aux,
    __u16 l3_offset)
{
    if (!aux) return XDP_DROP;
    struct endpoint_ctx ectx;
    int action = endpoint_common_processing(&ectx, ctx, ip6h, srh, entry,
                                            l3_offset, ctx->ingress_ifindex);
    if (action >= 0) return action;
    return endpoint_fib_redirect_nexthop(&ectx, aux->nexthop.nexthop);
}

// End.T: VRF-aware FIB lookup (RFC 8986 Section 4.3)
static __always_inline int process_end_t(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ipv6_sr_hdr *srh,
    struct sid_function_entry *entry,
    __u16 l3_offset)
{
    __u32 fib_ifindex = entry->vrf_ifindex ? entry->vrf_ifindex : ctx->ingress_ifindex;
    struct endpoint_ctx ectx;
    int action = endpoint_common_processing(&ectx, ctx, ip6h, srh, entry,
                                            l3_offset, fib_ifindex);
    if (action >= 0) return action;
    return endpoint_fib_redirect(&ectx, fib_ifindex);
}

#endif // SRV6_ENDPOINT_BASIC_H
