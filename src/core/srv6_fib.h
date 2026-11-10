#ifndef SRV6_FIB_H
#define SRV6_FIB_H

#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>

#include "core/xdp_prog.h"
#include "core/xdp_redirect.h"

// FIB lookup result codes
#define FIB_RESULT_REDIRECT  0   // Success, redirect to ifindex
#define FIB_RESULT_DROP     -1   // Drop packet (blackhole/unreachable)
#define FIB_RESULT_PASS     -2   // Pass to kernel stack
// The route resolved but its neighbour is not (yet) known. Callers that
// treat every non-redirect as a failure must still hand this one to the
// kernel: XDP dropping it means nothing ever emits the Neighbor
// Solicitation, so the flow stays black-holed instead of recovering.
// Callers that lump it in with FIB_RESULT_PASS keep their old behaviour
// for free, because it stays a negative "not redirected" code.
#define FIB_RESULT_NO_NEIGH -3

#define SRV6_FIB_MAIN_TABLE 254 // RT_TABLE_MAIN

// Fill zeroed params for the IPv6 FIB lookup the data plane makes and return
// the flags to run it with. Family, the device the lookup runs on, source and
// destination are set; flowinfo and L4 stay 0. vrf_id is the ingress VRF of
// the packet whose outer header is looked up, 0 for every lookup that is not
// an encapsulation's outer header.
//
// vrf_id 0 runs the lookup on the device as an ingress lookup, ip rules
// included. A non-zero vrf_id (a tenant AC's encapsulation) looks the outer
// header up in the main table directly (BPF_FIB_LOOKUP_DIRECT |
// BPF_FIB_LOOKUP_TBID): the outer header is underlay traffic, and on a port
// enslaved to a VRF device the l3mdev rule would take the lookup to the
// tenant's table, which ends in an unreachable default and may hold a tenant
// route that covers the SID. That lookup does not consult ip rules. The
// daemon checks at load time that the kernel accepts BPF_FIB_LOOKUP_TBID
// (bpf.ProbeFibLookupTBID).
//
// Every IPv6 lookup goes through here: the XDP path (srv6_fib_lookup_v6_core,
// srv6_fib_lookup_encap), the tc path's encap and the control plane's uplink
// probe (bum_uplink_probe), so a change to the inputs reaches each of them.
// End.X adjacency resolution does not: it looks up the configured next hop
// with the exposed inner source (endpoint_resolve_adjacency).
static __always_inline __u32 srv6_fib_v6_params_set(
    struct bpf_fib_lookup *params,
    const void *src,
    const void *dst,
    __u32 ifindex,
    __u32 vrf_id)
{
    params->family = AF_INET6;
    params->ifindex = ifindex;
    __builtin_memcpy(params->ipv6_src, src, sizeof(params->ipv6_src));
    __builtin_memcpy(params->ipv6_dst, dst, sizeof(params->ipv6_dst));
    if (vrf_id == 0)
        return 0;
    params->tbid = SRV6_FIB_MAIN_TABLE;
    return BPF_FIB_LOOKUP_DIRECT | BPF_FIB_LOOKUP_TBID;
}

// Run the IPv6 FIB lookup on params set by srv6_fib_v6_params_set.
static __always_inline int srv6_fib_lookup_v6_params(
    void *ctx,
    struct bpf_fib_lookup *params,
    const void *src,
    const void *dst,
    __u32 ifindex,
    __u32 vrf_id)
{
    __u32 flags = srv6_fib_v6_params_set(params, src, dst, ifindex, vrf_id);
    return bpf_fib_lookup(ctx, params, sizeof(*params), flags);
}

// Map an IPv6 bpf_fib_lookup return value to a FIB_RESULT_* code. On
// success the Ethernet addresses are rewritten and out_ifindex is set.
static __always_inline int srv6_fib_v6_result(
    int ret,
    struct bpf_fib_lookup *fib_params,
    struct ethhdr *eth,
    __u32 *out_ifindex)
{
    switch (ret) {
    case BPF_FIB_LKUP_RET_SUCCESS:
        __builtin_memcpy(eth->h_dest, fib_params->dmac, ETH_ALEN);
        __builtin_memcpy(eth->h_source, fib_params->smac, ETH_ALEN);
        *out_ifindex = fib_params->ifindex;
        return FIB_RESULT_REDIRECT;

    case BPF_FIB_LKUP_RET_BLACKHOLE:
    case BPF_FIB_LKUP_RET_UNREACHABLE:
    case BPF_FIB_LKUP_RET_PROHIBIT:
        return FIB_RESULT_DROP;

    case BPF_FIB_LKUP_RET_NO_NEIGH:
        return FIB_RESULT_NO_NEIGH;

    default:
        return FIB_RESULT_PASS;
    }
}

// Core IPv6 FIB lookup with explicit dst address, update Ethernet header
// dst: FIB lookup destination (ip6h->daddr for normal, nexthop for End.X)
// ifindex: L3 device index for lookup (use ctx->ingress_ifindex or VRF ifindex)
// Returns: FIB_RESULT_REDIRECT (success), FIB_RESULT_DROP, or FIB_RESULT_PASS
// On success, eth header is updated and out_ifindex is set
static __always_inline int srv6_fib_lookup_v6_core(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ethhdr *eth,
    __u32 *out_ifindex,
    void *dst,
    __u32 ifindex)
{
    struct bpf_fib_lookup fib_params = {};
    int ret = srv6_fib_lookup_v6_params(ctx, &fib_params, &ip6h->saddr, dst, ifindex, 0);
    return srv6_fib_v6_result(ret, &fib_params, eth, out_ifindex);
}

// Perform IPv6 FIB lookup using ip6h->daddr as destination
static __always_inline int srv6_fib_lookup_and_update(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ethhdr *eth,
    __u32 *out_ifindex,
    __u32 ifindex)
{
    return srv6_fib_lookup_v6_core(ctx, ip6h, eth, out_ifindex, &ip6h->daddr, ifindex);
}

// The lookup for a headend's new outer header (ip6h->daddr) on the ingress
// device. vrf_id is the packet's ingress VRF (tailcall_ctx.vrf_id, passed
// down by the caller): see srv6_fib_v6_params_set.
static __always_inline int srv6_fib_lookup_encap(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ethhdr *eth,
    __u32 *out_ifindex,
    __u32 vrf_id)
{
    struct bpf_fib_lookup fib_params = {};
    int ret = srv6_fib_lookup_v6_params(ctx, &fib_params, &ip6h->saddr, &ip6h->daddr,
                                        ctx->ingress_ifindex, vrf_id);
    return srv6_fib_v6_result(ret, &fib_params, eth, out_ifindex);
}

// Convert FIB lookup result to XDP action (redirect/drop/pass)
static __always_inline int fib_result_to_xdp_action(int fib_result, __u32 ifindex)
{
    switch (fib_result) {
    case FIB_RESULT_REDIRECT:
        return xdp_redirect_dev(ifindex);
    case FIB_RESULT_DROP:
        return XDP_DROP;
    default:
        return XDP_PASS;
    }
}

// Convenience wrapper that performs FIB lookup and returns XDP action
static __always_inline int srv6_fib_redirect(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ethhdr *eth,
    __u32 ifindex)
{
    __u32 out_ifindex;
    int result = srv6_fib_lookup_and_update(ctx, ip6h, eth, &out_ifindex, ifindex);
    return fib_result_to_xdp_action(result, out_ifindex);
}

// srv6_fib_redirect for a headend's outer header.
static __always_inline int srv6_fib_redirect_encap(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ethhdr *eth,
    __u32 vrf_id)
{
    __u32 out_ifindex;
    int result = srv6_fib_lookup_encap(ctx, ip6h, eth, &out_ifindex, vrf_id);
    return fib_result_to_xdp_action(result, out_ifindex);
}

// ========================================================================
// IPv4 FIB Lookup Helpers
// ========================================================================

// Perform IPv4 FIB lookup and update Ethernet header
// ifindex: L3 device index for lookup (use ctx->ingress_ifindex or VRF ifindex)
static __always_inline int srv6_fib_lookup_and_update_v4(
    struct xdp_md *ctx,
    struct iphdr *iph,
    struct ethhdr *eth,
    __u32 *out_ifindex,
    __u32 ifindex)
{
    struct bpf_fib_lookup fib_params = {};
    fib_params.family = AF_INET;
    fib_params.ifindex = ifindex;
    fib_params.ipv4_src = iph->saddr;
    fib_params.ipv4_dst = iph->daddr;

    int ret = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);

    switch (ret) {
    case BPF_FIB_LKUP_RET_SUCCESS:
        __builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
        __builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
        *out_ifindex = fib_params.ifindex;
        return FIB_RESULT_REDIRECT;

    case BPF_FIB_LKUP_RET_BLACKHOLE:
    case BPF_FIB_LKUP_RET_UNREACHABLE:
    case BPF_FIB_LKUP_RET_PROHIBIT:
        return FIB_RESULT_DROP;

    default:
        // BPF_FIB_LKUP_RET_NOT_FWDED, etc.
        return FIB_RESULT_PASS;
    }
}

// Convenience wrapper for IPv4 that performs FIB lookup and returns XDP action
static __always_inline int srv6_fib_redirect_v4(
    struct xdp_md *ctx,
    struct iphdr *iph,
    struct ethhdr *eth,
    __u32 ifindex)
{
    __u32 out_ifindex;
    int result = srv6_fib_lookup_and_update_v4(ctx, iph, eth, &out_ifindex, ifindex);
    return fib_result_to_xdp_action(result, out_ifindex);
}

#endif // SRV6_FIB_H
