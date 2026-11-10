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

// Run the IPv6 FIB lookup the data plane makes, on zeroed params: family,
// the device the lookup runs on, source and destination; flowinfo, L4 and
// flags stay 0. The XDP path (srv6_fib_lookup_v6_core), the tc path's encap
// and the control plane's uplink probe (bum_uplink_probe) all go through
// here, so a change to the inputs reaches each of them. End.X adjacency
// resolution does not: it looks up the configured next hop with the exposed
// inner source (endpoint_resolve_adjacency).
static __always_inline int srv6_fib_lookup_v6_params(
    void *ctx,
    struct bpf_fib_lookup *params,
    const void *src,
    const void *dst,
    __u32 ifindex)
{
    params->family = AF_INET6;
    params->ifindex = ifindex;
    __builtin_memcpy(params->ipv6_src, src, sizeof(params->ipv6_src));
    __builtin_memcpy(params->ipv6_dst, dst, sizeof(params->ipv6_dst));
    return bpf_fib_lookup(ctx, params, sizeof(*params), 0);
}

#define SRV6_FIB_MAIN_TABLE 254     // RT_TABLE_MAIN
#define SRV6_FIB_LOOPBACK_IFINDEX 1 // the loopback device, in every namespace
#define SRV6_FIB_EINVAL 22

// Run the IPv6 FIB lookup for the outer header of an encapsulation. The
// outer header is underlay traffic whatever VRF the inner packet came from.
// For a packet from the global VRF (vrf_id 0) this is the ingress-device
// lookup above, ip rules included. A packet from a tenant AC is looked up in
// the main table directly instead: on an ingress port enslaved to a VRF
// device the l3mdev rule would take the lookup to the tenant's table, which
// ends in an unreachable default and may hold a tenant route that covers the
// SID. BPF_FIB_LOOKUP_TBID (Linux 6.5) names the main table. A kernel without
// it refuses the flag with -EINVAL; the lookup then runs again on the
// loopback device, which cannot be enslaved to a VRF, so its table is main
// as well.
static __always_inline int srv6_fib_lookup_v6_encap_params(
    void *ctx,
    struct bpf_fib_lookup *params,
    const void *src,
    const void *dst,
    __u32 ifindex,
    __u32 vrf_id)
{
    if (vrf_id == 0)
        return srv6_fib_lookup_v6_params(ctx, params, src, dst, ifindex);

    params->family = AF_INET6;
    params->ifindex = ifindex;
    params->tbid = SRV6_FIB_MAIN_TABLE;
    __builtin_memcpy(params->ipv6_src, src, sizeof(params->ipv6_src));
    __builtin_memcpy(params->ipv6_dst, dst, sizeof(params->ipv6_dst));
    int ret = bpf_fib_lookup(ctx, params, sizeof(*params),
                             BPF_FIB_LOOKUP_DIRECT | BPF_FIB_LOOKUP_TBID);
    if (ret != -SRV6_FIB_EINVAL)
        return ret;

    params->ifindex = SRV6_FIB_LOOPBACK_IFINDEX;
    params->tbid = 0;
    return bpf_fib_lookup(ctx, params, sizeof(*params), BPF_FIB_LOOKUP_DIRECT);
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
    int ret = srv6_fib_lookup_v6_params(ctx, &fib_params, &ip6h->saddr, dst, ifindex);
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
// device, by the packet's ingress VRF: see srv6_fib_lookup_v6_encap_params.
static __always_inline int srv6_fib_lookup_encap(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ethhdr *eth,
    __u32 *out_ifindex,
    __u32 vrf_id)
{
    struct bpf_fib_lookup fib_params = {};
    int ret = srv6_fib_lookup_v6_encap_params(ctx, &fib_params, &ip6h->saddr, &ip6h->daddr,
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
