#ifndef SRV6_FIB_H
#define SRV6_FIB_H

#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>

#include "xdp_prog.h"

// FIB lookup result codes
#define FIB_RESULT_REDIRECT  0   // Success, redirect to ifindex
#define FIB_RESULT_DROP     -1   // Drop packet (blackhole/unreachable)
#define FIB_RESULT_PASS     -2   // Pass to kernel stack

// Perform IPv6 FIB lookup and update Ethernet header
// Returns: FIB_RESULT_REDIRECT (success), FIB_RESULT_DROP, or FIB_RESULT_PASS
// On success, eth header is updated and ifindex is set
static __always_inline int srv6_fib_lookup_and_update(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ethhdr *eth,
    __u32 *out_ifindex)
{
    struct bpf_fib_lookup fib_params = {};
    fib_params.family = AF_INET6;
    fib_params.ifindex = ctx->ingress_ifindex;

    __builtin_memcpy(fib_params.ipv6_src, &ip6h->saddr, sizeof(fib_params.ipv6_src));
    __builtin_memcpy(fib_params.ipv6_dst, &ip6h->daddr, sizeof(fib_params.ipv6_dst));

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

// Convenience wrapper that performs FIB lookup and returns XDP action
static __always_inline int srv6_fib_redirect(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ethhdr *eth)
{
    __u32 ifindex;
    int result = srv6_fib_lookup_and_update(ctx, ip6h, eth, &ifindex);

    switch (result) {
    case FIB_RESULT_REDIRECT:
        return bpf_redirect(ifindex, 0);
    case FIB_RESULT_DROP:
        return XDP_DROP;
    default:
        return XDP_PASS;
    }
}

#endif // SRV6_FIB_H
