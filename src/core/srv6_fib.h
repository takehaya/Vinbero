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

// Whether the kernel's bpf_fib_lookup accepts BPF_FIB_LOOKUP_TBID. The
// daemon sets it at load from bpf.ProbeFibLookupTBID (or the
// internal.bpf.fib_lookup_tbid override). Without it every lookup is the
// ingress-device one, and the daemon does not close the VRF tables.
const volatile __u8 fib_lookup_tbid = 1;

// internal.bpf.fib_lookup_global: 0 ("rules") runs every vrf 0 lookup as
// the full lookup (flags 0, ip rules included); 1 ("auto") lets the daemon
// switch each address family to a direct lookup (BPF_FIB_LOOKUP_DIRECT)
// while that gives the full lookup's answer (pkg/fibmode). Set at load.
const volatile __u8 fib_lookup_global_auto = 0;

// What the daemon decided for the vrf 0 lookups of each family: 1 runs them
// as a direct lookup, 0 as the full lookup. Zero (the state of a new map, and
// what the daemon writes whenever it cannot tell) is the full lookup.
struct fib_global_mode {
    __u8 v4;
    __u8 v6;
    __u8 pad[2];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct fib_global_mode);
    __uint(max_entries, 1);
} fib_global_mode_map SEC(".maps");

// The host routes of the kernel's local table (table 255), by family: the
// node's own addresses, broadcast and anycast addresses. A destination
// listed here takes the full lookup even in the direct mode, because the
// full lookup reads the local table first and stops at these routes, which a
// direct lookup in the main or VRF table would not see. The daemon keeps the
// maps in step with the table and turns the family's direct mode off when
// the table holds a route these maps cannot express.
#define FIB_LOCAL_MAX_ENTRIES 8192

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __be32);
    __type(value, __u8);
    __uint(max_entries, FIB_LOCAL_MAX_ENTRIES);
} fib_local_v4_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct in6_addr);
    __type(value, __u8);
    __uint(max_entries, FIB_LOCAL_MAX_ENTRIES);
} fib_local_v6_map SEC(".maps");

// The flags for a vrf 0 lookup of dst (params->ipv4_dst or ipv6_dst, on the
// stack): 0 for the full lookup, or BPF_FIB_LOOKUP_DIRECT. A direct lookup
// without a table ID reads one table: the VRF table when the lookup's device
// is a VRF device or a port enslaved to one, the main table otherwise. The
// daemon enables it for a family only while the ip rules of the namespace,
// the local table, the IPv4 default table and the VRF tables are such that
// the full lookup of any destination not in the local table ends in that
// same table with the same answer (docs/design/ja/vrf.md). The rest of the
// local table is checked here: 127.0.0.0/8 and ff00::/8, the prefixes the
// kernel itself puts there, and the host routes in fib_local_v4/v6_map.
static __always_inline __u32 srv6_fib_global_flags(__u8 family, const void *dst)
{
    if (!fib_lookup_global_auto)
        return 0;
    __u32 key = 0;
    struct fib_global_mode *mode = bpf_map_lookup_elem(&fib_global_mode_map, &key);
    if (!mode)
        return 0;
    if (family == AF_INET6) {
        if (!mode->v6 || *(const __u8 *)dst == 0xff)
            return 0;
        if (bpf_map_lookup_elem(&fib_local_v6_map, dst))
            return 0;
    } else {
        if (!mode->v4 || *(const __u8 *)dst == 127)
            return 0;
        if (bpf_map_lookup_elem(&fib_local_v4_map, dst))
            return 0;
    }
    return BPF_FIB_LOOKUP_DIRECT;
}

// Fill zeroed params for the IPv6 FIB lookup the data plane makes and return
// the flags to run it with. Family, the device the lookup runs on, source and
// destination are set; flowinfo and L4 stay 0. vrf_id is the ingress VRF of
// the packet whose outer header is looked up, 0 for every lookup that is not
// an encapsulation's outer header.
//
// vrf_id 0 runs the lookup on the device as an ingress lookup, ip rules
// included, or as the direct lookup that gives the same answer
// (srv6_fib_global_flags). A non-zero vrf_id (a tenant AC's encapsulation) looks the outer
// header up in the main table directly (BPF_FIB_LOOKUP_DIRECT |
// BPF_FIB_LOOKUP_TBID): the outer header is underlay traffic, and on a port
// enslaved to a VRF device the l3mdev rule would take the lookup to the
// tenant's table, which ends in an unreachable default and may hold a tenant
// route that covers the SID. That lookup does not consult ip rules. On a
// kernel without BPF_FIB_LOOKUP_TBID (fib_lookup_tbid 0) a tenant packet takes
// the ingress-device lookup too, and the VRF tables are left open.
//
// Every IPv6 lookup goes through here: the XDP path (srv6_fib_lookup_v6_core,
// srv6_fib_lookup_encap), the tc path's encap and the control plane's uplink
// probe (bum_uplink_probe), so a change to the inputs reaches each of them.
// End.X adjacency resolution does not: it looks up the configured next hop
// with the exposed inner source (endpoint_resolve_adjacency), and takes its
// flags from srv6_fib_global_flags itself.
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
    if (vrf_id == 0 || !fib_lookup_tbid)
        return srv6_fib_global_flags(AF_INET6, params->ipv6_dst);
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

    int ret = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params),
                             srv6_fib_global_flags(AF_INET, &fib_params.ipv4_dst));

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
