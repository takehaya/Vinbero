#ifndef SRV6_ENDPOINT_CORE_H
#define SRV6_ENDPOINT_CORE_H

#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

#include "core/xdp_prog.h"
#include "core/srv6.h"
#include "headend/srv6_headend_utils.h"
#include "core/srv6_fib.h"
#include "endpoint/srv6_decaps.h"
#include "core/xdp_stats.h"

// Pick the VRF ifindex from aux->l3vrf, falling back to the ingress
// interface when aux is absent or carries a zero ifindex (e.g. End.T
// without a configured VRF).
static __always_inline __u32 aux_vrf_or_ingress_ifindex(
    struct sid_aux_entry *aux,
    struct xdp_md *ctx)
{
    return (aux && aux->l3vrf.vrf_ifindex) ? aux->l3vrf.vrf_ifindex : ctx->ingress_ifindex;
}

// Endpoint processing context - shared by all endpoint functions
struct endpoint_ctx {
    struct xdp_md *ctx;
    struct ipv6hdr *ip6h;
    struct ipv6_sr_hdr *srh;
    struct sid_function_entry *entry;
    void *data_end;
    __u8 segments_left;
    __u8 new_sl;
    __u16 l3_offset;  // distance from packet start to IPv6 header (14/18/22)
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
    struct sid_function_entry *entry,
    __u16 l3_offset)
{
    ectx->ctx = ctx;
    ectx->ip6h = ip6h;
    ectx->srh = srh;
    ectx->entry = entry;
    ectx->data_end = (void *)(long)ctx->data_end;
    ectx->segments_left = srh->segments_left;
    ectx->l3_offset = l3_offset;

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

// Core FIB lookup + redirect with explicit dst address
// Re-derives all packet pointers from ctx->data (safe after bpf_xdp_adjust_head)
static __always_inline int endpoint_fib_redirect_core(struct endpoint_ctx *ectx, void *dst, __u32 fib_ifindex)
{
    void *data = (void *)(long)ectx->ctx->data;
    void *data_end = (void *)(long)ectx->ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end) {
        return XDP_DROP;
    }

    struct ipv6hdr *ip6h = (struct ipv6hdr *)(data + ectx->l3_offset);
    if ((void *)(ip6h + 1) > data_end) {
        return XDP_DROP;
    }

    __u32 ifindex;
    int fib_result = srv6_fib_lookup_v6_core(ectx->ctx, ip6h, eth, &ifindex, dst, fib_ifindex);

    switch (fib_result) {
    case FIB_RESULT_REDIRECT:
        return bpf_redirect(ifindex, 0);
    case FIB_RESULT_DROP:
        return XDP_DROP;
    default:
        // Unresolved or unrouted: hand the packet to the kernel only when
        // the lookup ran in the ingress context, where the kernel repeats
        // the same decision (and resolves the neighbour on NO_NEIGH). A
        // VRF-bound lookup (End.T/uT) is one the kernel would not repeat
        // for a packet that arrived on a non-VRF interface, so it fails
        // closed instead of escaping the table binding.
        if (fib_ifindex != ectx->ctx->ingress_ifindex)
            return XDP_DROP;
        return XDP_PASS;
    }
}

// FIB lookup on ip6h->daddr (for End, End.T)
static __always_inline int endpoint_fib_redirect(struct endpoint_ctx *ectx, __u32 fib_ifindex)
{
    void *data = (void *)(long)ectx->ctx->data;
    void *data_end = (void *)(long)ectx->ctx->data_end;
    struct ipv6hdr *ip6h = (void *)data + ectx->l3_offset;
    if ((void *)(ip6h + 1) > data_end) {
        return XDP_DROP;
    }
    return endpoint_fib_redirect_core(ectx, &ip6h->daddr, fib_ifindex);
}

// FIB lookup on explicit nexthop (for End.X)
static __always_inline int endpoint_fib_redirect_nexthop(struct endpoint_ctx *ectx, void *nexthop)
{
    return endpoint_fib_redirect_core(ectx, nexthop, ectx->ctx->ingress_ifindex);
}

// ========================================================================
// SRv6 Flavor Helpers (PSP, USP, USD)
// ========================================================================

// Strip SRH from packet, preserving Ethernet + IPv6 headers
// Uses the same adjust_head pattern as srv6_decap():
//   1. Save Eth + IPv6 header to stack
//   2. Strip all (Eth + IPv6 + SRH) via adjust_head(+)
//   3. Re-expand Eth + IPv6 via adjust_head(-)
//   4. Restore saved headers with updated nexthdr/payload_len
//
// Before: [Eth(14)][IPv6(40)][SRH][Upper Layer]
// After:  [Eth(14)][IPv6(40)][Upper Layer]
//
// Returns: 0 on success, -1 on failure
// Note: After success, caller must re-fetch all pointers from ctx->data
static __always_inline int endpoint_strip_srh(struct endpoint_ctx *ectx)
{
    void *data = (void *)(long)ectx->ctx->data;
    void *data_end = (void *)(long)ectx->ctx->data_end;
    __u16 l3_off = ectx->l3_offset;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    struct ipv6hdr *ip6h = (struct ipv6hdr *)(data + l3_off);
    if ((void *)(ip6h + 1) > data_end)
        return -1;

    // Save Eth header (always 14 bytes)
    struct ethhdr saved_eth;
    __builtin_memcpy(&saved_eth, eth, sizeof(saved_eth));

    // Save VLAN tag(s) between Eth and IPv6 (0, 4, or 8 bytes)
    __u32 saved_vlan[2];
    save_vlan_tags(saved_vlan, data, data_end, l3_off);

    // Save IPv6 header
    struct ipv6hdr saved_ip6h;
    __builtin_memcpy(&saved_ip6h, ip6h, sizeof(saved_ip6h));

    // Save SRH metadata before stripping
    __u8 inner_nexthdr = ectx->srh->nexthdr;
    int srh_len = 8 + (ectx->srh->hdrlen * 8);

    // Strip L2 + IPv6 + SRH (includes VLAN tag if present)
    int total_strip = l3_off + sizeof(struct ipv6hdr) + srh_len;
    if (bpf_xdp_adjust_head(ectx->ctx, total_strip))
        return -1;

    // Re-expand for L2 + IPv6 header (VLAN preserved)
    if (bpf_xdp_adjust_head(ectx->ctx, -(int)(l3_off + sizeof(struct ipv6hdr))))
        return -1;

    // Re-fetch pointers
    data = (void *)(long)ectx->ctx->data;
    data_end = (void *)(long)ectx->ctx->data_end;

    eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    ip6h = (struct ipv6hdr *)(data + l3_off);
    if ((void *)(ip6h + 1) > data_end)
        return -1;

    // Restore Eth header
    __builtin_memcpy(eth, &saved_eth, sizeof(saved_eth));

    // Restore VLAN tag(s)
    if (restore_vlan_tags(saved_vlan, (void *)eth, data_end, l3_off) != 0)
        return -1;

    // Restore IPv6 header with updated nexthdr and payload_len
    __builtin_memcpy(ip6h, &saved_ip6h, sizeof(saved_ip6h));
    ip6h->nexthdr = inner_nexthdr;
    ip6h->payload_len = bpf_htons(bpf_ntohs(ip6h->payload_len) - srh_len);

    return 0;
}

// endpoint_strip_srh with a locally built context, for callers outside
// the endpoint_common_processing pipeline. Only the fields
// endpoint_strip_srh reads are meaningful; keep this the single place
// that knows which those are.
static __always_inline int endpoint_strip_srh_at(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ipv6_sr_hdr *srh,
    struct sid_function_entry *entry,
    __u16 l3_offset)
{
    struct endpoint_ctx ectx;
    ectx.ctx = ctx;
    ectx.ip6h = ip6h;
    ectx.srh = srh;
    ectx.entry = entry;
    ectx.data_end = (void *)(long)ctx->data_end;
    ectx.l3_offset = l3_offset;
    return endpoint_strip_srh(&ectx);
}

// Handle USD flavor: decapsulate inner packet at SL=0
// Performs full decap (strip Eth+IPv6+SRH) and FIB redirect on inner packet
static __always_inline int endpoint_handle_usd(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ipv6_sr_hdr *srh,
    struct sid_function_entry *entry,
    __u32 fib_ifindex,
    __u16 l3_offset)
{
    __u8 inner_proto = srh->nexthdr;

    if (inner_proto == IPPROTO_IPIP) {
        DEBUG_PRINT("USD: Decapsulating inner IPv4\n");
        if (srv6_decap(ctx, srh, IPPROTO_IPIP, l3_offset) != 0)
            return XDP_DROP;

        void *data = (void *)(long)ctx->data;
        void *data_end = (void *)(long)ctx->data_end;
        struct ethhdr *eth = data;
        if ((void *)(eth + 1) > data_end) return XDP_DROP;
        struct iphdr *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end) return XDP_DROP;
        eth->h_proto = bpf_htons(ETH_P_IP);
        int action = srv6_fib_redirect_v4(ctx, iph, eth, fib_ifindex);
        return (action == XDP_PASS) ? XDP_DROP : action;
    }

    if (inner_proto == IPPROTO_IPV6) {
        DEBUG_PRINT("USD: Decapsulating inner IPv6\n");
        if (srv6_decap(ctx, srh, IPPROTO_IPV6, l3_offset) != 0)
            return XDP_DROP;

        void *data = (void *)(long)ctx->data;
        void *data_end = (void *)(long)ctx->data_end;
        struct ethhdr *eth = data;
        if ((void *)(eth + 1) > data_end) return XDP_DROP;
        struct ipv6hdr *inner_ip6h = (void *)(eth + 1);
        if ((void *)(inner_ip6h + 1) > data_end) return XDP_DROP;
        int action = srv6_fib_redirect(ctx, inner_ip6h, eth, fib_ifindex);
        return (action == XDP_PASS) ? XDP_DROP : action;
    }

    DEBUG_PRINT("USD: Unsupported inner protocol %d\n", inner_proto);
    return XDP_DROP;
}

// Spend one hop of the exposed inner packet's lifetime before it is
// forwarded: bpf_redirect bypasses the kernel's forwarding path, so
// nothing else decrements it. IPv4 needs the incremental header-checksum
// fold for the TTL byte. Returns -1 when the lifetime is exhausted.
static __always_inline int endpoint_spend_inner_hop(void *inner, __u8 inner_proto)
{
    if (inner_proto == IPPROTO_IPV6) {
        struct ipv6hdr *i6 = inner;
        if (i6->hop_limit <= 1)
            return -1;
        i6->hop_limit--;
    } else {
        struct iphdr *i4 = inner;
        if (i4->ttl <= 1)
            return -1;
        __u32 csum = i4->check;
        csum += bpf_htons(0x0100);
        i4->check = (__u16)(csum + (csum >> 16));
        i4->ttl--;
    }
    return 0;
}

// Resolve an End.X-family adjacency: a plain neighbour/route resolution
// of the configured nexthop, with the source set to the packet that will
// actually leave (the exposed inner IPv6 source, or unspecified for an
// inner IPv4 packet) so source-specific routing cannot pick a different
// interface than the forwarded packet would. Writes the resolved MACs
// into eth on success.
static __always_inline int endpoint_resolve_adjacency(
    struct xdp_md *ctx, struct ethhdr *eth,
    const void *inner_src6, void *nexthop, __u32 *oif)
{
    struct bpf_fib_lookup fib_params = {};
    fib_params.family = AF_INET6;
    fib_params.ifindex = ctx->ingress_ifindex;
    if (inner_src6)
        __builtin_memcpy(fib_params.ipv6_src, inner_src6, sizeof(fib_params.ipv6_src));
    __builtin_memcpy(fib_params.ipv6_dst, nexthop, sizeof(fib_params.ipv6_dst));
    if (bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0) != BPF_FIB_LKUP_RET_SUCCESS)
        return -1;
    __builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
    __builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
    *oif = fib_params.ifindex;
    return 0;
}

// USD towards an adjacency (RFC 8986 Sec.4.16.3 for End.X: the exposed
// packet is forwarded via a member of J, not by a FIB lookup on its
// destination). The adjacency is resolved on the still-encapsulated
// packet so the resolved MACs ride through the decap's eth save/restore;
// the adjacency must resolve, exactly like classic End.X forwarding.
static __always_inline int endpoint_handle_usd_nexthop(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ipv6_sr_hdr *srh,
    void *nexthop,
    __u16 l3_offset)
{
    __u8 inner_proto = srh->nexthdr;
    if (inner_proto != IPPROTO_IPIP && inner_proto != IPPROTO_IPV6)
        return XDP_DROP;
    // The inner offset below comes from hdrlen alone, so a malformed SRH
    // whose Last Entry exceeds the declared length must be refused here
    // (endpoint_init does not cross-check them at SL=0), or segment list
    // bytes would be exposed as the inner packet.
    if (srh->hdrlen < 2 * (srh->first_segment + 1))
        return XDP_DROP;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    // The exposed packet sits right behind the SRH: take its IPv6 source
    // for the resolver, and refuse to expose a truncated inner header
    // (the decap would otherwise emit a bare Ethernet frame).
    const void *inner_src6 = NULL;
    void *inner = (void *)srh + 8 + (srh->hdrlen * 8);
    if (inner_proto == IPPROTO_IPV6) {
        if (inner + sizeof(struct ipv6hdr) > data_end)
            return XDP_DROP;
        inner_src6 = &((struct ipv6hdr *)inner)->saddr;
    } else {
        if (inner + sizeof(struct iphdr) > data_end)
            return XDP_DROP;
    }

    __u32 oif;
    if (endpoint_resolve_adjacency(ctx, eth, inner_src6, nexthop, &oif) != 0)
        return XDP_DROP;

    if (endpoint_spend_inner_hop(inner, inner_proto) != 0)
        return XDP_DROP;

    if (srv6_decap(ctx, srh, inner_proto, l3_offset) != 0)
        return XDP_DROP;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;
    eth->h_proto = bpf_htons(inner_proto == IPPROTO_IPIP ? ETH_P_IP : ETH_P_IPV6);
    return bpf_redirect(oif, 0);
}

// Handle USP flavor: strip SRH at SL=0 and perform FIB lookup
// Called when SL=0 and USP flavor is set
static __always_inline int endpoint_handle_usp(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ipv6_sr_hdr *srh,
    struct sid_function_entry *entry,
    __u32 fib_ifindex,
    __u16 l3_offset)
{
    if (endpoint_strip_srh_at(ctx, ip6h, srh, entry, l3_offset) != 0) {
        DEBUG_PRINT("USP: Failed to strip SRH\n");
        return XDP_DROP;
    }

    DEBUG_PRINT("USP: Stripped SRH, FIB lookup on DA\n");
    struct endpoint_ctx ectx;
    ectx.ctx = ctx;
    ectx.ip6h = ip6h;
    ectx.srh = srh;
    ectx.entry = entry;
    ectx.data_end = (void *)(long)ctx->data_end;
    ectx.l3_offset = l3_offset;
    return endpoint_fib_redirect(&ectx, fib_ifindex);
}

// ========================================================================
// Common End/End.X/End.T Pipeline
// ========================================================================

// Shared processing for End, End.X, End.T:
//   init → SL=0 flavor handling (USD/USP) → DA update → PSP strip
//
// Returns >= 0: final XDP action (packet handled by SL=0 flavor or error).
// Returns -1:   caller should perform variant-specific FIB redirect.
//
// sl0_fib_ifindex: FIB ifindex for the SL=0 flavors USD and USP
// (End/End.X: ingress, End.T/uT: the bound VRF).
// usd_nexthop: non-NULL for the End.X family, whose USD forwards the
// exposed packet via the adjacency instead of by a FIB lookup.
static __always_inline int endpoint_common_processing(
    struct endpoint_ctx *ectx,
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ipv6_sr_hdr *srh,
    struct sid_function_entry *entry,
    __u16 l3_offset,
    __u32 sl0_fib_ifindex,
    void *usd_nexthop)
{
    int ret = endpoint_init(ectx, ctx, ip6h, srh, entry, l3_offset);

    if (ret == -1) {
        if (entry->flavor == SRV6_LOCAL_FLAVOR_USD) {
            if (usd_nexthop)
                return endpoint_handle_usd_nexthop(ctx, ip6h, srh,
                                                   usd_nexthop, l3_offset);
            return endpoint_handle_usd(ctx, ip6h, srh, entry, sl0_fib_ifindex, l3_offset);
        }
        if (entry->flavor == SRV6_LOCAL_FLAVOR_USP)
            return endpoint_handle_usp(ctx, ip6h, srh, entry, sl0_fib_ifindex, l3_offset);
        return XDP_PASS;
    }
    if (ret == -2)
        return XDP_DROP;

    // RFC 8986 S05 and S12: the segment list is advancing, so this node is
    // a hop on the path and spends a hop limit. The behaviors that reach
    // here are the ones that forward the packet onward -- End, End.X,
    // End.T, and End.AN, which is End with its own slot. The decap
    // behaviors terminate the outer header instead and leave it alone, and
    // the SL=0 flavors above are the last segment.
    //
    // Two deliberate differences from the pseudocode. S06 asks for an
    // ICMPv6 Time Exceeded before discarding, which no behavior here
    // generates: the packet is dropped, so the node stays invisible to
    // traceroute. And the malformed-SRH check (S08-S11) already ran inside
    // endpoint_init, so a packet that is both malformed and out of hop
    // limit is dropped for the former; both outcomes are a drop either way.
    //
    // The decrement is undone when the packet ends up going to the kernel
    // rather than out of an interface, because the kernel's own forwarding
    // spends one. See endpoint_settle_hop_limit.
    if (ip6h->hop_limit <= 1)
        return XDP_DROP;
    ip6h->hop_limit--;

    if (endpoint_update_da(ectx) != 0)
        return XDP_DROP;

    if (ectx->new_sl == 0 && entry->flavor == SRV6_LOCAL_FLAVOR_PSP)
        if (endpoint_strip_srh(ectx) != 0)
            return XDP_DROP;

    return -1;
}

// endpoint_settle_hop_limit reconciles the decrement made while advancing
// the segment list with what actually happened to the packet.
//
// A redirect leaves this node for good, so the hop stands. Anything else
// hands the packet to the kernel, whose IPv6 forwarding decrements again --
// keeping our decrement too would spend two hop limits on one hop. Give it
// back and let the kernel account for it.
static __always_inline int endpoint_settle_hop_limit(struct endpoint_ctx *ectx, int action)
{
    if (action == XDP_REDIRECT)
        return action;

    void *data = (void *)(long)ectx->ctx->data;
    void *data_end = (void *)(long)ectx->ctx->data_end;
    struct ipv6hdr *ip6h = (struct ipv6hdr *)(data + ectx->l3_offset);
    if ((void *)(ip6h + 1) > data_end)
        return XDP_DROP;
    ip6h->hop_limit++;
    return action;
}

#endif // SRV6_ENDPOINT_CORE_H
