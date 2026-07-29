#ifndef SRV6_ENDPOINT_PROXY_H
#define SRV6_ENDPOINT_PROXY_H

// Service programming proxies, forward direction (SRv6 -> service).
// draft-ietf-spring-srv6-service-programming: the SR-unaware service sees
// only the inner payload, so the proxy strips the SR encapsulation here
// and hands the bare packet to the service on IFACE-OUT. The chain state
// travels out of band (End.AS: static CACHE in service_ingress_map), so
// unlike End.DX*/DT* the decap does NOT require SL == 0 — the proxy
// usually sits mid-chain with segments still left after the service.

#include "endpoint/srv6_endpoint_core.h"

// Emit a decapsulated L3 packet towards the service. The frame's Ethernet
// header was preserved by srv6_decap*; only the ethertype (and, in static
// MAC mode, the MACs) need rewriting.
static __always_inline int svc_fwd_l3_out(
    struct xdp_md *ctx,
    struct sid_aux_entry *aux,
    __u8 inner_type)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    eth->h_proto = (inner_type == SVC_INNER_IPV4) ? bpf_htons(ETH_P_IP)
                                                  : bpf_htons(ETH_P_IPV6);

    if (aux->service.flags & SVC_AUX_F_STATIC_MAC) {
        if (aux->service.iface_out == 0)
            return XDP_DROP;
        __builtin_memcpy(eth->h_dest, aux->service.dmac, ETH_ALEN);
        __builtin_memcpy(eth->h_source, aux->service.smac, ETH_ALEN);
        return bpf_redirect(aux->service.iface_out, 0);
    }

    // FIB mode: the operator routes the inner destination via IFACE-OUT,
    // so a plain lookup resolves the service-facing next hop and MACs.
    if (inner_type == SVC_INNER_IPV4) {
        struct iphdr *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end)
            return XDP_DROP;
        int action = srv6_fib_redirect_v4(ctx, iph, eth, ctx->ingress_ifindex);
        return (action == XDP_PASS) ? XDP_DROP : action;
    }
    struct ipv6hdr *inner_ip6h = (void *)(eth + 1);
    if ((void *)(inner_ip6h + 1) > data_end)
        return XDP_DROP;
    int action = srv6_fib_redirect(ctx, inner_ip6h, eth, ctx->ingress_ifindex);
    return (action == XDP_PASS) ? XDP_DROP : action;
}

// End.AS forward, SRH present. Strips the whole SR encapsulation (any SL —
// the static CACHE re-creates the chain on return) and forwards the inner
// payload to the service.
static __always_inline int process_end_as(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ipv6_sr_hdr *srh,
    struct sid_function_entry *entry,
    struct sid_aux_entry *aux,
    __u16 l3_offset)
{
    if (!aux)
        return XDP_DROP;

    if (aux->service.inner_type == SVC_INNER_ETHERNET) {
        if (srh->nexthdr != IPPROTO_ETHERNET)
            return XDP_DROP;
        if (aux->service.iface_out == 0)
            return XDP_DROP;
        int strip_len = calc_decap_strip_len(srh, l3_offset);
        if (bpf_xdp_adjust_head(ctx, strip_len))
            return XDP_DROP;
        void *data = (void *)(long)ctx->data;
        void *data_end = (void *)(long)ctx->data_end;
        struct ethhdr *inner_eth = data;
        if ((void *)(inner_eth + 1) > data_end)
            return XDP_DROP;
        return bpf_redirect(aux->service.iface_out, 0);
    }

    // Constant expected-proto per branch: a runtime-selected proto value
    // defeats the verifier's packet-bounds tracking through the inlined
    // decap chain (each branch inlines its own fully-constant copy).
    if (aux->service.inner_type == SVC_INNER_IPV4) {
        if (srv6_decap(ctx, srh, IPPROTO_IPIP, l3_offset) != 0)
            return XDP_DROP;
        return svc_fwd_l3_out(ctx, aux, SVC_INNER_IPV4);
    }
    if (aux->service.inner_type == SVC_INNER_IPV6) {
        if (srv6_decap(ctx, srh, IPPROTO_IPV6, l3_offset) != 0)
            return XDP_DROP;
        return svc_fwd_l3_out(ctx, aux, SVC_INNER_IPV6);
    }
    return XDP_DROP;
}

// The reduced-encap (no SRH) forward path lives directly in the
// tailcall_endpoint_end_as target: it must call srv6_decap*_nosrh without
// a preceding ip6h derivation (see the comment on the target).

#endif // SRV6_ENDPOINT_PROXY_H
