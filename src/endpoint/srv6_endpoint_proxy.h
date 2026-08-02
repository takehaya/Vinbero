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

// ========== End.AD (dynamic proxy) forward direction ==========

// svc_ad_cache_seed captures the outer IPv6 + SRH (already SL-decremented
// and DA-updated, i.e. ready to prepend verbatim on return) into
// ad_cache_map keyed by the proxy's IFACE-IN circuit. The update-skip rule
// avoids hammering the shared cache line on every packet of a stable
// chain: an existing entry is left alone when the length matches, the
// header bytes (flow label zeroed) match, and the hop limit moved less
// than the configured margin. Returns 0 on success (or skip), -1 on a
// packet/verifier bound failure.
static __noinline int svc_ad_cache_seed(
    struct xdp_md *ctx,
    struct sid_aux_entry *aux,
    __u16 l3_offset,
    __u16 srh_len)
{
    if (srh_len < 8 || srh_len > 8 + MAX_SEGMENTS * 16)
        return -1;
    // u32 on purpose: a u16 would get an "& 0xffff" truncation before the
    // helper call, which resets the verifier's lower bound and turns the
    // range into [0, N] ("invalid zero-sized read").
    __u32 hdr_len = sizeof(struct ipv6hdr) + (__u32)srh_len;
    // Reject anything the constant-size copy switches below cannot handle
    // (only 40 + 8 + n*16, i.e. a segments-only SRH) BEFORE the row is
    // invalidated. An SRH carrying TLVs / padding — a legitimate HMAC TLV
    // makes hdrlen odd, or a crafted value — otherwise passes the range
    // check, flips valid to 0, then falls into the seed switch's default:
    // and leaves a previously good cache row dead: a one-packet denial of
    // service against the return path. End.AD does not support TLV-bearing
    // SRH; such chains are dropped here without touching the cache.
    if (hdr_len < sizeof(struct ipv6hdr) + 8 || hdr_len > AD_CACHE_HDR_MAX ||
        (hdr_len & 15) != 0)
        return -1;

    struct service_ingress_key key = {
        .ifindex = aux->service.iface_in,
        .vlan_id = aux->service.vlan_in,
    };

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ipv6hdr *ip6h = (struct ipv6hdr *)(data + l3_offset);
    if ((void *)(ip6h + 1) > data_end)
        return -1;
    // The whole header we are about to capture must actually be on the
    // wire BEFORE the existing row is invalidated: a truncated packet
    // with an inflated SRH hdrlen would otherwise flip valid to 0, fail
    // the copy, and leave a previously good cache row dead — a one-packet
    // denial of service against the return path.
    if (data + l3_offset + hdr_len > data_end)
        return -1;
    __u8 hop_limit = ip6h->hop_limit;

    struct ad_cache_val *val = bpf_map_lookup_elem(&ad_cache_map, &key);
    if (!val) {
        // First packet on this circuit: materialize the row, then fill
        // it in place (the value is far too large for the BPF stack).
        struct ad_cache_val zero = {};
        if (bpf_map_update_elem(&ad_cache_map, &key, &zero, BPF_ANY))
            return -1;
        val = bpf_map_lookup_elem(&ad_cache_map, &key);
        if (!val)
            return -1;
    } else if (val->valid && val->hdr_len == hdr_len) {
        // Update-skip: leave a stable chain's cache line alone. The whole
        // header (outer IPv6 + SRH + every segment) must match — a chain
        // that reroutes behind an unchanged next segment must still
        // refresh the cache. Excluded from the comparison: payload_len
        // (per-packet), hop_limit (tolerated within the margin), and the
        // flow label (zeroed at capture time).
        __u8 margin = aux->service.hop_limit_margin;
        __u8 diff = val->hop_limit > hop_limit ? val->hop_limit - hop_limit
                                               : hop_limit - val->hop_limit;
        if (diff <= margin) {
            // Constant trip count per possible length: a loop bound by
            // the variable hdr_len leaves the &val->hdr[off] access
            // unprovable on kernel 6.1 (its verifier does not refine off
            // from the break comparison the way newer ones do).
            int same = 1;
            switch (hdr_len) {
#define AD_CMP_CHUNKS(n)                                                   \
    case (n):                                                              \
        for (int off = 0; off < (n); off += 16) {                          \
            __u8 chunk[16];                                                \
            if (bpf_xdp_load_bytes(ctx, l3_offset + off, chunk, 16)) {     \
                same = 0;                                                  \
                break;                                                     \
            }                                                              \
            if (off == 0) {                                                \
                /* byte0 = version|TC-high, byte1 = TC-low|FL-high; keep  */\
                /* the version nibble, drop the whole Traffic Class and   */\
                /* Flow Label (all per-packet) so DSCP churn does not      */\
                /* force a re-seed.                                        */\
                chunk[0] &= 0xf0;                                          \
                chunk[1] = 0;                                              \
                chunk[2] = 0;                                              \
                chunk[3] = 0;                                              \
                chunk[4] = val->hdr[4]; /* payload_len: per-packet */      \
                chunk[5] = val->hdr[5];                                    \
                chunk[7] = val->hdr[7]; /* hop_limit: margin-checked */    \
            }                                                              \
            if (__builtin_memcmp(chunk, &val->hdr[off], 16) != 0) {        \
                same = 0;                                                  \
                break;                                                     \
            }                                                              \
        }                                                                  \
        break;
            AD_CMP_CHUNKS(48)  AD_CMP_CHUNKS(64)  AD_CMP_CHUNKS(80)
            AD_CMP_CHUNKS(96)  AD_CMP_CHUNKS(112) AD_CMP_CHUNKS(128)
            AD_CMP_CHUNKS(144) AD_CMP_CHUNKS(160) AD_CMP_CHUNKS(176)
            AD_CMP_CHUNKS(192) AD_CMP_CHUNKS(208)
#undef AD_CMP_CHUNKS
            default:
                same = 0;
            }
            if (same)
                return 0;
        }
    }

    // Seqlock publish protocol for concurrent return-path readers: bump
    // seq to an odd value before the bytes change and back to even after.
    // valid stays as the "seeded at least once" flag. A reader that sees
    // an even seq, copies the row, and re-reads the same seq observed a
    // consistent header; if seq moved (or is odd) it drops the packet
    // rather than replaying a torn — but still syntactically valid, hence
    // silently mis-delivered — header. The compiler barriers pin the
    // store order; BPF has no portable release/acquire fence on our oldest
    // kernels, so on weakly-ordered CPUs the guarantee is "a torn read is
    // caught and dropped", not "never observed".
    val->valid = 0;
    val->seq++; // now odd: writer in progress
    asm volatile("" ::: "memory");
    // Constant-size copy per possible header length: a variable length
    // reaches the helper with its verifier lower bound destroyed (clang
    // range-checks a derived register, so the refinement never propagates
    // back — "invalid zero-sized read"). A well-formed SRH holds 0..10
    // 16-byte segments, so hdr_len has exactly 11 possible values.
    switch (hdr_len) {
#define AD_SEED_CASE(n)                                            \
    case (n):                                                      \
        if (bpf_xdp_load_bytes(ctx, l3_offset, val->hdr, (n)))     \
            return -1;                                             \
        break;
    AD_SEED_CASE(48)  AD_SEED_CASE(64)  AD_SEED_CASE(80)
    AD_SEED_CASE(96)  AD_SEED_CASE(112) AD_SEED_CASE(128)
    AD_SEED_CASE(144) AD_SEED_CASE(160) AD_SEED_CASE(176)
    AD_SEED_CASE(192) AD_SEED_CASE(208)
#undef AD_SEED_CASE
    default:
        return -1;
    }
    // Normalize the per-packet fields so the update-skip comparison above
    // matches a stable chain regardless of DSCP / flow-label churn. byte0
    // = version|TC-high, byte1 = TC-low|FL-high: keep the version nibble,
    // zero the whole Traffic Class and Flow Label. Without this, DSCP-mixed
    // traffic on one circuit would re-seed the 208-byte row every packet.
    val->hdr[0] &= 0xf0;
    val->hdr[1] = 0;
    val->hdr[2] = 0;
    val->hdr[3] = 0;
    val->hdr_len = hdr_len;
    val->hop_limit = hop_limit;
    asm volatile("" ::: "memory");
    val->valid = 1;
    val->seq++; // back to even: update complete
    return 0;
}

// End.AD forward, SRH present. Standard End processing (SL--, DA update)
// on the outer header first, so the cached copy is ready to prepend on
// return; then the same decap-and-deliver as End.AS. SL == 0 is a drop:
// with no next segment there is no valid return state to cache (and the
// reduced-encap form is rejected at the tail-call target for the same
// reason).
static __always_inline int process_end_ad(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ipv6_sr_hdr *srh,
    struct sid_function_entry *entry,
    struct sid_aux_entry *aux,
    __u16 l3_offset)
{
    if (!aux)
        return XDP_DROP;

    struct endpoint_ctx ectx;
    int ret = endpoint_init(&ectx, ctx, ip6h, srh, entry, l3_offset);
    if (ret != 0)
        return XDP_DROP; // SL == 0 (-1) or malformed SL (-2)

    // The dynamic cache stores the outer IPv6 + SRH verbatim and replays it,
    // so End.AD only supports a segments-only SRH. hdrlen counts 8-byte
    // units; a segments-only header is exactly (first_segment + 1) segments
    // of 16 bytes = (first_segment + 1) * 2 units. Any other value means a
    // TLV or padding is present (a 16-byte-aligned TLV would otherwise slip
    // past the length guard in svc_ad_cache_seed) — reject it here, before
    // endpoint_update_da mutates the header, so such chains drop cleanly
    // instead of being cached as an unreplayable shape.
    if (srh->hdrlen != (__u16)(srh->first_segment + 1) * 2)
        return XDP_DROP;

    if (endpoint_update_da(&ectx) != 0)
        return XDP_DROP;

    __u16 srh_len = 8 + ((__u16)srh->hdrlen * 8);
    if (svc_ad_cache_seed(ctx, aux, l3_offset, srh_len) != 0)
        return XDP_DROP;

    // Delivery to the service is identical to End.AS from here on.
    return process_end_as(ctx, ip6h, srh, entry, aux, l3_offset);
}

// ========== End.AM (masquerading proxy) forward direction ==========

// End.AM forward: decrement SL, masquerade the destination as the final
// segment (Segment List[0]) and hand the packet — SRH and all — to the
// service. The service must ignore extension headers; the return path
// de-masquerades from the in-packet SRH, so unlike AS/AD there is no
// out-of-band state. L3 payloads only (the draft defines no L2 form) and
// the delivery is always the pre-resolved static MAC: after masquerading
// the DA names the chain's final destination, so a FIB lookup would route
// straight past the service.
static __always_inline int process_end_am(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ipv6_sr_hdr *srh,
    struct sid_function_entry *entry,
    struct sid_aux_entry *aux,
    __u16 l3_offset)
{
    if (!aux)
        return XDP_DROP;
    if (!(aux->service.flags & SVC_AUX_F_STATIC_MAC) ||
        aux->service.iface_out == 0)
        return XDP_DROP;
    if (srh->nexthdr == IPPROTO_ETHERNET)
        return XDP_DROP;

    struct endpoint_ctx ectx;
    int ret = endpoint_init(&ectx, ctx, ip6h, srh, entry, l3_offset);
    if (ret != 0)
        return XDP_DROP; // SL == 0 (the draft drops) or malformed SL

    // Masquerade: SL consumed, DA = Segment List[0] (the final segment).
    srh->segments_left = ectx.new_sl;
    void *seg_base = (void *)srh + 8;
    if (copy_segment_by_index(&ip6h->daddr, seg_base, ectx.data_end, 0) != 0)
        return XDP_DROP;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;
    __builtin_memcpy(eth->h_dest, aux->service.dmac, ETH_ALEN);
    __builtin_memcpy(eth->h_source, aux->service.smac, ETH_ALEN);
    return bpf_redirect(aux->service.iface_out, 0);
}

#endif // SRV6_ENDPOINT_PROXY_H
