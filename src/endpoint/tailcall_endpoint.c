// Endpoint tail call targets (21 SEC("xdp") programs).
// Included from xdp_prog.c — not compiled standalone.

// ========== Helpers shared by tail call targets (nosrh path) ==========

static __always_inline int nosrh_fib_v4(
    struct xdp_md *ctx,
    struct sid_aux_entry *aux)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_DROP;

    eth->h_proto = bpf_htons(ETH_P_IP);

    __u32 fib_ifindex = aux_vrf_or_ingress_ifindex(aux, ctx);
    int action = srv6_fib_redirect_v4(ctx, iph, eth, fib_ifindex);
    return (action == XDP_PASS) ? XDP_DROP : action;
}

static __always_inline int nosrh_fib_v6(
    struct xdp_md *ctx,
    struct sid_aux_entry *aux)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    struct ipv6hdr *inner_ip6h = (void *)(eth + 1);
    if ((void *)(inner_ip6h + 1) > data_end)
        return XDP_DROP;

    eth->h_proto = bpf_htons(ETH_P_IPV6);

    __u32 fib_ifindex = aux_vrf_or_ingress_ifindex(aux, ctx);
    int action = srv6_fib_redirect(ctx, inner_ip6h, eth, fib_ifindex);
    return (action == XDP_PASS) ? XDP_DROP : action;
}

// ========== Pattern A: localsid-only actions ==========

DEFINE_ENDPOINT_LOCALSID(tailcall_endpoint_end, process_end)
DEFINE_ENDPOINT_LOCALSID(tailcall_endpoint_end_m_gtp6_d_di, process_end_m_gtp6_d_di)

DEFINE_ENDPOINT_LOCALSID_AUX(tailcall_endpoint_end_t, process_end_t)
DEFINE_ENDPOINT_LOCALSID_AUX(tailcall_endpoint_end_x, process_end_x)
DEFINE_ENDPOINT_LOCALSID_AUX(tailcall_endpoint_end_b6, process_end_b6_insert)
DEFINE_ENDPOINT_LOCALSID_AUX(tailcall_endpoint_end_b6_encaps, process_end_b6_encaps)
DEFINE_ENDPOINT_LOCALSID_AUX(tailcall_endpoint_end_m_gtp6_d, process_end_m_gtp6_d)

// ========== Pattern B: localsid + aux + SRH/no-SRH dual-path ==========
//
// One tailcall site handles both RFC 9433 §6.x nominal (SRH-present, SL=0) and
// RFC 8986 §4.1.1 single-SID H.Encaps reduced encap (no SRH on wire, IPv6
// nexthdr is the inner protocol). See xdp_tailcall_macros.h for the per-path
// contract. Used for End.* that decapsulate the SR packet.
DEFINE_ENDPOINT_LOCALSID_AUX_DUAL(tailcall_endpoint_end_m_gtp4_e,
                                  process_end_m_gtp4_e, process_end_m_gtp4_e_nosrh)
DEFINE_ENDPOINT_LOCALSID_AUX_DUAL(tailcall_endpoint_end_m_gtp6_e,
                                  process_end_m_gtp6_e, process_end_m_gtp6_e_nosrh)
DEFINE_ENDPOINT_LOCALSID_AUX_DUAL(tailcall_endpoint_end_dt2,
                                  process_end_dt2, process_end_dt2_nosrh)
DEFINE_ENDPOINT_LOCALSID_AUX_DUAL(tailcall_endpoint_end_dt2m,
                                  process_end_dt2m, process_end_dt2m_nosrh)

// ========== Pattern C: localsid + nosrh decap helper + FIB redirect ==========
//
// These targets share the nosrh path shape "srv6_decap_nosrh + nosrh_fib_*"
// rather than calling a *_nosrh process function, so they keep their
// handwritten bodies (the *_DUAL macro assumes the *_nosrh fn does its own
// stripping internally).

SEC("xdp")
int tailcall_endpoint_end_dx2(struct xdp_md *ctx)
{
    struct tailcall_ctx *tctx = tailcall_ctx_read();
    if (!tctx) TAILCALL_RETURN(ctx,XDP_DROP);
    TAILCALL_BOUND_L3OFF(tctx, l3_off);

    TAILCALL_AUX_LOOKUP(tctx, aux);

    if (tctx->dispatch_type == DISPATCH_NOSRH) {
        if (!aux) TAILCALL_RETURN(ctx,XDP_DROP);
        __u32 oif;
        __builtin_memcpy(&oif, aux->nexthop.nexthop, sizeof(__u32));
        if (oif == 0) TAILCALL_RETURN(ctx,XDP_DROP);
        if (CALL_WITH_CONST_L3(l3_off, srv6_decap_l2_nosrh, ctx, tctx->inner_proto) != 0)
            TAILCALL_RETURN(ctx,XDP_DROP);
        TAILCALL_RETURN(ctx,bpf_redirect(oif, 0));
    }

    struct ethhdr *eth;
    struct ipv6hdr *ip6h;
    struct ipv6_sr_hdr *srh;
    TAILCALL_PARSE_SRH(ctx, l3_off, eth, ip6h, srh);

    int action = CALL_WITH_CONST_L3(l3_off, process_end_dx2, ctx, ip6h, srh, &tctx->sid_entry, aux);
    TAILCALL_RETURN(ctx,action);
}

SEC("xdp")
int tailcall_endpoint_end_dx4(struct xdp_md *ctx)
{
    struct tailcall_ctx *tctx = tailcall_ctx_read();
    if (!tctx) TAILCALL_RETURN(ctx,XDP_DROP);
    TAILCALL_BOUND_L3OFF(tctx, l3_off);

    TAILCALL_AUX_LOOKUP(tctx, aux);

    if (tctx->dispatch_type == DISPATCH_NOSRH) {
        if (CALL_WITH_CONST_L3(l3_off, srv6_decap_nosrh, ctx, IPPROTO_IPIP, tctx->inner_proto) != 0)
            TAILCALL_RETURN(ctx,XDP_DROP);
        TAILCALL_RETURN(ctx,nosrh_fib_v4(ctx, aux));
    }

    struct ethhdr *eth;
    struct ipv6hdr *ip6h;
    struct ipv6_sr_hdr *srh;
    TAILCALL_PARSE_SRH(ctx, l3_off, eth, ip6h, srh);

    int action = CALL_WITH_CONST_L3(l3_off, process_end_dx4, ctx, ip6h, srh, &tctx->sid_entry);
    TAILCALL_RETURN(ctx,action);
}

SEC("xdp")
int tailcall_endpoint_end_dx6(struct xdp_md *ctx)
{
    struct tailcall_ctx *tctx = tailcall_ctx_read();
    if (!tctx) TAILCALL_RETURN(ctx,XDP_DROP);
    TAILCALL_BOUND_L3OFF(tctx, l3_off);

    TAILCALL_AUX_LOOKUP(tctx, aux);

    if (tctx->dispatch_type == DISPATCH_NOSRH) {
        if (CALL_WITH_CONST_L3(l3_off, srv6_decap_nosrh, ctx, IPPROTO_IPV6, tctx->inner_proto) != 0)
            TAILCALL_RETURN(ctx,XDP_DROP);
        TAILCALL_RETURN(ctx,nosrh_fib_v6(ctx, aux));
    }

    struct ethhdr *eth;
    struct ipv6hdr *ip6h;
    struct ipv6_sr_hdr *srh;
    TAILCALL_PARSE_SRH(ctx, l3_off, eth, ip6h, srh);

    int action = CALL_WITH_CONST_L3(l3_off, process_end_dx6, ctx, ip6h, srh, &tctx->sid_entry);
    TAILCALL_RETURN(ctx,action);
}

SEC("xdp")
int tailcall_endpoint_end_dt4(struct xdp_md *ctx)
{
    struct tailcall_ctx *tctx = tailcall_ctx_read();
    if (!tctx) TAILCALL_RETURN(ctx,XDP_DROP);
    TAILCALL_BOUND_L3OFF(tctx, l3_off);

    TAILCALL_AUX_LOOKUP(tctx, aux);

    if (tctx->dispatch_type == DISPATCH_NOSRH) {
        if (CALL_WITH_CONST_L3(l3_off, srv6_decap_nosrh, ctx, IPPROTO_IPIP, tctx->inner_proto) != 0)
            TAILCALL_RETURN(ctx,XDP_DROP);
        TAILCALL_RETURN(ctx,nosrh_fib_v4(ctx, aux));
    }

    struct ethhdr *eth;
    struct ipv6hdr *ip6h;
    struct ipv6_sr_hdr *srh;
    TAILCALL_PARSE_SRH(ctx, l3_off, eth, ip6h, srh);

    int action = CALL_WITH_CONST_L3(l3_off, process_end_dt4, ctx, ip6h, srh, &tctx->sid_entry, aux);
    TAILCALL_RETURN(ctx,action);
}

SEC("xdp")
int tailcall_endpoint_end_dt6(struct xdp_md *ctx)
{
    struct tailcall_ctx *tctx = tailcall_ctx_read();
    if (!tctx) TAILCALL_RETURN(ctx,XDP_DROP);
    TAILCALL_BOUND_L3OFF(tctx, l3_off);

    TAILCALL_AUX_LOOKUP(tctx, aux);

    if (tctx->dispatch_type == DISPATCH_NOSRH) {
        if (CALL_WITH_CONST_L3(l3_off, srv6_decap_nosrh, ctx, IPPROTO_IPV6, tctx->inner_proto) != 0)
            TAILCALL_RETURN(ctx,XDP_DROP);
        TAILCALL_RETURN(ctx,nosrh_fib_v6(ctx, aux));
    }

    struct ethhdr *eth;
    struct ipv6hdr *ip6h;
    struct ipv6_sr_hdr *srh;
    TAILCALL_PARSE_SRH(ctx, l3_off, eth, ip6h, srh);

    int action = CALL_WITH_CONST_L3(l3_off, process_end_dt6, ctx, ip6h, srh, &tctx->sid_entry, aux);
    TAILCALL_RETURN(ctx,action);
}

SEC("xdp")
int tailcall_endpoint_end_dt46(struct xdp_md *ctx)
{
    struct tailcall_ctx *tctx = tailcall_ctx_read();
    if (!tctx) TAILCALL_RETURN(ctx,XDP_DROP);
    TAILCALL_BOUND_L3OFF(tctx, l3_off);

    TAILCALL_AUX_LOOKUP(tctx, aux);

    if (tctx->dispatch_type == DISPATCH_NOSRH) {
        __u8 nh = tctx->inner_proto;
        if (nh == IPPROTO_IPIP) {
            if (CALL_WITH_CONST_L3(l3_off, srv6_decap_nosrh, ctx, IPPROTO_IPIP, nh) != 0)
                TAILCALL_RETURN(ctx,XDP_DROP);
            TAILCALL_RETURN(ctx,nosrh_fib_v4(ctx, aux));
        }
        if (nh == IPPROTO_IPV6) {
            if (CALL_WITH_CONST_L3(l3_off, srv6_decap_nosrh, ctx, IPPROTO_IPV6, nh) != 0)
                TAILCALL_RETURN(ctx,XDP_DROP);
            TAILCALL_RETURN(ctx,nosrh_fib_v6(ctx, aux));
        }
        TAILCALL_RETURN(ctx,XDP_DROP);
    }

    struct ethhdr *eth;
    struct ipv6hdr *ip6h;
    struct ipv6_sr_hdr *srh;
    TAILCALL_PARSE_SRH(ctx, l3_off, eth, ip6h, srh);

    int action = CALL_WITH_CONST_L3(l3_off, process_end_dt46, ctx, ip6h, srh, &tctx->sid_entry, aux);
    TAILCALL_RETURN(ctx,action);
}

// End.AS: same handwritten shape as End.DX4/DX6 — the nosrh branch calls
// srv6_decap*_nosrh directly with a constant expected proto per family and
// must NOT pre-derive ip6h (the DUAL macro's ip6h bounds check lets clang
// elide the decap helper's own eth check, which the verifier then rejects
// on the merged path).
SEC("xdp")
int tailcall_endpoint_end_as(struct xdp_md *ctx)
{
    struct tailcall_ctx *tctx = tailcall_ctx_read();
    if (!tctx) TAILCALL_RETURN(ctx,XDP_DROP);
    TAILCALL_BOUND_L3OFF(tctx, l3_off);

    TAILCALL_AUX_LOOKUP(tctx, aux);
    if (!aux) TAILCALL_RETURN(ctx,XDP_DROP);
    __u8 inner_type = aux->service.inner_type;

    if (tctx->dispatch_type == DISPATCH_NOSRH) {
        if (inner_type == SVC_INNER_ETHERNET) {
            if (aux->service.iface_out == 0)
                TAILCALL_RETURN(ctx,XDP_DROP);
            if (CALL_WITH_CONST_L3(l3_off, srv6_decap_l2_nosrh, ctx, tctx->inner_proto) != 0)
                TAILCALL_RETURN(ctx,XDP_DROP);
            TAILCALL_RETURN(ctx,bpf_redirect(aux->service.iface_out, 0));
        }
        if (inner_type == SVC_INNER_IPV4) {
            if (CALL_WITH_CONST_L3(l3_off, srv6_decap_nosrh, ctx, IPPROTO_IPIP, tctx->inner_proto) != 0)
                TAILCALL_RETURN(ctx,XDP_DROP);
            TAILCALL_RETURN(ctx,svc_fwd_l3_out(ctx, aux, SVC_INNER_IPV4));
        }
        if (inner_type == SVC_INNER_IPV6) {
            if (CALL_WITH_CONST_L3(l3_off, srv6_decap_nosrh, ctx, IPPROTO_IPV6, tctx->inner_proto) != 0)
                TAILCALL_RETURN(ctx,XDP_DROP);
            TAILCALL_RETURN(ctx,svc_fwd_l3_out(ctx, aux, SVC_INNER_IPV6));
        }
        TAILCALL_RETURN(ctx,XDP_DROP);
    }

    struct ethhdr *eth;
    struct ipv6hdr *ip6h;
    struct ipv6_sr_hdr *srh;
    TAILCALL_PARSE_SRH(ctx, l3_off, eth, ip6h, srh);

    int action = CALL_WITH_CONST_L3(l3_off, process_end_as, ctx, ip6h, srh,
                                    &tctx->sid_entry, aux);
    TAILCALL_RETURN(ctx,action);
}

// End.AD: SRH-only (reduced encap carries no next segment, so there is no
// valid return state to cache — the front door would loop the return
// traffic back to this very SID). Cache seeding and delivery live in
// process_end_ad / svc_ad_cache_seed.
SEC("xdp")
int tailcall_endpoint_end_ad(struct xdp_md *ctx)
{
    struct tailcall_ctx *tctx = tailcall_ctx_read();
    if (!tctx) TAILCALL_RETURN(ctx,XDP_DROP);
    TAILCALL_BOUND_L3OFF(tctx, l3_off);

    TAILCALL_AUX_LOOKUP(tctx, aux);
    if (!aux) TAILCALL_RETURN(ctx,XDP_DROP);

    if (tctx->dispatch_type == DISPATCH_NOSRH)
        TAILCALL_RETURN(ctx,XDP_DROP);

    struct ethhdr *eth;
    struct ipv6hdr *ip6h;
    struct ipv6_sr_hdr *srh;
    TAILCALL_PARSE_SRH(ctx, l3_off, eth, ip6h, srh);

    int action = CALL_WITH_CONST_L3(l3_off, process_end_ad, ctx, ip6h, srh,
                                    &tctx->sid_entry, aux);
    TAILCALL_RETURN(ctx,action);
}

// End.AM: SRH-only like End.AD — the reduced-encap form carries no SRH to
// masquerade or de-masquerade against.
SEC("xdp")
int tailcall_endpoint_end_am(struct xdp_md *ctx)
{
    struct tailcall_ctx *tctx = tailcall_ctx_read();
    if (!tctx) TAILCALL_RETURN(ctx,XDP_DROP);
    TAILCALL_BOUND_L3OFF(tctx, l3_off);

    TAILCALL_AUX_LOOKUP(tctx, aux);
    if (!aux) TAILCALL_RETURN(ctx,XDP_DROP);

    if (tctx->dispatch_type == DISPATCH_NOSRH)
        TAILCALL_RETURN(ctx,XDP_DROP);

    struct ethhdr *eth;
    struct ipv6hdr *ip6h;
    struct ipv6_sr_hdr *srh;
    TAILCALL_PARSE_SRH(ctx, l3_off, eth, ip6h, srh);

    int action = CALL_WITH_CONST_L3(l3_off, process_end_am, ctx, ip6h, srh,
                                    &tctx->sid_entry, aux);
    TAILCALL_RETURN(ctx,action);
}

SEC("xdp")
int tailcall_endpoint_end_dx2v(struct xdp_md *ctx)
{
    struct tailcall_ctx *tctx = tailcall_ctx_read();
    if (!tctx) TAILCALL_RETURN(ctx,XDP_DROP);
    TAILCALL_BOUND_L3OFF(tctx, l3_off);

    TAILCALL_AUX_LOOKUP(tctx, aux);

    if (tctx->dispatch_type == DISPATCH_NOSRH) {
        if (!aux) TAILCALL_RETURN(ctx,XDP_DROP);
        int action = CALL_WITH_CONST_L3(l3_off, process_end_dx2v_nosrh, ctx,
                                        tctx->inner_proto, aux);
        TAILCALL_RETURN(ctx,action);
    }

    struct ethhdr *eth;
    struct ipv6hdr *ip6h;
    struct ipv6_sr_hdr *srh;
    TAILCALL_PARSE_SRH(ctx, l3_off, eth, ip6h, srh);

    int action = CALL_WITH_CONST_L3(l3_off, process_end_dx2v, ctx, ip6h, srh,
                                    &tctx->sid_entry, aux);
    TAILCALL_RETURN(ctx,action);
}
