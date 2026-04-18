// Endpoint tail call targets (16 SEC("xdp") programs).
// Included from xdp_prog.c — not compiled standalone.

// ========== Helpers shared by tail call targets (nosrh path) ==========

static __always_inline int nosrh_fib_v4(
    struct xdp_md *ctx,
    struct sid_function_entry *entry)
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

    __u32 fib_ifindex = entry->vrf_ifindex ? entry->vrf_ifindex : ctx->ingress_ifindex;
    int action = srv6_fib_redirect_v4(ctx, iph, eth, fib_ifindex);
    return (action == XDP_PASS) ? XDP_DROP : action;
}

static __always_inline int nosrh_fib_v6(
    struct xdp_md *ctx,
    struct sid_function_entry *entry)
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

    __u32 fib_ifindex = entry->vrf_ifindex ? entry->vrf_ifindex : ctx->ingress_ifindex;
    int action = srv6_fib_redirect(ctx, inner_ip6h, eth, fib_ifindex);
    return (action == XDP_PASS) ? XDP_DROP : action;
}

// ========== Pattern A: localsid-only actions ==========

DEFINE_ENDPOINT_LOCALSID(tailcall_endpoint_end, process_end)
DEFINE_ENDPOINT_LOCALSID(tailcall_endpoint_end_t, process_end_t)
DEFINE_ENDPOINT_LOCALSID(tailcall_endpoint_end_m_gtp6_d_di, process_end_m_gtp6_d_di)

DEFINE_ENDPOINT_LOCALSID_AUX(tailcall_endpoint_end_x, process_end_x)
DEFINE_ENDPOINT_LOCALSID_AUX(tailcall_endpoint_end_b6, process_end_b6_insert)
DEFINE_ENDPOINT_LOCALSID_AUX(tailcall_endpoint_end_b6_encaps, process_end_b6_encaps)
DEFINE_ENDPOINT_LOCALSID_AUX(tailcall_endpoint_end_m_gtp6_d, process_end_m_gtp6_d)
DEFINE_ENDPOINT_LOCALSID_AUX(tailcall_endpoint_end_m_gtp6_e, process_end_m_gtp6_e)
DEFINE_ENDPOINT_LOCALSID_AUX(tailcall_endpoint_end_m_gtp4_e, process_end_m_gtp4_e)

// ========== Pattern B: localsid + nosrh dual-path actions ==========

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

    if (tctx->dispatch_type == DISPATCH_NOSRH) {
        if (CALL_WITH_CONST_L3(l3_off, srv6_decap_nosrh, ctx, IPPROTO_IPIP, tctx->inner_proto) != 0)
            TAILCALL_RETURN(ctx,XDP_DROP);
        TAILCALL_RETURN(ctx,nosrh_fib_v4(ctx, &tctx->sid_entry));
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

    if (tctx->dispatch_type == DISPATCH_NOSRH) {
        if (CALL_WITH_CONST_L3(l3_off, srv6_decap_nosrh, ctx, IPPROTO_IPV6, tctx->inner_proto) != 0)
            TAILCALL_RETURN(ctx,XDP_DROP);
        TAILCALL_RETURN(ctx,nosrh_fib_v6(ctx, &tctx->sid_entry));
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

    if (tctx->dispatch_type == DISPATCH_NOSRH) {
        if (CALL_WITH_CONST_L3(l3_off, srv6_decap_nosrh, ctx, IPPROTO_IPIP, tctx->inner_proto) != 0)
            TAILCALL_RETURN(ctx,XDP_DROP);
        TAILCALL_RETURN(ctx,nosrh_fib_v4(ctx, &tctx->sid_entry));
    }

    struct ethhdr *eth;
    struct ipv6hdr *ip6h;
    struct ipv6_sr_hdr *srh;
    TAILCALL_PARSE_SRH(ctx, l3_off, eth, ip6h, srh);

    int action = CALL_WITH_CONST_L3(l3_off, process_end_dt4, ctx, ip6h, srh, &tctx->sid_entry);
    TAILCALL_RETURN(ctx,action);
}

SEC("xdp")
int tailcall_endpoint_end_dt6(struct xdp_md *ctx)
{
    struct tailcall_ctx *tctx = tailcall_ctx_read();
    if (!tctx) TAILCALL_RETURN(ctx,XDP_DROP);
    TAILCALL_BOUND_L3OFF(tctx, l3_off);

    if (tctx->dispatch_type == DISPATCH_NOSRH) {
        if (CALL_WITH_CONST_L3(l3_off, srv6_decap_nosrh, ctx, IPPROTO_IPV6, tctx->inner_proto) != 0)
            TAILCALL_RETURN(ctx,XDP_DROP);
        TAILCALL_RETURN(ctx,nosrh_fib_v6(ctx, &tctx->sid_entry));
    }

    struct ethhdr *eth;
    struct ipv6hdr *ip6h;
    struct ipv6_sr_hdr *srh;
    TAILCALL_PARSE_SRH(ctx, l3_off, eth, ip6h, srh);

    int action = CALL_WITH_CONST_L3(l3_off, process_end_dt6, ctx, ip6h, srh, &tctx->sid_entry);
    TAILCALL_RETURN(ctx,action);
}

SEC("xdp")
int tailcall_endpoint_end_dt46(struct xdp_md *ctx)
{
    struct tailcall_ctx *tctx = tailcall_ctx_read();
    if (!tctx) TAILCALL_RETURN(ctx,XDP_DROP);
    TAILCALL_BOUND_L3OFF(tctx, l3_off);

    if (tctx->dispatch_type == DISPATCH_NOSRH) {
        __u8 nh = tctx->inner_proto;
        if (nh == IPPROTO_IPIP) {
            if (CALL_WITH_CONST_L3(l3_off, srv6_decap_nosrh, ctx, IPPROTO_IPIP, nh) != 0)
                TAILCALL_RETURN(ctx,XDP_DROP);
            TAILCALL_RETURN(ctx,nosrh_fib_v4(ctx, &tctx->sid_entry));
        }
        if (nh == IPPROTO_IPV6) {
            if (CALL_WITH_CONST_L3(l3_off, srv6_decap_nosrh, ctx, IPPROTO_IPV6, nh) != 0)
                TAILCALL_RETURN(ctx,XDP_DROP);
            TAILCALL_RETURN(ctx,nosrh_fib_v6(ctx, &tctx->sid_entry));
        }
        TAILCALL_RETURN(ctx,XDP_DROP);
    }

    struct ethhdr *eth;
    struct ipv6hdr *ip6h;
    struct ipv6_sr_hdr *srh;
    TAILCALL_PARSE_SRH(ctx, l3_off, eth, ip6h, srh);

    int action = CALL_WITH_CONST_L3(l3_off, process_end_dt46, ctx, ip6h, srh, &tctx->sid_entry);
    TAILCALL_RETURN(ctx,action);
}

SEC("xdp")
int tailcall_endpoint_end_dt2(struct xdp_md *ctx)
{
    struct tailcall_ctx *tctx = tailcall_ctx_read();
    if (!tctx) TAILCALL_RETURN(ctx,XDP_DROP);
    TAILCALL_BOUND_L3OFF(tctx, l3_off);

    TAILCALL_AUX_LOOKUP(tctx, aux);

    if (tctx->dispatch_type == DISPATCH_NOSRH) {
        // Re-derive ip6h for process_end_dt2_nosrh
        void *data = (void *)(long)ctx->data;
        void *data_end = (void *)(long)ctx->data_end;
        struct ipv6hdr *ip6h = (struct ipv6hdr *)(data + l3_off);
        if ((void *)(ip6h + 1) > data_end)
            TAILCALL_RETURN(ctx,XDP_DROP);

        int action = CALL_WITH_CONST_L3(l3_off, process_end_dt2_nosrh, ctx, ip6h, tctx->inner_proto,
                                            &tctx->sid_entry, aux);
        TAILCALL_RETURN(ctx,action);
    }

    struct ethhdr *eth;
    struct ipv6hdr *ip6h;
    struct ipv6_sr_hdr *srh;
    TAILCALL_PARSE_SRH(ctx, l3_off, eth, ip6h, srh);

    int action = CALL_WITH_CONST_L3(l3_off, process_end_dt2, ctx, ip6h, srh, &tctx->sid_entry, aux);
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
