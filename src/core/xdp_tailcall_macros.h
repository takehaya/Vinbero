#ifndef XDP_TAILCALL_MACROS_H
#define XDP_TAILCALL_MACROS_H

// Common macros for tail call targets.
// Depends on: xdp_tailcall_helpers.h (TAILCALL_RETURN, tailcall_ctx_read),
//             xdp_map.h (sid_aux_map), xdp_prog.h (ipv6_sr_hdr).

// Self-contained SRH parse for tail call targets.
// l3_off must be pre-bounded by caller via TAILCALL_BOUND_L3OFF.
// Separate bounds checks for each header — the verifier tracks per-pointer state.
#define TAILCALL_PARSE_SRH(ctx, l3_off, eth, ip6h, srh) do {                \
    void *_data = (void *)(long)(ctx)->data;                                  \
    void *_data_end = (void *)(long)(ctx)->data_end;                          \
    (eth) = (struct ethhdr *)_data;                                           \
    if ((void *)((eth) + 1) > _data_end)                                      \
        TAILCALL_RETURN(ctx,XDP_DROP);                              \
    (ip6h) = (struct ipv6hdr *)(_data + (l3_off));                            \
    if ((void *)((ip6h) + 1) > _data_end)                                     \
        TAILCALL_RETURN(ctx,XDP_DROP);                              \
    void *_srh_ptr = (void *)((ip6h) + 1);                                   \
    if (_srh_ptr + 8 > _data_end)                                             \
        TAILCALL_RETURN(ctx,XDP_DROP);                              \
    (srh) = (struct ipv6_sr_hdr *)_srh_ptr;                                   \
} while (0)

// Bound l3_offset from per-CPU map context. Max valid: Eth(14) + QinQ(8) = 22.
#define TAILCALL_BOUND_L3OFF(tctx, l3_off)                                    \
    __u16 l3_off = (tctx)->l3_offset;                                         \
    if ((l3_off) > 22) TAILCALL_RETURN(ctx,XDP_DROP)

// Call fn(ctx, ..., l3_offset) with l3_offset as a compile-time constant.
// The BPF verifier cannot track variable packet offsets through deeply-inlined
// helper chains that re-derive pointers from ctx->data. This switch converts
// the bounded l3_off (14/18/22) into a constant for each branch.
#define CALL_WITH_CONST_L3(l3_off, fn, ...)                                   \
    ({                                                                         \
        int _a;                                                                \
        switch (l3_off) {                                                      \
        case 18: _a = fn(__VA_ARGS__, 18); break;                              \
        case 22: _a = fn(__VA_ARGS__, 22); break;                              \
        default: _a = fn(__VA_ARGS__, 14); break;                              \
        }                                                                      \
        _a;                                                                    \
    })

// Lookup sid_aux_map when aux_index is non-zero. Index 0 is the "no aux"
// sentinel reserved by the userspace allocator.
//
// Plugin code uses this to read its own plugin_raw aux: a plugin SID's
// aux_entry holds bytes the plugin author laid out, and the plugin's own
// program is the only thing meant to interpret them.
#define TAILCALL_AUX_LOOKUP(tctx, aux)                                        \
    struct sid_aux_entry *(aux) = NULL;                                        \
    if ((tctx)->sid_entry.aux_index) {                                         \
        __u32 _idx = (tctx)->sid_entry.aux_index;                              \
        (aux) = bpf_map_lookup_elem(&sid_aux_map, &_idx);                      \
    }

// TAILCALL_BUILTIN_AUX_LOOKUP is TAILCALL_AUX_LOOKUP for vinbero's own
// behaviors, and it refuses the aux of a plugin-owned SID.
//
// The sid_aux_entry is a union discriminated by sid_entry.action. A
// built-in reads its own variant out of it -- End.DT4 reads l3vrf.vrf_ifindex,
// End.DX2 reads nexthop as an OIF, End.B6 reads a whole segment list. A
// plugin's data-plane half may bpf_tail_call into any built-in slot, and if
// it does, the built-in runs against the SID entry still describing the
// PLUGIN's SID -- whose aux is plugin_raw, bytes the plugin chose. Reading
// those as l3vrf.vrf_ifindex would let a plugin decapsulate into any VRF on
// the box, defeating the scope's VRF grant; reading them as End.B6's policy
// would let it encapsulate with an arbitrary segment list.
//
// The discriminator is the SID's own action. A plugin SID dispatches to an
// endpoint slot at or above ENDPOINT_PLUGIN_BASE, so an action in that range
// means the aux belongs to a plugin and no built-in variant describes it.
// The built-in gets NULL and falls back exactly as it does for a SID with no
// aux (End.DT4 uses the ingress ifindex, and so on).
#define TAILCALL_BUILTIN_AUX_LOOKUP(tctx, aux)                                 \
    struct sid_aux_entry *(aux) = NULL;                                        \
    if ((tctx)->sid_entry.aux_index &&                                         \
        (tctx)->sid_entry.action < ENDPOINT_PLUGIN_BASE) {                     \
        __u32 _idx = (tctx)->sid_entry.aux_index;                             \
        (aux) = bpf_map_lookup_elem(&sid_aux_map, &_idx);                      \
    }

// Headend tail call body macro (unified v4/v6).
// hdr_type: struct iphdr or struct ipv6hdr.
// Per-branch bounds checks with constant l3_off for BPF verifier.
#define HEADEND_BODY(fn_name, hdr_type)                                       \
    struct tailcall_ctx *tctx = tailcall_ctx_read();                          \
    if (!tctx) TAILCALL_RETURN(ctx,XDP_DROP);                                \
    TAILCALL_BOUND_L3OFF(tctx, l3_off);                                      \
    void *data = (void *)(long)ctx->data;                                    \
    void *data_end = (void *)(long)ctx->data_end;                            \
    int action;                                                               \
    if (l3_off == 18) {                                                       \
        struct ethhdr *eth = data;                                            \
        if ((void *)(eth + 1) > data_end) TAILCALL_RETURN(ctx,XDP_DROP);     \
        hdr_type *hdr = (hdr_type *)(data + 18);                             \
        if ((void *)(hdr + 1) > data_end) TAILCALL_RETURN(ctx,XDP_DROP);     \
        action = fn_name(ctx, eth, hdr, &tctx->headend, 18);                 \
    } else if (l3_off == 22) {                                                \
        struct ethhdr *eth = data;                                            \
        if ((void *)(eth + 1) > data_end) TAILCALL_RETURN(ctx,XDP_DROP);     \
        hdr_type *hdr = (hdr_type *)(data + 22);                             \
        if ((void *)(hdr + 1) > data_end) TAILCALL_RETURN(ctx,XDP_DROP);     \
        action = fn_name(ctx, eth, hdr, &tctx->headend, 22);                 \
    } else {                                                                  \
        struct ethhdr *eth = data;                                            \
        if ((void *)(eth + 1) > data_end) TAILCALL_RETURN(ctx,XDP_DROP);     \
        hdr_type *hdr = (hdr_type *)(data + 14);                             \
        if ((void *)(hdr + 1) > data_end) TAILCALL_RETURN(ctx,XDP_DROP);     \
        action = fn_name(ctx, eth, hdr, &tctx->headend, 14);                 \
    }                                                                         \
    TAILCALL_RETURN(ctx,action)

// Pattern A endpoint: localsid-only, no aux lookup
#define DEFINE_ENDPOINT_LOCALSID(prog_name, fn)                               \
SEC("xdp")                                                                    \
int prog_name(struct xdp_md *ctx)                                             \
{                                                                             \
    struct tailcall_ctx *tctx = tailcall_ctx_read();                          \
    if (!tctx) TAILCALL_RETURN(ctx, XDP_DROP);                               \
    TAILCALL_BOUND_L3OFF(tctx, l3_off);                                      \
                                                                              \
    struct ethhdr *eth;                                                       \
    struct ipv6hdr *ip6h;                                                     \
    struct ipv6_sr_hdr *srh;                                                  \
    TAILCALL_PARSE_SRH(ctx, l3_off, eth, ip6h, srh);                         \
                                                                              \
    int action = CALL_WITH_CONST_L3(l3_off, fn, ctx, ip6h, srh,              \
                                    &tctx->sid_entry);                        \
    TAILCALL_RETURN(ctx, action);                                             \
}

// Pattern A endpoint: localsid with aux lookup
#define DEFINE_ENDPOINT_LOCALSID_AUX(prog_name, fn)                           \
SEC("xdp")                                                                    \
int prog_name(struct xdp_md *ctx)                                             \
{                                                                             \
    struct tailcall_ctx *tctx = tailcall_ctx_read();                          \
    if (!tctx) TAILCALL_RETURN(ctx, XDP_DROP);                               \
    TAILCALL_BOUND_L3OFF(tctx, l3_off);                                      \
                                                                              \
    TAILCALL_BUILTIN_AUX_LOOKUP(tctx, aux);                                           \
                                                                              \
    struct ethhdr *eth;                                                       \
    struct ipv6hdr *ip6h;                                                     \
    struct ipv6_sr_hdr *srh;                                                  \
    TAILCALL_PARSE_SRH(ctx, l3_off, eth, ip6h, srh);                         \
                                                                              \
    int action = CALL_WITH_CONST_L3(l3_off, fn, ctx, ip6h, srh,              \
                                    &tctx->sid_entry, aux);                   \
    TAILCALL_RETURN(ctx, action);                                             \
}

// Pattern B endpoint: localsid + aux + dual-path (SRH-present or reduced encap)
//
// Generates a tailcall body that dispatches the same End.* behavior on either
// the SRH-present input (RFC 9433 §6.x nominal) or the reduced-encap input
// (RFC 8986 §4.1.1 H.Encaps with a single SID: outer IPv6 carries the inner
// protocol in `nexthdr` and no SRH is on the wire).
//
// Two process functions are required:
//   srh_fn(ctx, ip6h, srh, &sid_entry, aux, l3_off)
//     -- SRH path, identical shape to DEFINE_ENDPOINT_LOCALSID_AUX
//   nosrh_fn(ctx, ip6h, inner_proto, &sid_entry, aux, l3_off)
//     -- reduced-encap path; inner_proto is tctx->inner_proto (= ip6h->nexthdr
//        captured at dispatch time by process_srv6_decap_nosrh). The nosrh_fn
//        owns the outer-header strip (either via srv6_decap_*_nosrh() or an
//        inline bpf_xdp_adjust_head()).
//
// Use this macro for any End.* function that decapsulates the SR packet — the
// reduced-encap form lacks an SRH so callers cannot rely on a Routing header
// being present. Current users: End.DT2, End.DT2M, End.M.GTP4.E, End.M.GTP6.E.
// For transit/forwarding End.* (e.g. End.M.GTP6.D which advances the SR list
// and structurally requires `SL > 0` with an SRH), stay on Pattern A
// (DEFINE_ENDPOINT_LOCALSID_AUX).
#define DEFINE_ENDPOINT_LOCALSID_AUX_DUAL(prog_name, srh_fn, nosrh_fn)        \
SEC("xdp")                                                                    \
int prog_name(struct xdp_md *ctx)                                             \
{                                                                             \
    struct tailcall_ctx *tctx = tailcall_ctx_read();                          \
    if (!tctx) TAILCALL_RETURN(ctx, XDP_DROP);                                \
    TAILCALL_BOUND_L3OFF(tctx, l3_off);                                       \
                                                                              \
    TAILCALL_BUILTIN_AUX_LOOKUP(tctx, aux);                                           \
                                                                              \
    if (tctx->dispatch_type == DISPATCH_NOSRH) {                              \
        void *_data = (void *)(long)ctx->data;                                \
        void *_data_end = (void *)(long)ctx->data_end;                        \
        struct ipv6hdr *ip6h = (struct ipv6hdr *)(_data + l3_off);            \
        if ((void *)(ip6h + 1) > _data_end)                                   \
            TAILCALL_RETURN(ctx, XDP_DROP);                                   \
                                                                              \
        int action = CALL_WITH_CONST_L3(l3_off, nosrh_fn, ctx, ip6h,          \
                                        tctx->inner_proto,                    \
                                        &tctx->sid_entry, aux);               \
        TAILCALL_RETURN(ctx, action);                                         \
    }                                                                         \
                                                                              \
    struct ethhdr *eth;                                                       \
    struct ipv6hdr *ip6h;                                                     \
    struct ipv6_sr_hdr *srh;                                                  \
    TAILCALL_PARSE_SRH(ctx, l3_off, eth, ip6h, srh);                          \
                                                                              \
    int action = CALL_WITH_CONST_L3(l3_off, srh_fn, ctx, ip6h, srh,           \
                                    &tctx->sid_entry, aux);                   \
    TAILCALL_RETURN(ctx, action);                                             \
}

#endif // XDP_TAILCALL_MACROS_H
