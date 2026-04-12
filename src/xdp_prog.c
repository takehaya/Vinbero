#include <linux/types.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <stdbool.h>
#include <stddef.h>

#include "core/xdp_prog.h"
#include "core/xdp_map.h"
#include "core/srv6.h"
#include "headend/srv6_headend_utils.h"
#include "headend/srv6_headend.h"
#include "headend/srv6_encaps.h"
#include "headend/srv6_encaps_red.h"
#include "headend/srv6_insert.h"
#include "core/xdp_stats.h"
#include "core/xdpcap.h"
#include "endpoint/srv6_endpoint.h"
#include "endpoint/srv6_end_b6.h"
#include "l2vpn/bum_meta.h"
#include "core/srv6_gtp.h"
#include "endpoint/srv6_gtp_endpoint.h"
#include "endpoint/srv6_gtp_encap.h"
#include "headend/srv6_gtp_headend.h"

char _license[] SEC("license") = "GPL";

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
    STATS_INC(STATS_SRV6_END, 0);

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
    STATS_INC(STATS_SRV6_END, 0);

    __u32 fib_ifindex = entry->vrf_ifindex ? entry->vrf_ifindex : ctx->ingress_ifindex;
    int action = srv6_fib_redirect(ctx, inner_ip6h, eth, fib_ifindex);
    return (action == XDP_PASS) ? XDP_DROP : action;
}

// ========== Common macros for localsid tail call targets ==========

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

// Lookup sid_aux_map if has_aux is set
#define TAILCALL_AUX_LOOKUP(tctx, aux)                                        \
    struct sid_aux_entry *(aux) = NULL;                                        \
    if ((tctx)->sid_entry.has_aux) {                                           \
        __u32 _idx = (tctx)->sid_entry.aux_index;                              \
        (aux) = bpf_map_lookup_elem(&sid_aux_map, &_idx);                      \
    }

// ========== Endpoint Tail Call Targets (16 programs) ==========

// --- Pattern A: localsid-only actions ---

SEC("xdp")
int tailcall_endpoint_end(struct xdp_md *ctx)
{
    struct tailcall_ctx *tctx = tailcall_ctx_read();
    if (!tctx) TAILCALL_RETURN(ctx,XDP_DROP);
    TAILCALL_BOUND_L3OFF(tctx, l3_off);

    struct ethhdr *eth;
    struct ipv6hdr *ip6h;
    struct ipv6_sr_hdr *srh;
    TAILCALL_PARSE_SRH(ctx, l3_off, eth, ip6h, srh);

    int action = CALL_WITH_CONST_L3(l3_off, process_end, ctx, ip6h, srh, &tctx->sid_entry);
    TAILCALL_RETURN(ctx,action);
}

SEC("xdp")
int tailcall_endpoint_end_x(struct xdp_md *ctx)
{
    struct tailcall_ctx *tctx = tailcall_ctx_read();
    if (!tctx) TAILCALL_RETURN(ctx,XDP_DROP);
    TAILCALL_BOUND_L3OFF(tctx, l3_off);

    TAILCALL_AUX_LOOKUP(tctx, aux);

    struct ethhdr *eth;
    struct ipv6hdr *ip6h;
    struct ipv6_sr_hdr *srh;
    TAILCALL_PARSE_SRH(ctx, l3_off, eth, ip6h, srh);

    int action = CALL_WITH_CONST_L3(l3_off, process_end_x, ctx, ip6h, srh, &tctx->sid_entry, aux);
    TAILCALL_RETURN(ctx,action);
}

SEC("xdp")
int tailcall_endpoint_end_t(struct xdp_md *ctx)
{
    struct tailcall_ctx *tctx = tailcall_ctx_read();
    if (!tctx) TAILCALL_RETURN(ctx,XDP_DROP);
    TAILCALL_BOUND_L3OFF(tctx, l3_off);

    struct ethhdr *eth;
    struct ipv6hdr *ip6h;
    struct ipv6_sr_hdr *srh;
    TAILCALL_PARSE_SRH(ctx, l3_off, eth, ip6h, srh);

    int action = CALL_WITH_CONST_L3(l3_off, process_end_t, ctx, ip6h, srh, &tctx->sid_entry);
    TAILCALL_RETURN(ctx,action);
}

SEC("xdp")
int tailcall_endpoint_end_b6(struct xdp_md *ctx)
{
    struct tailcall_ctx *tctx = tailcall_ctx_read();
    if (!tctx) TAILCALL_RETURN(ctx,XDP_DROP);
    TAILCALL_BOUND_L3OFF(tctx, l3_off);

    TAILCALL_AUX_LOOKUP(tctx, aux);

    struct ethhdr *eth;
    struct ipv6hdr *ip6h;
    struct ipv6_sr_hdr *srh;
    TAILCALL_PARSE_SRH(ctx, l3_off, eth, ip6h, srh);

    int action = CALL_WITH_CONST_L3(l3_off, process_end_b6_insert, ctx, ip6h, srh, &tctx->sid_entry, aux);
    TAILCALL_RETURN(ctx,action);
}

SEC("xdp")
int tailcall_endpoint_end_b6_encaps(struct xdp_md *ctx)
{
    struct tailcall_ctx *tctx = tailcall_ctx_read();
    if (!tctx) TAILCALL_RETURN(ctx,XDP_DROP);
    TAILCALL_BOUND_L3OFF(tctx, l3_off);

    TAILCALL_AUX_LOOKUP(tctx, aux);

    struct ethhdr *eth;
    struct ipv6hdr *ip6h;
    struct ipv6_sr_hdr *srh;
    TAILCALL_PARSE_SRH(ctx, l3_off, eth, ip6h, srh);

    int action = CALL_WITH_CONST_L3(l3_off, process_end_b6_encaps, ctx, ip6h, srh, &tctx->sid_entry, aux);
    TAILCALL_RETURN(ctx,action);
}

SEC("xdp")
int tailcall_endpoint_end_m_gtp6_d(struct xdp_md *ctx)
{
    struct tailcall_ctx *tctx = tailcall_ctx_read();
    if (!tctx) TAILCALL_RETURN(ctx,XDP_DROP);
    TAILCALL_BOUND_L3OFF(tctx, l3_off);

    TAILCALL_AUX_LOOKUP(tctx, aux);

    struct ethhdr *eth;
    struct ipv6hdr *ip6h;
    struct ipv6_sr_hdr *srh;
    TAILCALL_PARSE_SRH(ctx, l3_off, eth, ip6h, srh);

    int action = CALL_WITH_CONST_L3(l3_off, process_end_m_gtp6_d, ctx, ip6h, srh, &tctx->sid_entry, aux);
    TAILCALL_RETURN(ctx,action);
}

SEC("xdp")
int tailcall_endpoint_end_m_gtp6_d_di(struct xdp_md *ctx)
{
    struct tailcall_ctx *tctx = tailcall_ctx_read();
    if (!tctx) TAILCALL_RETURN(ctx,XDP_DROP);
    TAILCALL_BOUND_L3OFF(tctx, l3_off);

    struct ethhdr *eth;
    struct ipv6hdr *ip6h;
    struct ipv6_sr_hdr *srh;
    TAILCALL_PARSE_SRH(ctx, l3_off, eth, ip6h, srh);

    int action = CALL_WITH_CONST_L3(l3_off, process_end_m_gtp6_d_di, ctx, ip6h, srh, &tctx->sid_entry);
    TAILCALL_RETURN(ctx,action);
}

SEC("xdp")
int tailcall_endpoint_end_m_gtp6_e(struct xdp_md *ctx)
{
    struct tailcall_ctx *tctx = tailcall_ctx_read();
    if (!tctx) TAILCALL_RETURN(ctx,XDP_DROP);
    TAILCALL_BOUND_L3OFF(tctx, l3_off);

    TAILCALL_AUX_LOOKUP(tctx, aux);

    struct ethhdr *eth;
    struct ipv6hdr *ip6h;
    struct ipv6_sr_hdr *srh;
    TAILCALL_PARSE_SRH(ctx, l3_off, eth, ip6h, srh);

    int action = CALL_WITH_CONST_L3(l3_off, process_end_m_gtp6_e, ctx, ip6h, srh, &tctx->sid_entry, aux);
    TAILCALL_RETURN(ctx,action);
}

SEC("xdp")
int tailcall_endpoint_end_m_gtp4_e(struct xdp_md *ctx)
{
    struct tailcall_ctx *tctx = tailcall_ctx_read();
    if (!tctx) TAILCALL_RETURN(ctx,XDP_DROP);
    TAILCALL_BOUND_L3OFF(tctx, l3_off);

    TAILCALL_AUX_LOOKUP(tctx, aux);

    struct ethhdr *eth;
    struct ipv6hdr *ip6h;
    struct ipv6_sr_hdr *srh;
    TAILCALL_PARSE_SRH(ctx, l3_off, eth, ip6h, srh);

    int action = CALL_WITH_CONST_L3(l3_off, process_end_m_gtp4_e, ctx, ip6h, srh, &tctx->sid_entry, aux);
    TAILCALL_RETURN(ctx,action);
}

// --- Pattern B: localsid + nosrh dual-path actions ---

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
        STATS_INC(STATS_SRV6_END, 0);
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

// ========== Headend Tail Call Targets ==========

// Helper macro for headend v4 tail call targets with per-branch bounds checks
#define HEADEND_V4_BODY(fn_name)                                              \
    struct tailcall_ctx *tctx = tailcall_ctx_read();                          \
    if (!tctx) TAILCALL_RETURN(ctx,XDP_DROP);                       \
    TAILCALL_BOUND_L3OFF(tctx, l3_off);                                       \
    void *data = (void *)(long)ctx->data;                                     \
    void *data_end = (void *)(long)ctx->data_end;                             \
    int action;                                                                \
    if (l3_off == 18) {                                                        \
        struct ethhdr *eth = data;                                             \
        if ((void *)(eth + 1) > data_end) TAILCALL_RETURN(ctx,XDP_DROP); \
        struct iphdr *iph = (struct iphdr *)(data + 18);                       \
        if ((void *)(iph + 1) > data_end) TAILCALL_RETURN(ctx,XDP_DROP); \
        action = fn_name(ctx, eth, iph, &tctx->headend, 18);                  \
    } else if (l3_off == 22) {                                                 \
        struct ethhdr *eth = data;                                             \
        if ((void *)(eth + 1) > data_end) TAILCALL_RETURN(ctx,XDP_DROP); \
        struct iphdr *iph = (struct iphdr *)(data + 22);                       \
        if ((void *)(iph + 1) > data_end) TAILCALL_RETURN(ctx,XDP_DROP); \
        action = fn_name(ctx, eth, iph, &tctx->headend, 22);                  \
    } else {                                                                   \
        struct ethhdr *eth = data;                                             \
        if ((void *)(eth + 1) > data_end) TAILCALL_RETURN(ctx,XDP_DROP); \
        struct iphdr *iph = (struct iphdr *)(data + 14);                       \
        if ((void *)(iph + 1) > data_end) TAILCALL_RETURN(ctx,XDP_DROP); \
        action = fn_name(ctx, eth, iph, &tctx->headend, 14);                  \
    }                                                                          \
    TAILCALL_RETURN(ctx,action)

// Helper macro for headend v6 tail call targets
#define HEADEND_V6_BODY(fn_name)                                              \
    struct tailcall_ctx *tctx = tailcall_ctx_read();                          \
    if (!tctx) TAILCALL_RETURN(ctx,XDP_DROP);                       \
    TAILCALL_BOUND_L3OFF(tctx, l3_off);                                       \
    void *data = (void *)(long)ctx->data;                                     \
    void *data_end = (void *)(long)ctx->data_end;                             \
    int action;                                                                \
    if (l3_off == 18) {                                                        \
        struct ethhdr *eth = data;                                             \
        if ((void *)(eth + 1) > data_end) TAILCALL_RETURN(ctx,XDP_DROP); \
        struct ipv6hdr *ip6h = (struct ipv6hdr *)(data + 18);                  \
        if ((void *)(ip6h + 1) > data_end) TAILCALL_RETURN(ctx,XDP_DROP); \
        action = fn_name(ctx, eth, ip6h, &tctx->headend, 18);                 \
    } else if (l3_off == 22) {                                                 \
        struct ethhdr *eth = data;                                             \
        if ((void *)(eth + 1) > data_end) TAILCALL_RETURN(ctx,XDP_DROP); \
        struct ipv6hdr *ip6h = (struct ipv6hdr *)(data + 22);                  \
        if ((void *)(ip6h + 1) > data_end) TAILCALL_RETURN(ctx,XDP_DROP); \
        action = fn_name(ctx, eth, ip6h, &tctx->headend, 22);                 \
    } else {                                                                   \
        struct ethhdr *eth = data;                                             \
        if ((void *)(eth + 1) > data_end) TAILCALL_RETURN(ctx,XDP_DROP); \
        struct ipv6hdr *ip6h = (struct ipv6hdr *)(data + 14);                  \
        if ((void *)(ip6h + 1) > data_end) TAILCALL_RETURN(ctx,XDP_DROP); \
        action = fn_name(ctx, eth, ip6h, &tctx->headend, 14);                 \
    }                                                                          \
    TAILCALL_RETURN(ctx,action)

SEC("xdp")
int tailcall_headend_v4_h_encaps(struct xdp_md *ctx) { HEADEND_V4_BODY(do_h_encaps_v4); }

SEC("xdp")
int tailcall_headend_v4_h_encaps_red(struct xdp_md *ctx) { HEADEND_V4_BODY(do_h_encaps_red_v4); }

SEC("xdp")
int tailcall_headend_v4_h_m_gtp4_d(struct xdp_md *ctx) { HEADEND_V4_BODY(do_h_m_gtp4_d); }

// ========== Headend v6 Tail Call Targets (4 programs) ==========

SEC("xdp")
int tailcall_headend_v6_h_encaps(struct xdp_md *ctx) { HEADEND_V6_BODY(do_h_encaps_v6); }

SEC("xdp")
int tailcall_headend_v6_h_encaps_red(struct xdp_md *ctx) { HEADEND_V6_BODY(do_h_encaps_red_v6); }

SEC("xdp")
int tailcall_headend_v6_h_insert(struct xdp_md *ctx) { HEADEND_V6_BODY(do_h_insert_v6); }

SEC("xdp")
int tailcall_headend_v6_h_insert_red(struct xdp_md *ctx) { HEADEND_V6_BODY(do_h_insert_red_v6); }

// ========== Dispatchers (tail call based) ==========

static __always_inline int process_headend_v4(
    struct xdp_md *ctx,
    struct ethhdr *eth,
    struct iphdr *iph,
    __u16 l3_offset)
{
    struct lpm_key_v4 key = { .prefixlen = 32 };
    __builtin_memcpy(key.addr, &iph->daddr, IPV4_ADDR_LEN);

    struct headend_entry *entry = bpf_map_lookup_elem(&headend_v4_map, &key);
    if (!entry)
        return XDP_PASS;

    if (tailcall_ctx_write_headend(entry, l3_offset) == 0)
        bpf_tail_call(ctx, &headend_v4_progs, entry->mode);

    return XDP_PASS;
}

static __always_inline int process_headend_v6(
    struct xdp_md *ctx,
    struct ethhdr *eth,
    struct ipv6hdr *ip6h,
    __u16 l3_offset)
{
    struct lpm_key_v6 key = { .prefixlen = 128 };
    __builtin_memcpy(key.addr, &ip6h->daddr, IPV6_ADDR_LEN);

    struct headend_entry *entry = bpf_map_lookup_elem(&headend_v6_map, &key);
    if (!entry)
        return XDP_PASS;

    if (tailcall_ctx_write_headend(entry, l3_offset) == 0)
        bpf_tail_call(ctx, &headend_v6_progs, entry->mode);

    return XDP_PASS;
}

static __always_inline int process_srv6_decap_nosrh(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    __u16 l3_offset)
{
    __u8 nh = ip6h->nexthdr;
    if (nh != IPPROTO_IPIP && nh != IPPROTO_IPV6 && nh != IPPROTO_ETHERNET)
        return XDP_PASS;

    struct lpm_key_v6 key = { .prefixlen = 128 };
    __builtin_memcpy(key.addr, &ip6h->daddr, IPV6_ADDR_LEN);
    struct sid_function_entry *entry = bpf_map_lookup_elem(&sid_function_map, &key);
    if (!entry)
        return XDP_PASS;

    if (tailcall_ctx_write_sid(entry, l3_offset, DISPATCH_NOSRH, nh) == 0)
        bpf_tail_call(ctx, &sid_endpoint_progs, entry->action);

    return XDP_PASS;
}

static __always_inline int process_srv6_localsid(
    struct xdp_md *ctx,
    struct ethhdr *eth,
    struct ipv6hdr *ip6h,
    __u16 l3_offset)
{
    if (ip6h->nexthdr != IPPROTO_ROUTING)
        return XDP_PASS;

    void *data_end = (void *)(long)ctx->data_end;
    void *srh_ptr = (void *)(ip6h + 1);
    if (srh_ptr + 8 > data_end)
        return XDP_PASS;

    struct ipv6_sr_hdr *srh = (struct ipv6_sr_hdr *)srh_ptr;
    if (srh->type != IPV6_SRCRT_TYPE_4)
        return XDP_PASS;

    struct lpm_key_v6 key = { .prefixlen = 128 };
    __builtin_memcpy(key.addr, &ip6h->daddr, IPV6_ADDR_LEN);

    struct sid_function_entry *entry = bpf_map_lookup_elem(&sid_function_map, &key);
    if (!entry)
        return XDP_PASS;

    if (tailcall_ctx_write_sid(entry, l3_offset, DISPATCH_LOCALSID, 0) == 0)
        bpf_tail_call(ctx, &sid_endpoint_progs, entry->action);

    return XDP_PASS;
}

// ========== L2 headend (unchanged — not tail-called) ==========

#include "headend/srv6_encaps_l2.h"

static __always_inline int process_bd_forwarding(
    struct xdp_md *ctx,
    struct headend_entry *l2_entry,
    __u16 vlan_id,
    __u64 pkt_len)
{
    if (l2_entry->bd_id == 0)
        return -1;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    struct fdb_key key = { .bd_id = l2_entry->bd_id };

    __builtin_memcpy(key.mac, eth->h_source, ETH_ALEN);
    struct fdb_entry *existing = bpf_map_lookup_elem(&fdb_map, &key);
    if (!existing ||
        (!existing->is_remote && !existing->is_static && existing->oif != ctx->ingress_ifindex)) {
        struct fdb_entry learn_val = {
            .oif = ctx->ingress_ifindex,
            .last_seen = bpf_ktime_get_ns(),
        };
        bpf_map_update_elem(&fdb_map, &key, &learn_val, BPF_ANY);
    } else if (existing && !existing->is_static) {
        existing->last_seen = bpf_ktime_get_ns();
    }

    if (eth->h_dest[0] & 0x01) {
        xdp_write_bum_meta(ctx, vlan_id);
        return XDP_PASS;
    }

    __builtin_memcpy(key.mac, eth->h_dest, ETH_ALEN);
    struct fdb_entry *dst_fdb = bpf_map_lookup_elem(&fdb_map, &key);
    if (dst_fdb) {
        if (dst_fdb->is_remote) {
            struct bd_peer_key pk = { .bd_id = dst_fdb->bd_id, .index = dst_fdb->peer_index };
            struct headend_entry *pe = bpf_map_lookup_elem(&bd_peer_map, &pk);
            if (pe) {
                __u16 l2_frame_len = (__u16)pkt_len;
                if (pe->mode == SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2_RED)
                    return do_h_encaps_l2_red(ctx, pe, l2_frame_len);
                return do_h_encaps_l2(ctx, pe, l2_frame_len);
            }
        }
        return XDP_PASS;
    }

    xdp_write_bum_meta(ctx, vlan_id);
    return XDP_PASS;
}

static __noinline int try_l2_headend(
    struct xdp_md *ctx,
    __u32 ifindex,
    __u16 vlan_id,
    __u64 pkt_len)
{
    struct headend_l2_key l2_key = { .ifindex = ifindex, .vlan_id = vlan_id };
    struct headend_entry *l2_entry = bpf_map_lookup_elem(&headend_l2_map, &l2_key);
    if (!headend_should_encaps_l2_any(l2_entry))
        return -1;

    int bd_action = process_bd_forwarding(ctx, l2_entry, vlan_id, pkt_len);
    if (bd_action >= 0)
        return bd_action;

    if (l2_entry->mode == SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2_RED)
        return do_h_encaps_l2_red(ctx, l2_entry, (__u16)pkt_len);
    return do_h_encaps_l2(ctx, l2_entry, (__u16)pkt_len);
}

// ========== L3 Pipeline ==========

static __always_inline int process_l3(struct xdp_md *ctx, __u16 l3_offset, __u16 proto)
{
    if (proto == bpf_htons(ETH_P_IPV6)) {
        struct ethhdr *eth;
        struct ipv6hdr *ip6h;

        // Stage 1: SRH-based endpoint processing
        REDERIVE_ETH_IP6(ctx, l3_offset, eth, ip6h);
        int action = process_srv6_localsid(ctx, eth, ip6h, l3_offset);
        if (action != XDP_PASS) return action;

        // Stage 2: Reduced SRH decap (no SRH present)
        REDERIVE_ETH_IP6(ctx, l3_offset, eth, ip6h);
        action = process_srv6_decap_nosrh(ctx, ip6h, l3_offset);
        if (action != XDP_PASS) return action;

        // Stage 3: Headend encapsulation
        REDERIVE_ETH_IP6(ctx, l3_offset, eth, ip6h);
        return process_headend_v6(ctx, eth, ip6h, l3_offset);
    }

    if (proto == bpf_htons(ETH_P_IP)) {
        struct ethhdr *eth;
        struct iphdr *iph;
        REDERIVE_ETH_IP4(ctx, l3_offset, eth, iph);
        return process_headend_v4(ctx, eth, iph, l3_offset);
    }

    return XDP_PASS;
}

// ========== Main XDP Entry Point ==========

SEC("xdp_vinbero_main")
int vinbero_main(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 pkt_len = data_end - data;
    int action = XDP_PASS;

    STATS_INC(STATS_RX_PACKETS, pkt_len);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        goto out;

    __u16 eth_proto = eth->h_proto;

    // ========== VLAN-tagged packets ==========
    if (eth_proto == bpf_htons(ETH_P_8021Q) ||
        eth_proto == bpf_htons(ETH_P_8021AD)) {

        struct vlan_hdr *vhdr = (void *)(eth + 1);
        if ((void *)(vhdr + 1) > data_end)
            goto out;

        __u16 vlan_id = bpf_ntohs(vhdr->h_vlan_TCI) & 0x0FFF;
        __u16 inner_proto = vhdr->h_vlan_encapsulated_proto;

        int l2_action = try_l2_headend(ctx, ctx->ingress_ifindex, vlan_id, pkt_len);
        if (l2_action >= 0) {
            action = l2_action;
            goto out;
        }

        data = (void *)(long)ctx->data;
        data_end = (void *)(long)ctx->data_end;
        eth = data;
        if ((void *)(eth + 1) > data_end)
            goto out;

        if (inner_proto == bpf_htons(ETH_P_8021Q) ||
            inner_proto == bpf_htons(ETH_P_8021AD)) {
            struct vlan_hdr *v2a = (struct vlan_hdr *)(eth + 1);
            if ((void *)(v2a + 1) > data_end)
                goto out;
            struct vlan_hdr *v2b = v2a + 1;
            if ((void *)(v2b + 1) > data_end)
                goto out;
            action = process_l3(ctx, 22, v2b->h_vlan_encapsulated_proto);
        } else {
            action = process_l3(ctx, 18, inner_proto);
        }
        goto out;
    }

    // ========== Non-VLAN packets ==========
    {
        int l2_action = try_l2_headend(ctx, ctx->ingress_ifindex, 0, pkt_len);
        if (l2_action >= 0) {
            action = l2_action;
            goto out;
        }
    }

    action = process_l3(ctx, 14, eth_proto);

out:
    // Note: When tail call succeeds, this epilogue is NOT reached.
    // Each tail call target runs tailcall_epilogue() instead.
    // This path handles: L2 headend, tail call fallback (empty slot), XDP_PASS.
    switch (action) {
    case XDP_PASS:
        STATS_INC(STATS_PASS, pkt_len);
        break;
    case XDP_DROP:
        STATS_INC(STATS_DROP, pkt_len);
        break;
    case XDP_REDIRECT:
        STATS_INC(STATS_REDIRECT, pkt_len);
        break;
    default:
        break;
    }

    RETURN_ACTION(ctx, &xdpcap_hook, action);
}

// ========== TC Ingress (BUM flooding — unchanged) ==========

#include "l2vpn/tc_bum.h"

SEC("tc")
int vinbero_tc_ingress(struct __sk_buff *skb)
{
    // Mode 2: Encap — clone returned to self with PE info in cb[]
    if (skb->cb[0] == TC_CB_ENCAP_MAGIC) {
        struct bd_peer_key pk = { .bd_id = (__u16)skb->cb[1], .index = (__u16)skb->cb[2] };
        struct headend_entry *pe = bpf_map_lookup_elem(&bd_peer_map, &pk);
        if (pe && pe->mode == SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2_RED)
            return tc_do_single_pe_encap_red(skb, skb->cb[1], skb->cb[2]);
        return tc_do_single_pe_encap(skb, skb->cb[1], skb->cb[2]);
    }

    // Mode 1: Dispatch — XDP wrote BUM meta, clone to self for each PE
    __u16 vlan_id;
    if (!tc_read_bum_meta(skb, &vlan_id))
        return TC_ACT_OK;

    return tc_dispatch_bum_clones(skb, vlan_id);
}
