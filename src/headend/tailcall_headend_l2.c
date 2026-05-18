// L2 Headend tail call targets (2 SEC("xdp") programs).
// Included from xdp_prog.c AFTER headend/srv6_encaps_l2.h so the encap
// helpers (do_h_encaps_l2 / do_h_encaps_l2_red) are in scope.
//
// L2 encap does not need an L3 offset — the do_h_encaps_l2* helpers
// treat the whole inner frame (Eth + payload) as opaque bytes to wrap
// in SRH. The dispatcher copies the chosen headend_entry into
// tctx->headend (same union variant L3 uses) before tail-calling here,
// so bd_id and SRH are already accessible from the target.

#define HEADEND_L2_BODY(fn_name)                                              \
    struct tailcall_ctx *tctx = tailcall_ctx_read();                          \
    if (!tctx) TAILCALL_RETURN(ctx, XDP_DROP);                                \
    void *data = (void *)(long)ctx->data;                                     \
    void *data_end = (void *)(long)ctx->data_end;                             \
    __u16 l2_frame_len = (__u16)(data_end - data);                            \
    int action = fn_name(ctx, &tctx->headend, l2_frame_len);                  \
    TAILCALL_RETURN(ctx, action)

SEC("xdp")
int tailcall_headend_l2_h_encaps(struct xdp_md *ctx) { HEADEND_L2_BODY(do_h_encaps_l2); }

SEC("xdp")
int tailcall_headend_l2_h_encaps_red(struct xdp_md *ctx) { HEADEND_L2_BODY(do_h_encaps_l2_red); }

#undef HEADEND_L2_BODY
