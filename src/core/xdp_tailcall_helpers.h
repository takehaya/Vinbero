#ifndef XDP_TAILCALL_HELPERS_H
#define XDP_TAILCALL_HELPERS_H

// This file must be included AFTER xdp_map.h (needs map declarations).
// xdp_tailcall.h defines the struct/constants; this file provides the helpers.

#include "core/xdp_tailcall.h"
#include "core/xdp_stats.h"
#include "core/xdpcap.h"

// ========== Context Helpers ==========

// Write endpoint context (used by both localsid and nosrh dispatchers)
static __always_inline int tailcall_ctx_write_sid(
    struct sid_function_entry *entry,
    __u16 l3_offset,
    __u8 dispatch_type,
    __u8 inner_proto)
{
    __u32 key = TAILCALL_CTX_KEY;
    struct tailcall_ctx *tctx = bpf_map_lookup_elem(&tailcall_ctx_map, &key);
    if (!tctx) return -1;
    tctx->l3_offset = l3_offset;
    tctx->dispatch_type = dispatch_type;
    tctx->inner_proto = inner_proto;
    __builtin_memcpy(&tctx->sid_entry, entry, sizeof(*entry));
    return 0;
}

// Write headend context
static __always_inline int tailcall_ctx_write_headend(
    struct headend_entry *entry, __u16 l3_offset)
{
    __u32 key = TAILCALL_CTX_KEY;
    struct tailcall_ctx *tctx = bpf_map_lookup_elem(&tailcall_ctx_map, &key);
    if (!tctx) return -1;
    tctx->l3_offset = l3_offset;
    tctx->dispatch_type = DISPATCH_HEADEND;
    __builtin_memcpy(&tctx->headend, entry, sizeof(*entry));
    return 0;
}

// Read context (called by tail call targets)
static __always_inline struct tailcall_ctx *tailcall_ctx_read(void)
{
    __u32 key = TAILCALL_CTX_KEY;
    return bpf_map_lookup_elem(&tailcall_ctx_map, &key);
}

// ========== Tail Call Epilogue ==========
//
// bpf_tail_call does not return to the caller on success, so vinbero_main's
// out: label (stats + xdpcap) is never reached. Each tail call target must
// call this epilogue before returning to record final-action stats and
// invoke the xdpcap hook.

// __noinline: BPF subprogram so it appears as BTF_KIND_FUNC in the ELF.
// This allows the server to verify that plugins include the epilogue
// by checking BTF for the "tailcall_epilogue" function symbol.
// Overhead is ~2-5ns per packet (negligible vs map lookups at ~50ns).
//
// Stats are recorded here. xdpcap hook is NOT called from this subprogram
// because the additional stack frame would exceed BPF's 256-byte call stack
// limit in headend targets with large inline expansions. The caller handles
// xdpcap if needed.
static __noinline int tailcall_epilogue(struct xdp_md *ctx, int action)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 pkt_len = data_end - data;

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

    return action;
}

// Wrapper: stats via noinline epilogue + xdpcap hook (inline, for tail call targets)
#define TAILCALL_RETURN(ctx, action) \
    do { \
        int _act = tailcall_epilogue(ctx, action); \
        RETURN_ACTION(ctx, &xdpcap_hook, _act); \
    } while (0)

#endif // XDP_TAILCALL_HELPERS_H
