#ifndef XDP_TAILCALL_HELPERS_H
#define XDP_TAILCALL_HELPERS_H

// This file must be included AFTER xdp_map.h (needs map declarations).
// xdp_tailcall.h defines the struct/constants; this file provides the helpers.

#include "core/xdp_tailcall.h"
#include "core/xdp_stats.h"

// ========== Context Helpers ==========

// Write endpoint context (used by both localsid and nosrh dispatchers).
// `slot` is the tail-call index (= entry->action).
static __always_inline int tailcall_ctx_write_sid(
    struct sid_function_entry *entry,
    __u16 l3_offset,
    __u8 dispatch_type,
    __u8 inner_proto,
    __u8 slot)
{
    __u32 key = TAILCALL_CTX_KEY;
    struct tailcall_ctx *tctx = bpf_map_lookup_elem(&tailcall_ctx_map, &key);
    if (!tctx) return -1;
    tctx->l3_offset = l3_offset;
    tctx->dispatch_type = dispatch_type;
    tctx->inner_proto = inner_proto;
    tctx->slot = slot;
    tctx->flow_hash = 0; // never carry a previous packet's hash into an endpoint
    __builtin_memcpy(&tctx->sid_entry, entry, sizeof(*entry));
    return 0;
}

// Write headend context. Caller must pass DISPATCH_HEADEND_V4/V6/L2 so the
// epilogue can select the right stats map. `slot` is the tail-call index
// (= entry->mode). `flow_hash` is the inner flow hash for outer flow-label
// entropy (0 when the dispatcher does not hash, e.g. L2).
static __always_inline int tailcall_ctx_write_headend(
    struct headend_entry *entry,
    __u16 l3_offset,
    __u8 dispatch_type,
    __u8 slot,
    __u32 flow_hash)
{
    __u32 key = TAILCALL_CTX_KEY;
    struct tailcall_ctx *tctx = bpf_map_lookup_elem(&tailcall_ctx_map, &key);
    if (!tctx) return -1;
    tctx->l3_offset = l3_offset;
    tctx->dispatch_type = dispatch_type;
    tctx->slot = slot;
    tctx->flow_hash = flow_hash;
    __builtin_memcpy(&tctx->headend, entry, sizeof(*entry));
    return 0;
}

// Set the ingress VRF on the per-CPU context. Called once at the XDP entry
// before any dispatch. The dispatcher's write helpers only touch the scalar
// header fields and the union, so vrf_id set here survives to the tail-call
// target. Set every packet (vrf 0 when the front door is off) so the per-CPU
// entry never carries a stale vrf_id from a previous packet.
static __always_inline void tailcall_ctx_set_vrf(__u32 vrf_id)
{
    __u32 key = TAILCALL_CTX_KEY;
    struct tailcall_ctx *tctx = bpf_map_lookup_elem(&tailcall_ctx_map, &key);
    if (tctx)
        tctx->vrf_id = vrf_id;
}

// Set the service-return circuit VLAN. Called by try_service_return before
// the tail call; only DISPATCH_SERVICE_RETURN targets read it.
static __always_inline void tailcall_ctx_set_svc_vlan(__u16 vlan_id)
{
    __u32 key = TAILCALL_CTX_KEY;
    struct tailcall_ctx *tctx = bpf_map_lookup_elem(&tailcall_ctx_map, &key);
    if (tctx)
        tctx->svc_vlan_id = vlan_id;
}

// Read context (called by tail call targets)
static __always_inline struct tailcall_ctx *tailcall_ctx_read(void)
{
    __u32 key = TAILCALL_CTX_KEY;
    return bpf_map_lookup_elem(&tailcall_ctx_map, &key);
}

// ========== Tail Call Epilogue ==========
//
// bpf_tail_call does not return, so vinbero_main's stats epilogue is never
// reached from a tail call target. tailcall_epilogue records final-action
// stats instead, and is declared __noinline so BPF_CALL instructions
// referencing it are visible to the plugin validator (~2-5ns overhead).
//
// warn_unused_result catches `tailcall_epilogue(ctx, XDP_DROP);` (call
// without return) at compile time — a common plugin-author mistake that
// the static validator cannot detect.
static __noinline __attribute__((warn_unused_result))
int tailcall_epilogue(struct xdp_md *ctx, int action)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 pkt_len = data_end - data;

    stats_action_inc(action, pkt_len);

    // Per-slot invocation counter. Gated inside slot_stats_inc (same
    // enable_stats pattern as stats_inc above). Masks bound slot to each
    // map's range so the verifier can prove the lookup key is in-range.
    struct tailcall_ctx *tctx = tailcall_ctx_read();
    if (tctx) {
        __u32 slot = tctx->slot;
        switch (tctx->dispatch_type) {
        case DISPATCH_LOCALSID:
        case DISPATCH_NOSRH:
            slot_stats_inc(&slot_stats_endpoint, slot & (SLOT_STATS_ENDPOINT_MAX - 1), pkt_len);
            break;
        case DISPATCH_HEADEND_V4:
            slot_stats_inc(&slot_stats_headend_v4, slot & (SLOT_STATS_HEADEND_MAX - 1), pkt_len);
            break;
        case DISPATCH_HEADEND_V6:
            slot_stats_inc(&slot_stats_headend_v6, slot & (SLOT_STATS_HEADEND_MAX - 1), pkt_len);
            break;
        case DISPATCH_HEADEND_L2:
            slot_stats_inc(&slot_stats_headend_l2, slot & (SLOT_STATS_HEADEND_MAX - 1), pkt_len);
            break;
        case DISPATCH_SERVICE_RETURN:
            slot_stats_inc(&slot_stats_service_return, slot & (SLOT_STATS_SVC_RETURN_MAX - 1), pkt_len);
            break;
        default:
            break;
        }
    }

    return action;
}

#define TAILCALL_RETURN(ctx, action) return tailcall_epilogue(ctx, action)

#endif // XDP_TAILCALL_HELPERS_H
