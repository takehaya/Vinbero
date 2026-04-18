#ifndef VINBERO_SDK_PLUGIN_H
#define VINBERO_SDK_PLUGIN_H

/*
 * Vinbero Plugin SDK: entry-point header.
 *
 * A plugin is a SEC("xdp") BPF program registered into one of vinbero's
 * PROG_ARRAY slots (endpoint 32..63, headend_v4/v6 16..31) via the
 * PluginService API. Include this header to get:
 *
 *   - struct tailcall_ctx definition (per-CPU context handed in by the
 *     dispatcher before bpf_tail_call)
 *   - tailcall_ctx_read() helper to fetch it
 *   - tailcall_epilogue() which the plugin MUST call before returning so
 *     that per-action stats are recorded
 *   - verifier-friendly macros (TAILCALL_BOUND_L3OFF, CALL_WITH_CONST_L3,
 *     TAILCALL_PARSE_SRH, TAILCALL_AUX_LOOKUP)
 *
 * Return contract: write `return tailcall_epilogue(ctx, action);` at every
 * exit of the plugin program. The server-side validator checks for at
 * least one BPF_CALL to tailcall_epilogue and rejects plugins without it.
 */

/* xdp_map.h must come before xdp_tailcall_helpers.h: the helpers call
 * bpf_map_lookup_elem on maps (tailcall_ctx_map, sid_aux_map, ...) that
 * xdp_map.h declares.
 */
#include "core/xdp_map.h"
#include "core/xdp_tailcall.h"
#include "core/xdp_tailcall_helpers.h"
#include "core/xdp_tailcall_macros.h"

/*
 * VINBERO_SDK_VERSION: monotonic integer bumped whenever the SDK grows a
 * new feature plugin authors can condition on.
 *
 *   v1: initial SDK (Phase 1b) — tailcall_ctx_read, tailcall_epilogue,
 *       verifier-helper macros, shared map declarations.
 *   v2: adds VINBERO_PLUGIN(name) entry macro; tailcall_epilogue gains
 *       warn_unused_result.
 *
 * Version bumps are additive. Plugins compiled against an older SDK
 * remain valid against newer vinbero.
 */
#define VINBERO_SDK_VERSION 2

/*
 * VINBERO_PLUGIN(name) — recommended entry macro for plugin authors.
 *
 * Generates a SEC("xdp") wrapper that always returns through
 * tailcall_epilogue. Plugin bodies focus on packet processing:
 *
 *     VINBERO_PLUGIN(my_plugin)
 *     {
 *         if (err) return XDP_DROP;
 *         return XDP_PASS;
 *     }
 *
 * Behaviour and body signature:
 *   - The wrapper reads tailcall_ctx once. When the per-CPU slot is
 *     unexpectedly missing (should not happen in normal operation; the
 *     dispatcher always populates it before bpf_tail_call), the wrapper
 *     skips the body and returns XDP_DROP via epilogue. Plugin authors
 *     debugging a never-executed body should check the dispatcher path.
 *   - The body receives `(ctx, tctx)` where ctx is the same xdp_md
 *     pointer that entered the wrapper. tctx is non-NULL.
 *   - Every exit from the body flows through a single tailcall_epilogue
 *     call, so path coverage is structural, not validator-dependent.
 *
 * Plugins that need to bpf_tail_call into a vinbero PROG_ARRAY can do
 * so from inside the body: on success the tail call does not return, so
 * the wrapper's epilogue is unreachable; on failure the body falls
 * through to `return XDP_DROP;` and the wrapper records that.
 *
 * Authors that need direct control over the wrapper (e.g. advanced SRH
 * parsing macros that expand to TAILCALL_RETURN internally) can write a
 * raw `SEC("xdp") int name(struct xdp_md *ctx)` and call
 * tailcall_epilogue manually.
 */
#define VINBERO_PLUGIN(name)                                                   \
    static __always_inline int __vinbero_body_##name(                          \
        struct xdp_md *ctx, struct tailcall_ctx *tctx);                        \
    SEC("xdp")                                                                  \
    int name(struct xdp_md *ctx)                                               \
    {                                                                           \
        struct tailcall_ctx *_tctx = tailcall_ctx_read();                      \
        int _action = _tctx ? __vinbero_body_##name(ctx, _tctx) : XDP_DROP;    \
        return tailcall_epilogue(ctx, _action);                                \
    }                                                                           \
    static __always_inline int __vinbero_body_##name(                          \
        struct xdp_md *ctx, struct tailcall_ctx *tctx)

#endif /* VINBERO_SDK_PLUGIN_H */
