#ifndef VINBERO_SDK_HELPERS_H
#define VINBERO_SDK_HELPERS_H

/*
 * Verifier-friendly helper macros for plugin authors.
 *
 *   - TAILCALL_BOUND_L3OFF(tctx, l3_off)
 *       Clamp l3_offset to [0, 22] so the verifier can track packet pointers.
 *
 *   - CALL_WITH_CONST_L3(l3_off, fn, ...)
 *       Switch over the bounded l3_offset so fn(...) receives it as a
 *       compile-time constant. Required when fn dereferences packet data.
 *
 *   - TAILCALL_PARSE_SRH(ctx, l3_off, eth, ip6h, srh)
 *       Parse Ethernet + IPv6 + SRH with per-step bounds checks.
 *
 *   - TAILCALL_AUX_LOOKUP(tctx, aux)
 *       Fetch sid_aux_map entry when sid_entry.has_aux is set.
 */

#include "core/xdp_tailcall_macros.h"

#endif /* VINBERO_SDK_HELPERS_H */
