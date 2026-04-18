#ifndef VINBERO_SDK_TYPES_H
#define VINBERO_SDK_TYPES_H

/*
 * Public data structures exchanged between vinbero and plugins.
 *
 *   - struct sid_function_entry: lookup result in sid_function_map
 *   - struct sid_aux_entry     : auxiliary data (union of per-behavior variants)
 *   - struct headend_entry     : lookup result in headend_v4_map / headend_v6_map
 *   - struct tailcall_ctx      : per-CPU context passed across bpf_tail_call
 *
 * These definitions live in src/core/xdp_prog.h and src/core/xdp_tailcall.h.
 * Re-exported here so plugin authors don't need to know the internal layout.
 */

#include "core/xdp_prog.h"
#include "core/xdp_tailcall.h"

#endif /* VINBERO_SDK_TYPES_H */
