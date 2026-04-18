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

/*
 * VINBERO_PLUGIN_AUX_CAST: interpret sid_aux_entry.plugin_raw as a plugin-
 * defined struct. The caller is responsible for ensuring
 *   sizeof(type) <= sizeof(((struct sid_aux_entry *)0)->plugin_raw)
 * typically via _Static_assert at the plugin's translation-unit scope.
 */
#define VINBERO_PLUGIN_AUX_CAST(type, aux_ptr) \
    ((type *)((aux_ptr)->plugin_raw))

#endif /* VINBERO_SDK_TYPES_H */
