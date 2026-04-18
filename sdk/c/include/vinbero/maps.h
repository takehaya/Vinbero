#ifndef VINBERO_SDK_MAPS_H
#define VINBERO_SDK_MAPS_H

/*
 * Vinbero shared eBPF maps for plugins.
 *
 * These maps are created and populated by vinbero itself. Plugins declare
 * matching definitions in their ELF and vinbero replaces them at load
 * time (see MapReplacements). Treat vinbero-owned lookup state
 * (sid_function_map / sid_aux_map / fdb_map / headend_*_map / stats_map) as
 * read-only; writing corrupts the data plane or stats observed by user
 * space. scratch_map is per-CPU and safe for transient buffering.
 *
 * For custom counters, declare a plugin-private PERCPU_ARRAY in the
 * plugin ELF; vinbero creates it fresh at registration.
 */

#include "core/xdp_map.h"

#endif /* VINBERO_SDK_MAPS_H */
