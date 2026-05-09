// plugin_counter_evil.c — Negative example for the Vinbero plugin SDK.
//
// This plugin is intentionally written to violate the Phase 2 RO-write
// contract: it looks up an entry in `sid_function_map` (a vinbero
// shared READ-ONLY map) and rewrites its `action` field. The asm-level
// validator in `pkg/bpf/plugin_validate.go` must reject this plugin at
// load time. `make sdk-test-negative` confirms the rejection in CI.
//
// Do not copy this as a starting point for real plugins; use the
// `plugin-counter` sample instead.

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include <vinbero/plugin.h>
#include <vinbero/types.h>
#include <vinbero/maps.h>

VINBERO_PLUGIN(plugin_counter_evil)
{
    // Forbidden by Phase 2 RO enforcement: writing to sid_function_map
    // would let a plugin rewrite vinbero's control plane. The validator
    // sees the store target (whether resolved as the static map or as
    // a "(dynamic)" lookup-return-value pointer) and rejects load.
    __u32 key = 0;
    struct sid_function_entry *e =
        bpf_map_lookup_elem(&sid_function_map, &key);
    if (e)
        e->action = 99;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
