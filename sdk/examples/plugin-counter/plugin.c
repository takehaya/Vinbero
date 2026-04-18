// plugin_counter.c — Minimal Vinbero plugin example
//
// Counts packets dispatched to its slot and passes them through. The
// amount added per packet is configurable via plugin aux: set
// `plugin_counter_aux.increment` from the CLI
// (--plugin-aux-json '{"increment":10}').

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include <vinbero/plugin.h>
#include <vinbero/types.h>
#include <vinbero/maps.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} plugin_counter_map SEC(".maps");

struct plugin_counter_aux {
    __u32 increment;  // packets-per-packet step; 0 is treated as 1
};
VINBERO_PLUGIN_AUX_TYPE(plugin_counter, plugin_counter_aux);

VINBERO_PLUGIN(plugin_counter)
{
    if (tctx->l3_offset > 22)
        return XDP_DROP;

    __u32 step = 1;
    TAILCALL_AUX_LOOKUP(tctx, aux);
    if (aux) {
        struct plugin_counter_aux *cfg =
            VINBERO_PLUGIN_AUX_CAST(struct plugin_counter_aux, aux);
        if (cfg->increment)
            step = cfg->increment;
    }

    __u32 key = 0;
    __u64 *counter = bpf_map_lookup_elem(&plugin_counter_map, &key);
    if (counter)
        __sync_fetch_and_add(counter, (__u64)step);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
