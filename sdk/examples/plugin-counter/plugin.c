// plugin_counter.c — Minimal Vinbero plugin example
//
// Counts packets dispatched to its slot and passes them through.

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include <vinbero/plugin.h>
#include <vinbero/maps.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} plugin_counter_map SEC(".maps");

VINBERO_PLUGIN(plugin_counter)
{
    if (tctx->l3_offset > 22)
        return XDP_DROP;

    __u32 key = 0;
    __u64 *counter = bpf_map_lookup_elem(&plugin_counter_map, &key);
    if (counter)
        __sync_fetch_and_add(counter, 1);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
