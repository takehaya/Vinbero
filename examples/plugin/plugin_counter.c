// plugin_counter.c — Minimal Vinbero plugin example
//
// This plugin counts packets dispatched to its slot and passes them through.
// It demonstrates the plugin interface contract:
//   1. Read tailcall_ctx from per-CPU map
//   2. Bound l3_offset for BPF verifier
//   3. Do custom processing (increment counter)
//   4. Return via tailcall_epilogue (stats + xdpcap)

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "core/xdp_prog.h"
#include "core/xdp_map.h"

// Custom per-CPU counter map for this plugin
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} plugin_counter_map SEC(".maps");

SEC("xdp")
int plugin_counter(struct xdp_md *ctx)
{
    // 1. Read tail call context
    struct tailcall_ctx *tctx = tailcall_ctx_read();
    if (!tctx)
        return tailcall_epilogue(ctx, XDP_DROP);

    // 2. Bound l3_offset (mandatory for BPF verifier)
    __u16 l3_off = tctx->l3_offset;
    if (l3_off > 22)
        return tailcall_epilogue(ctx, XDP_DROP);

    // 3. Increment custom counter
    __u32 key = 0;
    __u64 *counter = bpf_map_lookup_elem(&plugin_counter_map, &key);
    if (counter)
        __sync_fetch_and_add(counter, 1);

    // 4. Pass packet through via epilogue (records stats + xdpcap)
    return tailcall_epilogue(ctx, XDP_PASS);
}

char _license[] SEC("license") = "GPL";
