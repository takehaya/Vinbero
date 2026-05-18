// plugin_counter_l2.c — Minimal Vinbero L2 headend plugin example.
//
// Demonstrates the headend_l2 plugin slot introduced in Phase 2 of the
// L2 headend plugin SDK (see docs/plan/plugin-sdk-l2-headend.md). The
// plugin sits between BD forwarding's encap-target decision and the
// built-in do_h_encaps_l2{,_red} encap body. It counts packets per BD
// in a plugin-owned map and dispatches back into headend_l2_progs[3]
// (H_ENCAPS_L2) so the built-in encap still runs.

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include <vinbero/plugin.h>
#include <vinbero/types.h>
#include <vinbero/maps.h>
#include <vinbero/headend_l2_helpers.h>

// Per-(bd_id) packet counter. bd_id is __u16 from headend_entry; the
// map keys it as __u32 to keep things verifier-simple.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 256);
} plugin_counter_l2_map SEC(".maps");

VINBERO_PLUGIN(plugin_counter_l2)
{
    __u32 key = (__u32)tctx->headend.bd_id;
    __u64 init = 0;
    __u64 *counter = bpf_map_lookup_elem(&plugin_counter_l2_map, &key);
    if (!counter) {
        bpf_map_update_elem(&plugin_counter_l2_map, &key, &init, BPF_NOEXIST);
        counter = bpf_map_lookup_elem(&plugin_counter_l2_map, &key);
    }
    if (counter)
        __sync_fetch_and_add(counter, 1);

    // Hand control back to the built-in H.Encaps.L2 encap so the packet
    // continues on its normal path. tctx->headend already carries the
    // chosen encap target (l2_entry or pe), so no rewrite needed.
    bpf_tail_call(ctx, &headend_l2_progs, SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2);
    // Tail call only returns on failure (empty slot / map error).
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
