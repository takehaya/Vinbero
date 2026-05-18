// plugin_custom_sh.c — Custom Split-Horizon (SH) filter for L2 headend.
//
// EVPN multi-homing reference plugin (Vinbero SDK v3+). Demonstrates how
// to observe source / destination ESI from a headend_l2_progs plugin
// slot and drop frames that would cross between two ACs that share an
// Ethernet Segment — i.e. apply an SH rule that's stricter (or just
// different) from vinbero's built-in behavior.
//
// Built-in Vinbero already enforces RFC 7432 §8.3 SH on the receive
// side (NON_DF_DROP). This plugin layers an additional TX-side check:
// if the local AC's ESI equals the destination peer's ESI, drop the
// frame before encap. Useful for topologies where two PEs are in the
// same ES and you want to force traffic to take an alternate path.

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>

#include <vinbero/plugin.h>
#include <vinbero/types.h>
#include <vinbero/maps.h>
#include <vinbero/headend_l2_helpers.h>

// Per-(bd_id) drop counter — observability for ops to confirm the
// plugin is taking effect. Real deployments would also export this via
// vinbero stats; for the example we keep it plugin-private. PERCPU_HASH
// keeps the increment lock-free in the XDP per-packet path.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 256);
} plugin_custom_sh_drops SEC(".maps");

static __always_inline void bump_drops(__u16 bd_id)
{
    __u32 key = (__u32)bd_id;
    __u64 init = 0;
    __u64 *c = bpf_map_lookup_elem(&plugin_custom_sh_drops, &key);
    if (!c) {
        bpf_map_update_elem(&plugin_custom_sh_drops, &key, &init, BPF_NOEXIST);
        c = bpf_map_lookup_elem(&plugin_custom_sh_drops, &key);
    }
    if (c)
        (*c)++;
}

VINBERO_PLUGIN(plugin_custom_sh)
{
    __u32 ifindex = (__u32)ctx->ingress_ifindex;
    __u16 vlan_id = vinbero_l2_vlan_id(ctx);
    __u16 bd_id = tctx->headend.bd_id;

    __u8 src_esi[ESI_LEN];
    __u8 dst_esi[ESI_LEN];

    // Pull both ends of the local AC <-> remote peer pair. Missing
    // entries (lookup returning -1) leave the ESI buffer all-zero,
    // which the equality check below treats as "not in an ES" -> pass.
    (void)vinbero_l2_lookup_esi(ifindex, vlan_id, src_esi);
    (void)vinbero_l2_dst_peer_esi(ctx, bd_id, dst_esi);

    // Drop only when BOTH sides have a non-zero ESI AND they match.
    // Comparing zeros against zeros would drop every non-multihomed
    // frame, which is obviously wrong.
    if (!vinbero_l2_esi_is_zero(src_esi) && vinbero_l2_esi_equal(src_esi, dst_esi)) {
        bump_drops(bd_id);
        return XDP_DROP;
    }

    // Not an SH violation — hand off to built-in H.Encaps.L2.
    bpf_tail_call(ctx, &headend_l2_progs, SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2);
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
