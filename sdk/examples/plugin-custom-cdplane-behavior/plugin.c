// Allow an outer IPv6 source prefix, then decapsulate through a host VRF grant.
#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>

#include <vinbero/plugin.h>
#include <vinbero/types.h>
#include <vinbero/maps.h>

struct plugin_custom_cdplane_behavior_aux {
    __u8 version;
    __u8 _reserved[7];
    struct vinbero_ipv6_prefix_t allowed_underlay_prefix;
};
_Static_assert(sizeof(struct plugin_custom_cdplane_behavior_aux) == 32,
               "aux must match the shared Go encoder");
_Static_assert(sizeof(struct plugin_custom_cdplane_behavior_aux) <=
               sizeof(((struct sid_aux_entry *)0)->plugin_raw), "aux too large");
VINBERO_PLUGIN_AUX_TYPE(plugin_custom_cdplane_behavior,
                       plugin_custom_cdplane_behavior_aux);

// Index 0 counts policy allows, index 1 policy rejects. An allow does not
// imply delivery: End.DT4 still checks the host grant and forwarding state.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 2);
} cdplane_policy SEC(".maps");

static __always_inline void count_decision(__u32 key)
{
    __u64 *count = bpf_map_lookup_elem(&cdplane_policy, &key);
    if (count)
        __sync_fetch_and_add(count, 1);
}

static __always_inline int
source_allowed(struct xdp_md *ctx,
               const struct plugin_custom_cdplane_behavior_aux *cfg,
               __u16 l3_off)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ipv6hdr *ip6h = data + l3_off;
    if ((void *)(ip6h + 1) > data_end || ip6h->version != 6)
        return 0;

    int matched = 1;
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        int bits = (int)cfg->allowed_underlay_prefix.prefix_len - i * 8;
        __u8 mask;
        if (bits >= 8)
            mask = 0xff;
        else if (bits <= 0)
            mask = 0;
        else
            mask = (__u8)(0xffu << (8 - bits));
        if ((ip6h->saddr.in6_u.u6_addr8[i] & mask) !=
            (cfg->allowed_underlay_prefix.addr[i] & mask))
            matched = 0;
    }
    return matched;
}

VINBERO_PLUGIN(plugin_custom_cdplane_behavior)
{
    TAILCALL_AUX_LOOKUP(tctx, aux);
    if (!aux)
        goto denied;

    const struct plugin_custom_cdplane_behavior_aux *cfg =
        VINBERO_PLUGIN_AUX_CAST(struct plugin_custom_cdplane_behavior_aux, aux);
    if (cfg->version != 1 || cfg->allowed_underlay_prefix.prefix_len > 128)
        goto denied;
    #pragma unroll
    for (int i = 0; i < 7; i++) {
        if (cfg->_reserved[i] || cfg->allowed_underlay_prefix._pad[i])
            goto denied;
    }

    __u16 l3_off = tctx->l3_offset;
    if (l3_off != 14 && l3_off != 18 && l3_off != 22)
        goto denied;
    if (!CALL_WITH_CONST_L3(l3_off, source_allowed, ctx, cfg))
        goto denied;

    count_decision(0);
    // Only the host-owned grant selects the VRF; plugin_raw never does.
    bpf_tail_call(ctx, &sid_endpoint_progs, SRV6_LOCAL_ACTION_END_DT4);
    return XDP_DROP;

denied:
    count_decision(1);
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
