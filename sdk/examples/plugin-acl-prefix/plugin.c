// plugin-acl-prefix/plugin.c
//
// Source-prefix ACL plugin. The deny rule (IPv6 prefix + action) is
// delivered per-SID via plugin aux, so operators can tune the ACL
// without recompiling the plugin:
//
//   vinbero sid create --action 33 \
//     --plugin-aux-json '{"deny_src": "fc00:12::/64", "action": 1}'
//
// The plugin inspects the outer IPv6 source address (the packet that
// reached this SRv6 endpoint) and drops it when it sits inside
// deny_src/prefix_len. action == 0 passes the packet even on match,
// which is useful for wiring up the rule before flipping the switch.

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>

#include <vinbero/plugin.h>
#include <vinbero/types.h>
#include <vinbero/maps.h>
#include <vinbero/helpers.h>

#define ACL_ACTION_PASS 0
#define ACL_ACTION_DROP 1

struct plugin_acl_prefix_aux {
    struct vinbero_ipv6_prefix_t deny_src;
    __u32 action;
};
VINBERO_PLUGIN_AUX_TYPE(plugin_acl_prefix, plugin_acl_prefix_aux);

// prefix_match_v6 returns 1 when addr equals prefix up to prefix_len bits.
// Always walks all 16 bytes with a per-byte mask derived from prefix_len,
// so no early break is required and the loop unrolls cleanly for the
// verifier.
static __always_inline int
prefix_match_v6(const __u8 *addr, const __u8 *prefix, __u8 prefix_len)
{
    if (prefix_len > 128)
        return 0;

    int matched = 1;
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        int bits = (int)prefix_len - i * 8;
        __u8 mask;
        if (bits >= 8)
            mask = 0xFF;
        else if (bits <= 0)
            mask = 0;
        else
            mask = (__u8)(0xFFu << (8 - bits));
        if ((addr[i] & mask) != (prefix[i] & mask))
            matched = 0;
    }
    return matched;
}

static __always_inline int
acl_check(struct xdp_md *ctx, struct sid_aux_entry *aux, __u16 l3_off)
{
    // aux is optional — a SID without rule just passes. Operators use
    // this to deploy the plugin first and populate the rule later.
    if (!aux)
        return XDP_PASS;

    struct plugin_acl_prefix_aux *cfg =
        VINBERO_PLUGIN_AUX_CAST(struct plugin_acl_prefix_aux, aux);

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    struct ipv6hdr *ip6h = (struct ipv6hdr *)(data + l3_off);
    if ((void *)(ip6h + 1) > data_end)
        return XDP_DROP;

    if (!prefix_match_v6(ip6h->saddr.in6_u.u6_addr8,
                         cfg->deny_src.addr,
                         cfg->deny_src.prefix_len))
        return XDP_PASS;

    return (cfg->action == ACL_ACTION_DROP) ? XDP_DROP : XDP_PASS;
}

VINBERO_PLUGIN(plugin_acl_prefix)
{
    __u16 l3_off = tctx->l3_offset;
    if (l3_off > 22)
        return XDP_DROP;

    TAILCALL_AUX_LOOKUP(tctx, aux);
    return CALL_WITH_CONST_L3(l3_off, acl_check, ctx, aux);
}

char _license[] SEC("license") = "GPL";
