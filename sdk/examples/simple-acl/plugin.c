// simple-acl/plugin.c
//
// Simple IPv6 source-address ACL plugin using VINBERO_PLUGIN.
// Drops packets whose outer IPv6 src is in acl_deny_map.

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>

#include <vinbero/plugin.h>
#include <vinbero/maps.h>
#include <vinbero/helpers.h>

#define IPV6_ADDR_LEN 16

struct ipv6_key {
    __u8 addr[IPV6_ADDR_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct ipv6_key);
    __type(value, __u8);
    __uint(max_entries, 1024);
} acl_deny_map SEC(".maps");

static __always_inline int acl_check(struct xdp_md *ctx, __u16 l3_off)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    struct ipv6hdr *ip6h = (struct ipv6hdr *)(data + l3_off);
    if ((void *)(ip6h + 1) > data_end)
        return XDP_DROP;

    struct ipv6_key key;
    __builtin_memcpy(key.addr, &ip6h->saddr, IPV6_ADDR_LEN);

    __u8 *denied = bpf_map_lookup_elem(&acl_deny_map, &key);
    if (denied)
        return XDP_DROP;
    return XDP_PASS;
}

VINBERO_PLUGIN(simple_acl)
{
    __u16 l3_off = tctx->l3_offset;
    if (l3_off > 22)
        return XDP_DROP;

    return CALL_WITH_CONST_L3(l3_off, acl_check, ctx);
}

char _license[] SEC("license") = "GPL";
