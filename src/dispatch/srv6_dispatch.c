// SRv6 dispatchers — tail call entry points from the main pipeline.
// Included from xdp_prog.c — not compiled standalone.

static __always_inline int process_headend_v4(
    struct xdp_md *ctx,
    struct ethhdr *eth,
    struct iphdr *iph,
    __u16 l3_offset)
{
    struct lpm_key_v4 key = { .prefixlen = 32 };
    __builtin_memcpy(key.addr, &iph->daddr, IPV4_ADDR_LEN);

    struct headend_entry *entry = bpf_map_lookup_elem(&headend_v4_map, &key);
    if (!entry)
        return XDP_PASS;

    if (tailcall_ctx_write_headend(entry, l3_offset, DISPATCH_HEADEND_V4, entry->mode) == 0)
        bpf_tail_call(ctx, &headend_v4_progs, entry->mode);

    return XDP_PASS;
}

static __always_inline int process_headend_v6(
    struct xdp_md *ctx,
    struct ethhdr *eth,
    struct ipv6hdr *ip6h,
    __u16 l3_offset)
{
    struct lpm_key_v6 key = { .prefixlen = 128 };
    __builtin_memcpy(key.addr, &ip6h->daddr, IPV6_ADDR_LEN);

    struct headend_entry *entry = bpf_map_lookup_elem(&headend_v6_map, &key);
    if (!entry)
        return XDP_PASS;

    if (tailcall_ctx_write_headend(entry, l3_offset, DISPATCH_HEADEND_V6, entry->mode) == 0)
        bpf_tail_call(ctx, &headend_v6_progs, entry->mode);

    return XDP_PASS;
}

static __always_inline int process_srv6_decap_nosrh(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    __u16 l3_offset)
{
    __u8 nh = ip6h->nexthdr;
    if (nh != IPPROTO_IPIP && nh != IPPROTO_IPV6 && nh != IPPROTO_ETHERNET)
        return XDP_PASS;

    struct lpm_key_v6 key = { .prefixlen = 128 };
    __builtin_memcpy(key.addr, &ip6h->daddr, IPV6_ADDR_LEN);
    struct sid_function_entry *entry = bpf_map_lookup_elem(&sid_function_map, &key);
    if (!entry)
        return XDP_PASS;

    if (tailcall_ctx_write_sid(entry, l3_offset, DISPATCH_NOSRH, nh, entry->action) == 0)
        bpf_tail_call(ctx, &sid_endpoint_progs, entry->action);

    return XDP_PASS;
}

static __always_inline int process_srv6_localsid(
    struct xdp_md *ctx,
    struct ethhdr *eth,
    struct ipv6hdr *ip6h,
    __u16 l3_offset)
{
    if (ip6h->nexthdr != IPPROTO_ROUTING)
        return XDP_PASS;

    void *data_end = (void *)(long)ctx->data_end;
    void *srh_ptr = (void *)(ip6h + 1);
    if (srh_ptr + 8 > data_end)
        return XDP_PASS;

    struct ipv6_sr_hdr *srh = (struct ipv6_sr_hdr *)srh_ptr;
    if (srh->type != IPV6_SRCRT_TYPE_4)
        return XDP_PASS;

    struct lpm_key_v6 key = { .prefixlen = 128 };
    __builtin_memcpy(key.addr, &ip6h->daddr, IPV6_ADDR_LEN);

    struct sid_function_entry *entry = bpf_map_lookup_elem(&sid_function_map, &key);
    if (!entry)
        return XDP_PASS;

    if (tailcall_ctx_write_sid(entry, l3_offset, DISPATCH_LOCALSID, 0, entry->action) == 0)
        bpf_tail_call(ctx, &sid_endpoint_progs, entry->action);

    return XDP_PASS;
}
