// SRv6 dispatchers — tail call entry points from the main pipeline.
// Included from xdp_prog.c — not compiled standalone.

// Resolve an ECMP group reference into the selected path's entry. Returns
// the chosen path (a map-value pointer, valid for the caller's lifetime) or
// the parent entry itself when the group is unresolvable — either no group
// (group_id 0) or a lookup miss during the control plane's update-skew
// window, where the parent's own segments serve as the fallback path. The
// caller must still validate num_segments: a parent that is a pure group
// reference carries none and must drop, not encap garbage.
static __always_inline struct headend_entry *resolve_ecmp_group(
    struct headend_entry *entry, __u32 flow_hash)
{
    if (entry->group_id == ECMP_GROUP_NONE)
        return entry;
    int sel = ecmp_select_path(entry->group_id, flow_hash);
    if (sel < 0)
        return entry;
    struct ecmp_path_key pk = {
        .group_id = entry->group_id,
        .path_index = (__u32)sel,
    };
    struct headend_entry *path = bpf_map_lookup_elem(&ecmp_path_map, &pk);
    return path ? path : entry;
}

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

    // Hashed for every headend packet (not only grouped ones): the hash also
    // becomes the outer flow-label entropy that keeps the underlay's ECMP
    // from polarizing on the identical outer {src, dst} of a PE pair.
    __u32 flow_hash = ecmp_flow_hash_v4(ctx, iph, l3_offset);
    entry = resolve_ecmp_group(entry, flow_hash);
    if (entry->group_id != ECMP_GROUP_NONE && entry->num_segments < 1)
        return XDP_DROP; // pure group reference with a dead group: no fallback

    if (tailcall_ctx_write_headend(entry, l3_offset, DISPATCH_HEADEND_V4, entry->mode, flow_hash) == 0)
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

    __u32 flow_hash = ecmp_flow_hash_v6(ctx, ip6h, l3_offset);
    entry = resolve_ecmp_group(entry, flow_hash);
    if (entry->group_id != ECMP_GROUP_NONE && entry->num_segments < 1)
        return XDP_DROP;

    if (tailcall_ctx_write_headend(entry, l3_offset, DISPATCH_HEADEND_V6, entry->mode, flow_hash) == 0)
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
