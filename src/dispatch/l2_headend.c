// L2 headend pipeline — BD forwarding and L2 encapsulation dispatch.
// Included from xdp_prog.c — not compiled standalone.
// Depends on headend/srv6_encaps_l2.h (must be included before this file).

static __always_inline int process_bd_forwarding(
    struct xdp_md *ctx,
    struct headend_entry *l2_entry,
    __u16 vlan_id,
    __u64 pkt_len)
{
    if (l2_entry->bd_id == 0)
        return -1;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    struct fdb_key key = { .bd_id = l2_entry->bd_id };

    __builtin_memcpy(key.mac, eth->h_source, ETH_ALEN);
    struct fdb_entry *existing = bpf_map_lookup_elem(&fdb_map, &key);
    if (!existing ||
        (!existing->is_remote && !existing->is_static && existing->oif != ctx->ingress_ifindex)) {
        struct fdb_entry learn_val = {
            .oif = ctx->ingress_ifindex,
            .last_seen = bpf_ktime_get_ns(),
        };
        bpf_map_update_elem(&fdb_map, &key, &learn_val, BPF_ANY);
    } else if (existing && !existing->is_static) {
        existing->last_seen = bpf_ktime_get_ns();
    }

    if (eth->h_dest[0] & 0x01) {
        xdp_write_bum_meta(ctx, vlan_id);
        return XDP_PASS;
    }

    __builtin_memcpy(key.mac, eth->h_dest, ETH_ALEN);
    struct fdb_entry *dst_fdb = bpf_map_lookup_elem(&fdb_map, &key);
    if (dst_fdb) {
        if (dst_fdb->is_remote) {
            struct bd_peer_key pk = { .bd_id = dst_fdb->bd_id, .index = dst_fdb->peer_index };
            struct headend_entry *pe = bpf_map_lookup_elem(&bd_peer_map, &pk);
            if (pe) {
                __u16 l2_frame_len = (__u16)pkt_len;
                if (pe->mode == SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2_RED)
                    return do_h_encaps_l2_red(ctx, pe, l2_frame_len);
                return do_h_encaps_l2(ctx, pe, l2_frame_len);
            }
        }
        return XDP_PASS;
    }

    xdp_write_bum_meta(ctx, vlan_id);
    return XDP_PASS;
}

static __noinline int try_l2_headend(
    struct xdp_md *ctx,
    __u32 ifindex,
    __u16 vlan_id,
    __u64 pkt_len)
{
    struct headend_l2_key l2_key = { .ifindex = ifindex, .vlan_id = vlan_id };
    struct headend_entry *l2_entry = bpf_map_lookup_elem(&headend_l2_map, &l2_key);
    if (!headend_should_encaps_l2_any(l2_entry))
        return -1;

    int bd_action = process_bd_forwarding(ctx, l2_entry, vlan_id, pkt_len);
    if (bd_action >= 0)
        return bd_action;

    if (l2_entry->mode == SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2_RED)
        return do_h_encaps_l2_red(ctx, l2_entry, (__u16)pkt_len);
    return do_h_encaps_l2(ctx, l2_entry, (__u16)pkt_len);
}
