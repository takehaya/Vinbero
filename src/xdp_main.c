// Main XDP entry point and L3 pipeline.
// Included from xdp_prog.c — not compiled standalone.

// ========== L3 Pipeline ==========

static __always_inline int process_l3(struct xdp_md *ctx, __u16 l3_offset, __u16 proto)
{
    if (proto == bpf_htons(ETH_P_IPV6)) {
        struct ethhdr *eth;
        struct ipv6hdr *ip6h;

        // Stage 1: SRH-based endpoint processing
        REDERIVE_ETH_IP6(ctx, l3_offset, eth, ip6h);
        int action = process_srv6_localsid(ctx, eth, ip6h, l3_offset);
        if (action != XDP_PASS) return action;

        // Stage 2: Reduced SRH decap (no SRH present)
        REDERIVE_ETH_IP6(ctx, l3_offset, eth, ip6h);
        action = process_srv6_decap_nosrh(ctx, ip6h, l3_offset);
        if (action != XDP_PASS) return action;

        // Stage 3: Headend encapsulation
        REDERIVE_ETH_IP6(ctx, l3_offset, eth, ip6h);
        return process_headend_v6(ctx, eth, ip6h, l3_offset);
    }

    if (proto == bpf_htons(ETH_P_IP)) {
        struct ethhdr *eth;
        struct iphdr *iph;
        REDERIVE_ETH_IP4(ctx, l3_offset, eth, iph);
        return process_headend_v4(ctx, eth, iph, l3_offset);
    }

    return XDP_PASS;
}

// ========== Main XDP Entry Point ==========

SEC("xdp_vinbero_main")
int vinbero_main(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 pkt_len = data_end - data;
    int action = XDP_PASS;

    STATS_INC(STATS_RX_PACKETS, pkt_len);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        goto out;

    __u16 eth_proto = eth->h_proto;

    // ========== VLAN-tagged packets ==========
    if (eth_proto == bpf_htons(ETH_P_8021Q) ||
        eth_proto == bpf_htons(ETH_P_8021AD)) {

        struct vlan_hdr *vhdr = (void *)(eth + 1);
        if ((void *)(vhdr + 1) > data_end)
            goto out;

        __u16 vlan_id = bpf_ntohs(vhdr->h_vlan_TCI) & 0x0FFF;
        __u16 inner_proto = vhdr->h_vlan_encapsulated_proto;

        int l2_action = try_l2_headend(ctx, ctx->ingress_ifindex, vlan_id, pkt_len);
        if (l2_action >= 0) {
            action = l2_action;
            goto out;
        }

        data = (void *)(long)ctx->data;
        data_end = (void *)(long)ctx->data_end;
        eth = data;
        if ((void *)(eth + 1) > data_end)
            goto out;

        if (inner_proto == bpf_htons(ETH_P_8021Q) ||
            inner_proto == bpf_htons(ETH_P_8021AD)) {
            struct vlan_hdr *v2a = (struct vlan_hdr *)(eth + 1);
            if ((void *)(v2a + 1) > data_end)
                goto out;
            struct vlan_hdr *v2b = v2a + 1;
            if ((void *)(v2b + 1) > data_end)
                goto out;
            action = process_l3(ctx, 22, v2b->h_vlan_encapsulated_proto);
        } else {
            action = process_l3(ctx, 18, inner_proto);
        }
        goto out;
    }

    // ========== Non-VLAN packets ==========
    {
        int l2_action = try_l2_headend(ctx, ctx->ingress_ifindex, 0, pkt_len);
        if (l2_action >= 0) {
            action = l2_action;
            goto out;
        }
    }

    action = process_l3(ctx, 14, eth_proto);

out:
    // Note: When tail call succeeds, this epilogue is NOT reached.
    // Each tail call target runs tailcall_epilogue() instead.
    // This path handles: L2 headend, tail call fallback (empty slot), XDP_PASS.
    switch (action) {
    case XDP_PASS:
        STATS_INC(STATS_PASS, pkt_len);
        break;
    case XDP_DROP:
        STATS_INC(STATS_DROP, pkt_len);
        break;
    case XDP_REDIRECT:
        STATS_INC(STATS_REDIRECT, pkt_len);
        break;
    default:
        break;
    }

    return action;
}
