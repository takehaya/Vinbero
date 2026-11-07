// Devmap egress programs for xdp-mode BUM replication.
// Included from xdp_prog.c — not compiled standalone.
//
// Each remote flood slot of a BD's devmap (bum_flood_map) runs its own copy
// of bum_remote_egress_N, N being the bd_peer index, so copies that leave
// through the same uplink still get their own peer's headers. The copy
// arrives untouched: the source AC comes from ctx->ingress_ifindex and its
// VLAN from the frame, which together key headend_l2_map exactly as the
// ingress lookup did. No data_meta is used, because generic XDP does not
// hand ingress metadata to devmap programs.
//
// These programs contain no tail call (see the single-call-site invariant in
// dispatch/l2_headend.c), and they return XDP_PASS to transmit: XDP_REDIRECT
// is not a valid devmap program verdict.

// Build [Eth][IPv6][SRH] (or [Eth][IPv6] for H.Encaps.L2.Red with one
// segment) in front of the frame. Returns 0, or -1 on any failure. The
// outer MACs are left zero for the FIB lookup to fill.
static __always_inline int bum_egress_encap(struct xdp_md *ctx, struct headend_entry *peer)
{
    __u8 nsegs = peer->num_segments;
    if (nsegs < 1 || nsegs > MAX_SEGMENTS)
        return -1;
    bool reduced = peer->mode == SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2_RED;
    // Segment entries carried in the SRH: all of them, or all but the
    // first for the reduced form (which needs no SRH at all for one).
    __u8 srh_count = reduced ? nsegs - 1 : nsegs;
    if (srh_count > MAX_SEGMENTS)
        return -1;
    int srh_len = srh_count ? 8 + 16 * (int)srh_count : 0;
    __u16 l2_len = (__u16)((long)ctx->data_end - (long)ctx->data);

    if (bpf_xdp_adjust_head(ctx, -((int)sizeof(struct ethhdr) + (int)sizeof(struct ipv6hdr) + srh_len)))
        return -1;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct ipv6hdr *ip6h = (struct ipv6hdr *)(eth + 1);
    if ((void *)(ip6h + 1) > data_end)
        return -1;

    __builtin_memset(eth->h_dest, 0, ETH_ALEN);
    __builtin_memset(eth->h_source, 0, ETH_ALEN);
    eth->h_proto = bpf_htons(ETH_P_IPV6);

    if (!srh_count) {
        build_outer_ipv6(ip6h, IPPROTO_ETHERNET, l2_len, peer->src_addr, &peer->segments[0], 0);
        return 0;
    }

    build_outer_ipv6(ip6h, IPPROTO_ROUTING, srh_len + l2_len, peer->src_addr, &peer->segments[0], 0);

    struct ipv6_sr_hdr *srh = (struct ipv6_sr_hdr *)(ip6h + 1);
    if ((void *)srh + 8 > data_end)
        return -1;
    srh->nexthdr = IPPROTO_ETHERNET;
    srh->hdrlen = (srh_len >> 3) - 1;
    srh->type = IPV6_SRCRT_TYPE_4;
    srh->flags = 0;
    srh->tag = 0;
    void *srh_segments = (void *)srh + 8;
    if (reduced) {
        // Same values as do_h_encaps_l2_red_multi: segments[0] is only in
        // the destination address.
        srh->segments_left = srh_count;
        srh->first_segment = srh_count - 1;
        return copy_segments_to_srh_reduced(srh_segments, data_end, peer->segments, nsegs) ? -1 : 0;
    }
    srh->segments_left = nsegs - 1;
    srh->first_segment = nsegs - 1;
    return copy_segments_to_srh(srh_segments, data_end, peer->segments, nsegs) ? -1 : 0;
}

static __noinline int bum_remote_egress_body(struct xdp_md *ctx, __u32 slot, __u32 src_if, __u32 egress_if)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 pkt_len = data_end - data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        goto drop;
    __u16 vlan_id = 0;
    if (eth->h_proto == bpf_htons(ETH_P_8021Q) || eth->h_proto == bpf_htons(ETH_P_8021AD)) {
        struct vlan_hdr *vh = (void *)(eth + 1);
        if ((void *)(vh + 1) > data_end)
            goto drop;
        vlan_id = bpf_ntohs(vh->h_vlan_TCI) & 0x0FFF;
    }

    struct headend_l2_key src_key = { .ifindex = src_if, .vlan_id = vlan_id };
    struct headend_entry *src = bpf_map_lookup_elem(&headend_l2_map, &src_key);
    if (!headend_should_encaps_l2_any(src) || src->bd_id == 0 || slot >= MAX_BUM_NEXTHOPS)
        goto drop;
    __u16 bd_id = src->bd_id;

    struct bd_peer_key pk = { .bd_id = bd_id, .index = (__u16)slot };
    struct headend_entry *peer = bpf_map_lookup_elem(&bd_peer_map, &pk);
    if (!peer || peer->flood_exclude)
        goto drop;

    // RFC 9252 split horizon, same rule as tc_dispatch_bum_clones: a peer
    // on the source AC's Ethernet Segment would re-flood to the shared CE.
    struct headend_l2_ext_val *src_ext = bpf_map_lookup_elem(&headend_l2_ext_map, &src_key);
    if (src_ext && !esi_is_zero(src_ext->esi)) {
        struct bd_peer_l2_ext_key ek = { .bd_id = bd_id, .index = (__u16)slot };
        struct bd_peer_l2_ext_val *pe = bpf_map_lookup_elem(&bd_peer_l2_ext_map, &ek);
        if (pe && esi_equal(pe->esi, src_ext->esi)) {
            STATS_INC(STATS_SPLIT_HORIZON_TX, pkt_len);
            return XDP_DROP;
        }
    }

    if (bum_egress_encap(ctx, peer) < 0)
        goto drop;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    eth = data;
    struct ipv6hdr *ip6h = (struct ipv6hdr *)(eth + 1);
    if ((void *)(ip6h + 1) > data_end)
        goto drop;

    // The lookup runs on the source AC, the device the tc path's lookup
    // uses too. The devmap entry fixed the egress device; a FIB answer that
    // disagrees (route change since the control plane resolved it) cannot
    // be honoured from here, so the copy is dropped and counted.
    __u32 oif = 0;
    if (srv6_fib_lookup_and_update(ctx, ip6h, eth, &oif, src_if) != FIB_RESULT_REDIRECT)
        goto drop;
    if (oif != egress_if) {
        STATS_INC(STATS_BUM_UPLINK_MISMATCH, pkt_len);
        return XDP_DROP;
    }
    STATS_INC(STATS_BUM_EGRESS_TX, pkt_len);
    return XDP_PASS;

drop:
    STATS_INC(STATS_BUM_EGRESS_DROP, pkt_len);
    return XDP_DROP;
}

#define BUM_REMOTE_EGRESS(n)                                                        \
    SEC("xdp/devmap")                                                               \
    int bum_remote_egress_##n(struct xdp_md *ctx)                                   \
    {                                                                               \
        return bum_remote_egress_body(ctx, n, ctx->ingress_ifindex, ctx->egress_ifindex); \
    }

// One program per flood slot: MAX_BUM_NEXTHOPS == 8.
BUM_REMOTE_EGRESS(0)
BUM_REMOTE_EGRESS(1)
BUM_REMOTE_EGRESS(2)
BUM_REMOTE_EGRESS(3)
BUM_REMOTE_EGRESS(4)
BUM_REMOTE_EGRESS(5)
BUM_REMOTE_EGRESS(6)
BUM_REMOTE_EGRESS(7)

_Static_assert(MAX_BUM_NEXTHOPS == 8, "one bum_remote_egress program per flood slot");

// Test entry for BPF_PROG_TEST_RUN, which refuses devmap programs and any
// non-zero egress_ifindex. Runs the same body with the slot, source AC and
// egress device taken from bum_test_params_map; the control plane never
// attaches it.
struct bum_test_params {
    __u32 slot;
    __u32 src_ifindex;
    __u32 egress_ifindex;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct bum_test_params);
    __uint(max_entries, 1);
} bum_test_params_map SEC(".maps");

SEC("xdp")
int bum_remote_egress_test(struct xdp_md *ctx)
{
    __u32 k = 0;
    struct bum_test_params *p = bpf_map_lookup_elem(&bum_test_params_map, &k);
    if (!p)
        return XDP_ABORTED;
    return bum_remote_egress_body(ctx, p->slot, p->src_ifindex, p->egress_ifindex);
}
