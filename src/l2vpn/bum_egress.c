// Devmap egress program for xdp-mode BUM replication.
// Included from xdp_prog.c — not compiled standalone.
//
// One program, bum_remote_egress, sits on every remote flood slot entry of
// every BD devmap (bum_flood_map), and on the local AC entries whose device
// is also the uplink of a slot of the BD. The copies it sees of one frame
// are identical, and all copies headed for one device also share the egress
// device, so the program cannot tell from the copy which peer it is for.
// It takes that from the frame's plan instead (bum_xdp.h): it finds the
// device's item, takes its next slot and builds that peer's H.Encaps.L2
// headers; once the slots are used up, one more copy leaves unchanged when
// the device is also a local AC. The plan also supplies the source AC and
// the BD, so the copy itself is not parsed.
//
// The program contains no tail call (see the single-call-site invariant in
// dispatch/l2_headend.c), and it returns XDP_PASS to transmit: XDP_REDIRECT
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

// The seq this copy belongs to. Generic XDP runs the devmap programs of a
// broadcast on the ingress CPU, synchronously, before that CPU takes
// another frame: the copy is from the CPU's latest AC-side BUM frame.
static __always_inline int bum_egress_seq_generic(__u64 *seq)
{
    __u32 zero = 0;
    __u64 *next = bpf_map_lookup_elem(&bum_seq, &zero);
    if (!next || *next == 0)
        return -1;
    *seq = *next - 1;
    return 0;
}

// Slot of the idx-th set bit of slots (ascending), or -1.
static __always_inline int bum_plan_nth_slot(__u8 slots, __u32 idx)
{
    __u32 seen = 0;
    for (__u32 i = 0; i < MAX_BUM_NEXTHOPS; i++) {
        if (!(slots & (1u << i)))
            continue;
        if (seen == idx)
            return (int)i;
        seen++;
    }
    return -1;
}

static __noinline int bum_remote_egress_body(struct xdp_md *ctx, __u64 seq, __u32 ingress_if, __u32 egress_if)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 pkt_len = data_end - data;

    __u32 k = seq & (BUM_PLAN_RING_SIZE - 1);
    struct bum_plan *plan = bpf_map_lookup_elem(&bum_plan_ring, &k);
    if (!plan)
        goto drop;
    // The plan must be this frame's: same number, same source AC, same
    // length. A mismatch means the copy outlived its plan; sending it with
    // another frame's slot list could deliver it to the wrong peers.
    if (plan->seq != seq || plan->src_ifindex != ingress_if || plan->len != pkt_len) {
        STATS_INC(STATS_BUM_PLAN_STALE, pkt_len);
        return XDP_DROP;
    }

    struct bum_plan_uplink *up = NULL;
    for (__u32 u = 0; u < BUM_PLAN_MAX_UPLINKS; u++) {
        if (u >= plan->n_uplinks)
            break;
        if (plan->up[u].ifindex == egress_if) {
            up = &plan->up[u];
            break;
        }
    }
    // The devmap holds one entry per peer behind the uplink, plus the
    // device's local AC entry when it is an AC of the BD too; the plan
    // lists fewer slots when split horizon or flood_exclude removed some.
    // The copies are identical, so which one becomes the local copy does
    // not matter: the first one past the slots. The copies beyond that are
    // surplus, among them the ingress AC's own when the broadcast had to
    // include the ingress device (item.local is 0 there).
    if (!up) {
        STATS_INC(STATS_BUM_PLAN_SURPLUS, pkt_len);
        return XDP_DROP;
    }
    __u32 idx = up->next_idx++;
    if (idx >= up->n) {
        if (idx == up->n && up->local)
            return XDP_PASS;
        STATS_INC(STATS_BUM_PLAN_SURPLUS, pkt_len);
        return XDP_DROP;
    }

    // Kernels without "bpf: Run generic devmap egress prog on private skb"
    // hand every copy of a broadcast the same packet buffer, and the
    // headers one copy writes in front of the frame are what every queued
    // copy then carries. The control plane checks for that at startup and
    // runs xdp-mode BDs in tc mode there; should a shared buffer show up
    // anyway, only its first remote copy is encapsulated and the others are
    // dropped rather than sent to the wrong peer.
    if ((__u64)(long)ctx->data == plan->data && plan->shared++ > 0) {
        STATS_INC(STATS_BUM_SHARED_BUFFER, pkt_len);
        return XDP_DROP;
    }

    int slot = bum_plan_nth_slot(up->slots, idx);
    if (slot < 0)
        goto drop;
    __u32 src_if = plan->src_ifindex;
    struct bd_peer_key pk = { .bd_id = plan->bd_id, .index = (__u16)slot };
    struct headend_entry *peer = bpf_map_lookup_elem(&bd_peer_map, &pk);
    if (!peer)
        goto drop;

    if (bum_egress_encap(ctx, peer) < 0)
        goto drop;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
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

SEC("xdp/devmap")
int bum_remote_egress(struct xdp_md *ctx)
{
    __u64 seq;
    if (bum_egress_seq_generic(&seq) < 0) {
        STATS_INC(STATS_BUM_PLAN_STALE, (__u64)((long)ctx->data_end - (long)ctx->data));
        return XDP_DROP;
    }
    return bum_remote_egress_body(ctx, seq, ctx->ingress_ifindex, ctx->egress_ifindex);
}

// Test entry for BPF_PROG_TEST_RUN, which refuses devmap programs and any
// non-zero egress_ifindex. Runs the same body for the calling CPU's latest
// plan, with the source AC and egress device taken from
// bum_test_params_map; the control plane never attaches it.
//
// Every test run gets a fresh buffer, which may or may not land where the
// ingress run's was. same_buffer makes that explicit: 1 stands for a copy
// on the ingress buffer, 0 for a copy on a buffer of its own.
struct bum_test_params {
    __u32 ingress_ifindex;
    __u32 egress_ifindex;
    __u32 same_buffer;
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
    __u64 seq;
    if (bum_egress_seq_generic(&seq) < 0) {
        STATS_INC(STATS_BUM_PLAN_STALE, (__u64)((long)ctx->data_end - (long)ctx->data));
        return XDP_DROP;
    }
    __u32 rk = seq & (BUM_PLAN_RING_SIZE - 1);
    struct bum_plan *plan = bpf_map_lookup_elem(&bum_plan_ring, &rk);
    if (plan)
        plan->data = p->same_buffer ? (__u64)(long)ctx->data : 0;
    return bum_remote_egress_body(ctx, seq, p->ingress_ifindex, p->egress_ifindex);
}
