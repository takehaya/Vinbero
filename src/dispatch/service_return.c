// Service-programming return path (draft-ietf-spring-srv6-service-programming).
// Included from xdp_prog.c — not compiled standalone.
//
// A proxy IFACE-IN is a dedicated attachment circuit: every frame arriving
// on it belongs to the one proxy segment bound to that circuit. The front
// door (xdp_main) calls try_service_return before try_l2_headend; a miss
// returns -1 and the packet continues down the ordinary pipeline, so
// non-proxy traffic pays exactly one hash lookup.
//
// The bpf_tail_call into service_return_progs below must stay the single
// lexical site referencing that PROG_ARRAY in this translation unit: a
// second site silently breaks XDP_REDIRECT from the targets (see the
// repro note in dispatch/l2_headend.c).

// Map the outermost ethertype to the SVC_INNER_* capability required to
// accept the frame. An Ethernet-typed circuit accepts any frame (the whole
// frame is the payload); an L3-typed circuit accepts only its own family.
static __always_inline int svc_inner_type_ok(__u8 mask, __u16 eth_proto)
{
    if (mask & SVC_INNER_ETHERNET)
        return 1;
    if (eth_proto == bpf_htons(ETH_P_IP))
        return mask & SVC_INNER_IPV4;
    if (eth_proto == bpf_htons(ETH_P_IPV6))
        return mask & SVC_INNER_IPV6;
    return 0;
}

// ========== Return tail-call targets ==========

// SVC_RET_AS: re-encapsulate the service's output from the static CACHE
// (tctx->headend, copied from service_ingress_entry.encap by the front
// door below). L3 circuits carry the real l3_offset; an Ethernet circuit
// carries 0 and the whole frame is the payload (see DISPATCH_SERVICE_RETURN).
SEC("xdp")
int tailcall_service_return_as(struct xdp_md *ctx)
{
    struct tailcall_ctx *tctx = tailcall_ctx_read();
    if (!tctx) TAILCALL_RETURN(ctx, XDP_DROP);

    struct headend_entry *entry = &tctx->headend;
    if (entry->num_segments < 1 || entry->num_segments > MAX_SEGMENTS)
        TAILCALL_RETURN(ctx, XDP_DROP);

    if (tctx->l3_offset == 0) {
        // Ethernet circuit: wrap the whole frame (H.Encaps.L2 shape).
        void *data = (void *)(long)ctx->data;
        void *data_end = (void *)(long)ctx->data_end;
        __u16 l2_frame_len = (__u16)(data_end - data);
        int action = do_h_encaps_l2(ctx, entry, l2_frame_len);
        TAILCALL_RETURN(ctx, action);
    }

    TAILCALL_BOUND_L3OFF(tctx, l3_off);
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        TAILCALL_RETURN(ctx, XDP_DROP);

    struct ethhdr saved_eth;
    __builtin_memcpy(&saved_eth, eth, sizeof(saved_eth));

    // The front door validated the payload against the circuit's inner
    // type mask; the IP version nibble picks the concrete family here.
    void *l3 = data + l3_off;
    if (l3 + 1 > data_end)
        TAILCALL_RETURN(ctx, XDP_DROP);
    __u8 ver = (*(__u8 *)l3) >> 4;

    int action;
    if (ver == 4) {
        struct iphdr *iph = (struct iphdr *)l3;
        if ((void *)(iph + 1) > data_end)
            TAILCALL_RETURN(ctx, XDP_DROP);
        action = CALL_WITH_CONST_L3(l3_off, do_h_encaps_core, ctx,
                                    &saved_eth, entry, IPPROTO_IPIP,
                                    bpf_ntohs(iph->tot_len));
    } else if (ver == 6) {
        struct ipv6hdr *inner_ip6h = (struct ipv6hdr *)l3;
        if ((void *)(inner_ip6h + 1) > data_end)
            TAILCALL_RETURN(ctx, XDP_DROP);
        action = CALL_WITH_CONST_L3(l3_off, do_h_encaps_core, ctx,
                                    &saved_eth, entry, IPPROTO_IPV6,
                                    bpf_ntohs(inner_ip6h->payload_len) +
                                        (__u16)sizeof(struct ipv6hdr));
    } else {
        action = XDP_DROP;
    }
    TAILCALL_RETURN(ctx, action);
}

// SVC_RET_AD: prepend the dynamically cached outer IPv6 + SRH. The cache
// was seeded by the forward direction in the ready-to-prepend form
// (SL decremented, DA = next segment, flow label zeroed); only the
// payload length needs recomputing per packet. A miss or an invalid row
// drops: the chain has not taught us where this circuit's traffic goes.
SEC("xdp")
int tailcall_service_return_ad(struct xdp_md *ctx)
{
    struct tailcall_ctx *tctx = tailcall_ctx_read();
    if (!tctx) TAILCALL_RETURN(ctx, XDP_DROP);

    struct service_ingress_key key = {
        .ifindex = ctx->ingress_ifindex,
        .vlan_id = tctx->svc_vlan_id,
    };
    struct ad_cache_val *val = bpf_map_lookup_elem(&ad_cache_map, &key);
    if (!val || !val->valid)
        TAILCALL_RETURN(ctx, XDP_DROP);
    __u32 hdr_len = val->hdr_len;
    if (hdr_len < sizeof(struct ipv6hdr) + 8 || hdr_len > AD_CACHE_HDR_MAX)
        TAILCALL_RETURN(ctx, XDP_DROP);

    __u16 l3_off = tctx->l3_offset; // 0 = Ethernet circuit (whole frame is payload)
    if (l3_off > 22)
        TAILCALL_RETURN(ctx, XDP_DROP);

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u16 frame_len = (__u16)(data_end - data);
    if (l3_off >= frame_len)
        TAILCALL_RETURN(ctx, XDP_DROP);
    __u16 payload_total = frame_len - l3_off; // Ethernet circuit: the whole frame

    struct ethhdr saved_eth = {};
    if (l3_off != 0) {
        struct ethhdr *eth = data;
        if ((void *)(eth + 1) > data_end)
            TAILCALL_RETURN(ctx, XDP_DROP);
        __builtin_memcpy(&saved_eth, eth, sizeof(saved_eth));
    }
    saved_eth.h_proto = bpf_htons(ETH_P_IPV6);

    // Grow headroom for [Eth][cached outer], consuming the original L2
    // bytes (l3_off; zero on an Ethernet circuit where the frame itself
    // is the payload).
    if (bpf_xdp_adjust_head(ctx, -(int)(ETH_HLEN + hdr_len - l3_off)))
        TAILCALL_RETURN(ctx, XDP_DROP);

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    struct ethhdr *new_eth = data;
    if ((void *)(new_eth + 1) > data_end)
        TAILCALL_RETURN(ctx, XDP_DROP);
    __builtin_memcpy(new_eth, &saved_eth, sizeof(saved_eth));

    // Constant-size store per possible header length (see the matching
    // switch in svc_ad_cache_seed for why a variable length is rejected).
    switch (hdr_len) {
#define AD_REPLAY_CASE(n)                                            \
    case (n):                                                        \
        if (bpf_xdp_store_bytes(ctx, ETH_HLEN, val->hdr, (n)))       \
            TAILCALL_RETURN(ctx, XDP_DROP);                          \
        break;
    AD_REPLAY_CASE(48)  AD_REPLAY_CASE(64)  AD_REPLAY_CASE(80)
    AD_REPLAY_CASE(96)  AD_REPLAY_CASE(112) AD_REPLAY_CASE(128)
    AD_REPLAY_CASE(144) AD_REPLAY_CASE(160) AD_REPLAY_CASE(176)
    AD_REPLAY_CASE(192) AD_REPLAY_CASE(208)
#undef AD_REPLAY_CASE
    default:
        TAILCALL_RETURN(ctx, XDP_DROP);
    }

    // The cached payload_len is from the seeding packet; recompute for
    // this one: SRH (hdr_len - 40) + the payload behind it.
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    struct ipv6hdr *outer = (struct ipv6hdr *)(data + ETH_HLEN);
    if ((void *)(outer + 1) > data_end)
        TAILCALL_RETURN(ctx, XDP_DROP);
    outer->payload_len = bpf_htons((__u16)(hdr_len - sizeof(struct ipv6hdr)) + payload_total);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        TAILCALL_RETURN(ctx, XDP_DROP);
    int action = srv6_fib_redirect(ctx, outer, eth, ctx->ingress_ifindex);
    TAILCALL_RETURN(ctx, action);
}

// Return-path front door. Returns -1 when {ifindex, vlan} is not a proxy
// IFACE-IN (caller continues the normal pipeline) or an XDP action.
// eth_proto is the ethertype at l3_offset (inner proto for VLAN frames).
static __noinline int try_service_return(
    struct xdp_md *ctx,
    __u32 ifindex,
    __u16 vlan_id,
    __u16 l3_offset,
    __u16 eth_proto)
{
    struct service_ingress_key key = {
        .ifindex = ifindex,
        .vlan_id = vlan_id,
    };
    struct service_ingress_entry *entry =
        bpf_map_lookup_elem(&service_ingress_map, &key);
    if (!entry)
        return -1;

    // A frame that is not the circuit's payload type is link maintenance
    // (ARP on an IPv4 circuit, LLDP, ...) — hand it to the kernel so the
    // circuit's neighbour state stays alive. Only matching payloads enter
    // the proxy.
    if (!svc_inner_type_ok(entry->inner_type_mask, eth_proto))
        return XDP_PASS;

    if (entry->inner_type_mask & SVC_INNER_ETHERNET) {
        // Ethernet-typed circuit: the whole frame (offset 0) is the
        // payload to re-encapsulate, so l3_offset must not point the
        // return program at an L3 header it would strip.
        l3_offset = 0;
    } else {
        // L3 circuit: ND / multicast / broadcast is link maintenance too
        // (an IPv6 ethertype match includes NS/NA), and must reach the
        // kernel instead of being encapsulated into the chain.
        void *data = (void *)(long)ctx->data;
        void *data_end = (void *)(long)ctx->data_end;
        if (eth_proto == bpf_htons(ETH_P_IPV6)) {
            struct ipv6hdr *ip6h = (struct ipv6hdr *)(data + l3_offset);
            if ((void *)(ip6h + 1) > data_end)
                return XDP_PASS;
            __u8 d0 = ip6h->daddr.s6_addr[0];
            __u8 d1 = ip6h->daddr.s6_addr[1];
            if (d0 == 0xff || (d0 == 0xfe && (d1 & 0xc0) == 0x80))
                return XDP_PASS; // multicast / link-local destination
        } else {
            struct iphdr *iph = (struct iphdr *)(data + l3_offset);
            if ((void *)(iph + 1) > data_end)
                return XDP_PASS;
            __u8 d0 = ((__u8 *)&iph->daddr)[0];
            if (d0 >= 224)
                return XDP_PASS; // multicast / broadcast destination
        }
    }

    if (tailcall_ctx_write_headend(&entry->encap, l3_offset,
                                   DISPATCH_SERVICE_RETURN, entry->behavior,
                                   0) == 0) {
        tailcall_ctx_set_svc_vlan(vlan_id);
        bpf_tail_call(ctx, &service_return_progs, entry->behavior);
    }
    // Unpopulated slot (behavior not implemented yet) or ctx write failure:
    // the circuit is dedicated, so fail closed rather than leaking the raw
    // service frame into the normal pipeline.
    return XDP_DROP;
}
