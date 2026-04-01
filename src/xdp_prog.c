#include <linux/types.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "xdp_prog.h"
#include "xdp_map.h"
#include "srv6.h"
#include "xdp_utils.h"
#include "srv6_headend_utils.h"
#include "srv6_headend.h"
#include "srv6_encaps.h"
#include "xdp_stats.h"
#include "xdpcap.h"
#include "srv6_endpoint.h"
#include "xdp_vlan.h"
#include "bum_meta.h"

char _license[] SEC("license") = "GPL";

// H.Encaps for IPv4 (RFC 8986 Section 5.1)
static __always_inline int do_h_encaps_v4(
    struct xdp_md *ctx,
    struct ethhdr *eth,
    struct iphdr *iph,
    struct headend_entry *entry)
{
    if (entry->num_segments < 1 || entry->num_segments > MAX_SEGMENTS) {
        DEBUG_PRINT("H.Encaps.v4: Invalid segment count %d\n", entry->num_segments);
        return XDP_DROP;
    }

    // Save before bpf_xdp_adjust_head invalidates packet pointers
    struct ethhdr saved_eth;
    __builtin_memcpy(&saved_eth, eth, sizeof(struct ethhdr));
    __u16 inner_total_len = bpf_ntohs(iph->tot_len);

    return do_h_encaps_core(ctx, &saved_eth, entry, IPPROTO_IPIP, inner_total_len);
}

static __always_inline int process_headend_v4(
    struct xdp_md *ctx,
    struct ethhdr *eth,
    struct iphdr *iph)
{
    struct lpm_key_v4 key = {
        .prefixlen = 32,
    };
    __builtin_memcpy(key.addr, &iph->daddr, IPV4_ADDR_LEN);

    struct headend_entry *entry = bpf_map_lookup_elem(&headend_v4_map, &key);
    if (!headend_should_encaps(entry)) {
        return XDP_PASS;
    }

    DEBUG_PRINT("Headend.v4: Performing H.Encaps\n");
    return do_h_encaps_v4(ctx, eth, iph, entry);
}

// H.Encaps for IPv6 (RFC 8986 Section 5.1)
static __always_inline int do_h_encaps_v6(
    struct xdp_md *ctx,
    struct ethhdr *eth,
    struct ipv6hdr *inner_ip6h,
    struct headend_entry *entry)
{
    if (entry->num_segments < 1 || entry->num_segments > MAX_SEGMENTS) {
        DEBUG_PRINT("H.Encaps.v6: Invalid segment count %d\n", entry->num_segments);
        return XDP_DROP;
    }

    // Save before bpf_xdp_adjust_head invalidates packet pointers
    struct ethhdr saved_eth;
    __builtin_memcpy(&saved_eth, eth, sizeof(struct ethhdr));
    // IPv6 total length = fixed header (40) + payload_len
    __u16 inner_total_len = 40 + bpf_ntohs(inner_ip6h->payload_len);

    return do_h_encaps_core(ctx, &saved_eth, entry, IPPROTO_IPV6, inner_total_len);
}

static __always_inline int process_headend_v6(
    struct xdp_md *ctx,
    struct ethhdr *eth,
    struct ipv6hdr *ip6h)
{
    struct lpm_key_v6 key = {
        .prefixlen = 128,
    };
    __builtin_memcpy(key.addr, &ip6h->daddr, IPV6_ADDR_LEN);

    struct headend_entry *entry = bpf_map_lookup_elem(&headend_v6_map, &key);
    if (!headend_should_encaps(entry)) {
        return XDP_PASS;
    }

    DEBUG_PRINT("Headend.v6: Performing H.Encaps\n");
    return do_h_encaps_v6(ctx, eth, ip6h, entry);
}

// Dispatch SRv6 Local SID endpoint functions for packets with Routing Header
static __always_inline int process_srv6_localsid(
    struct xdp_md *ctx,
    struct ethhdr *eth,
    struct ipv6hdr *ip6h,
    void *data_end)
{
    if (ip6h->nexthdr != IPPROTO_ROUTING) {
        return XDP_PASS;
    }

    void *srh_ptr = (void *)(ip6h + 1);
    if (srh_ptr + 8 > data_end) {
        return XDP_PASS;
    }

    struct ipv6_sr_hdr *srh = (struct ipv6_sr_hdr *)srh_ptr;

    if (srh->type != IPV6_SRCRT_TYPE_4) {
        DEBUG_PRINT("SRv6: Not SR type (type=%d)\n", srh->type);
        return XDP_PASS;
    }

    struct lpm_key_v6 key = {
        .prefixlen = 128,
    };
    __builtin_memcpy(key.addr, &ip6h->daddr, IPV6_ADDR_LEN);

    struct sid_function_entry *entry = bpf_map_lookup_elem(&sid_function_map, &key);
    if (!entry) {
        DEBUG_PRINT("SRv6: No SID function entry for DA\n");
        return XDP_PASS;
    }

    DEBUG_PRINT("SRv6: Found SID function, action=%d\n", entry->action);

    switch (entry->action) {
    case SRV6_LOCAL_ACTION_END:
        return process_end(ctx, ip6h, srh, entry);

    case SRV6_LOCAL_ACTION_END_X:
        return process_end_x(ctx, ip6h, srh, entry);

    case SRV6_LOCAL_ACTION_END_T:
        return process_end_t(ctx, ip6h, srh, entry);

    case SRV6_LOCAL_ACTION_END_DX2:
        return process_end_dx2(ctx, ip6h, srh, entry);

    case SRV6_LOCAL_ACTION_END_DX4:
        return process_end_dx4(ctx, ip6h, srh, entry);

    case SRV6_LOCAL_ACTION_END_DX6:
        return process_end_dx6(ctx, ip6h, srh, entry);

    case SRV6_LOCAL_ACTION_END_DT4:
        return process_end_dt4(ctx, ip6h, srh, entry);

    case SRV6_LOCAL_ACTION_END_DT6:
        return process_end_dt6(ctx, ip6h, srh, entry);

    case SRV6_LOCAL_ACTION_END_DT46:
        return process_end_dt46(ctx, ip6h, srh, entry);

    case SRV6_LOCAL_ACTION_END_DT2:
        return process_end_dt2(ctx, ip6h, srh, entry);

    // Phase 2+ endpoint functions (not yet implemented)
    case SRV6_LOCAL_ACTION_END_B6:
    case SRV6_LOCAL_ACTION_END_B6_ENCAPS:
    case SRV6_LOCAL_ACTION_END_BM:
    case SRV6_LOCAL_ACTION_END_S:
    case SRV6_LOCAL_ACTION_END_AS:
    case SRV6_LOCAL_ACTION_END_AM:
    case SRV6_LOCAL_ACTION_END_BPF:
    default:
        DEBUG_PRINT("SRv6: Unsupported action %d\n", entry->action);
        return XDP_PASS;
    }
}

// Forward declaration for do_h_encaps_l2 (defined below, used by process_bd_forwarding)
static __noinline int do_h_encaps_l2(
    struct xdp_md *ctx,
    struct headend_entry *entry,
    __u16 l2_frame_len);

// BD forwarding: MAC learning, BUM flood, FDB-based unicast forwarding.
// Shared by both VLAN-tagged and untagged paths.
//
// Returns:
//   >= 0 : final XDP action (caller should goto out)
//   -1   : no BD processing done (caller should fall through)
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

    // src MAC learning: only overwrite if missing or local entry with different oif.
    // Do NOT overwrite remote entries (is_remote=1) — those are learned by End.DT2.
    __builtin_memcpy(key.mac, eth->h_source, ETH_ALEN);
    struct fdb_entry *existing = bpf_map_lookup_elem(&fdb_map, &key);
    if (!existing ||
        (!existing->is_remote && existing->oif != ctx->ingress_ifindex)) {
        struct fdb_entry learn_val = { .oif = ctx->ingress_ifindex };
        bpf_map_update_elem(&fdb_map, &key, &learn_val, BPF_ANY);
    }

    // BUM (broadcast/unknown-unicast/multicast) -> meta + XDP_PASS for TC flood
    if (eth->h_dest[0] & 0x01) {
        xdp_write_bum_meta(ctx, vlan_id);
        return XDP_PASS;
    }

    // dst MAC lookup
    __builtin_memcpy(key.mac, eth->h_dest, ETH_ALEN);
    struct fdb_entry *dst_fdb = bpf_map_lookup_elem(&fdb_map, &key);
    if (dst_fdb) {
        if (dst_fdb->is_remote) {
            // Remote FDB hit -> bd_peer_map -> SRv6 encap
            struct bd_peer_key pk = { .bd_id = dst_fdb->bd_id, .index = dst_fdb->peer_index };
            struct headend_entry *pe = bpf_map_lookup_elem(&bd_peer_map, &pk);
            if (pe) {
                __u16 l2_frame_len = (__u16)pkt_len;
                return do_h_encaps_l2(ctx, pe, l2_frame_len);
            }
        }
        // Local FDB hit -> bridge forwarding
        return XDP_PASS;
    }

    // FDB miss -> BUM flood (unknown unicast)
    xdp_write_bum_meta(ctx, vlan_id);
    return XDP_PASS;
}

// H.Encaps.L2: Prepend [Outer Eth][Outer IPv6][SRH] before the L2 frame (RFC 8986 Section 5.1)
static __noinline int do_h_encaps_l2(
    struct xdp_md *ctx,
    struct headend_entry *entry,
    __u16 l2_frame_len)
{
    if (entry->num_segments < 1 || entry->num_segments > MAX_SEGMENTS) {
        return XDP_DROP;
    }

    int srh_len = 8 + (16 * entry->num_segments);
    int new_headers_len = sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + srh_len;

    if (bpf_xdp_adjust_head(ctx, -(new_headers_len))) {
        return XDP_DROP;
    }

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *new_eth = data;
    CHECK_BOUND(new_eth, data_end, sizeof(*new_eth));

    struct ipv6hdr *outer_ip6h = (struct ipv6hdr *)(new_eth + 1);
    CHECK_BOUND(outer_ip6h, data_end, sizeof(*outer_ip6h));

    struct ipv6_sr_hdr *srh = (struct ipv6_sr_hdr *)(outer_ip6h + 1);
    CHECK_BOUND(srh, data_end, 8);
    CHECK_BOUND(srh, data_end, srh_len);

    __builtin_memset(new_eth->h_dest, 0, ETH_ALEN);
    __builtin_memset(new_eth->h_source, 0, ETH_ALEN);
    new_eth->h_proto = bpf_htons(ETH_P_IPV6);

    outer_ip6h->version = 6;
    outer_ip6h->priority = 0;
    outer_ip6h->flow_lbl[0] = 0;
    outer_ip6h->flow_lbl[1] = 0;
    outer_ip6h->flow_lbl[2] = 0;
    outer_ip6h->payload_len = bpf_htons(srh_len + l2_frame_len);
    outer_ip6h->nexthdr = IPPROTO_ROUTING;
    outer_ip6h->hop_limit = 64;
    __builtin_memcpy(&outer_ip6h->saddr, entry->src_addr, sizeof(struct in6_addr));
    __builtin_memcpy(&outer_ip6h->daddr, &entry->segments[0], sizeof(struct in6_addr));

    srh->nexthdr = IPPROTO_ETHERNET;
    srh->hdrlen = (srh_len >> 3) - 1;
    srh->type = IPV6_SRCRT_TYPE_4;
    srh->segments_left = entry->num_segments - 1;
    srh->first_segment = entry->num_segments - 1;
    srh->flags = 0;
    srh->tag = 0;

    void *srh_segments = (void *)srh + 8;
    if (copy_segments_to_srh(srh_segments, data_end, entry->segments, entry->num_segments) != 0) {
        return XDP_DROP;
    }

    __u32 ifindex;
    int fib_result = srv6_fib_lookup_and_update(ctx, outer_ip6h, new_eth, &ifindex, ctx->ingress_ifindex);

    switch (fib_result) {
    case FIB_RESULT_REDIRECT:
        return bpf_redirect(ifindex, 0);
    case FIB_RESULT_DROP:
        return XDP_DROP;
    default:
        // After encap, must not return XDP_PASS (stale pointers in caller)
        return XDP_DROP;
    }
}

// L3 processing macro with constant-offset packet pointer derivation.
// After process_srv6_localsid (which may call bpf_xdp_adjust_head internally),
// ip6h is invalidated by the verifier's state merging. We re-derive it from
// ctx->data using the same constant L3_OFFSET to get a fresh pkt_ptr.
#define DO_L3_PROCESS(ctx, l3_offset, d_end, proto)                            \
    do {                                                                        \
        if ((proto) == bpf_htons(ETH_P_IPV6)) {                                \
            void *_d = (void *)(long)(ctx)->data;                               \
            void *_de = (void *)(long)(ctx)->data_end;                          \
            struct ethhdr *_eth = _d;                                           \
            if ((void *)(_eth + 1) > _de) { action = XDP_PASS; goto out; }     \
            struct ipv6hdr *_ip6h = (struct ipv6hdr *)(_d + (l3_offset));       \
            if ((void *)(_ip6h + 1) > _de) { action = XDP_PASS; goto out; }    \
            action = process_srv6_localsid(ctx, _eth, _ip6h, _de);             \
            if (action != XDP_PASS) goto out;                                   \
            /* Re-derive after localsid (bpf_xdp_adjust_head invalidates) */    \
            _d = (void *)(long)(ctx)->data;                                     \
            _de = (void *)(long)(ctx)->data_end;                                \
            _eth = _d;                                                          \
            if ((void *)(_eth + 1) > _de) { action = XDP_PASS; goto out; }     \
            _ip6h = (struct ipv6hdr *)(_d + (l3_offset));                       \
            if ((void *)(_ip6h + 1) > _de) { action = XDP_PASS; goto out; }    \
            action = process_headend_v6(ctx, _eth, _ip6h);                     \
            goto out;                                                           \
        }                                                                       \
        if ((proto) == bpf_htons(ETH_P_IP)) {                                 \
            void *_d = (void *)(long)(ctx)->data;                               \
            void *_de = (void *)(long)(ctx)->data_end;                          \
            struct ethhdr *_eth = _d;                                           \
            if ((void *)(_eth + 1) > _de) { action = XDP_PASS; goto out; }     \
            struct iphdr *_iph = (struct iphdr *)(_d + (l3_offset));            \
            if ((void *)(_iph + 1) > _de) { action = XDP_PASS; goto out; }     \
            action = process_headend_v4(ctx, _eth, _iph);                      \
            goto out;                                                           \
        }                                                                       \
    } while (0)

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

        struct headend_l2_key l2_key = { .ifindex = ctx->ingress_ifindex, .vlan_id = vlan_id };
        struct headend_entry *l2_entry = bpf_map_lookup_elem(&headend_l2_map, &l2_key);
        if (headend_should_encaps_l2(l2_entry)) {
            int bd_action = process_bd_forwarding(ctx, l2_entry, vlan_id, pkt_len);
            if (bd_action >= 0) {
                action = bd_action;
                goto out;
            }
            // bd_id == 0: no Bridge Domain, direct H.Encaps.L2 for all traffic
            action = do_h_encaps_l2(ctx, l2_entry, (__u16)pkt_len);
            goto out;
        }

        // L2 miss — use a fresh scope with new variables to prevent clang
        // from reusing stale packet pointers from before the map lookup.
        {
            void *d2 = (void *)(long)ctx->data;
            void *d2_end = (void *)(long)ctx->data_end;
            struct ethhdr *e2 = d2;
            if ((void *)(e2 + 1) > d2_end)
                goto out;

            if (inner_proto == bpf_htons(ETH_P_8021Q) ||
                inner_proto == bpf_htons(ETH_P_8021AD)) {
                // QinQ: skip 2 VLAN tags
                struct vlan_hdr *v2a = (struct vlan_hdr *)(e2 + 1);
                if ((void *)(v2a + 1) > d2_end)
                    goto out;
                struct vlan_hdr *v2b = v2a + 1;
                if ((void *)(v2b + 1) > d2_end)
                    goto out;
                __u16 proto2 = v2b->h_vlan_encapsulated_proto;
                DO_L3_PROCESS(ctx, 22, d2_end, proto2);  /* eth(14) + 2*vlan(4) */
            } else {
                DO_L3_PROCESS(ctx, 18, d2_end, inner_proto);  /* eth(14) + vlan(4) */
            }
        }
        goto out;
    }

    // ========== Non-VLAN packets ==========
    {
        struct headend_l2_key l2_key = { .ifindex = ctx->ingress_ifindex, .vlan_id = 0 };
        struct headend_entry *l2_entry = bpf_map_lookup_elem(&headend_l2_map, &l2_key);
        if (headend_should_encaps_l2(l2_entry)) {
            int bd_action = process_bd_forwarding(ctx, l2_entry, 0, pkt_len);
            if (bd_action >= 0) {
                action = bd_action;
                goto out;
            }
            // bd_id == 0: no Bridge Domain, direct H.Encaps.L2 for all traffic
            action = do_h_encaps_l2(ctx, l2_entry, (__u16)pkt_len);
            goto out;
        }
    }

    DO_L3_PROCESS(ctx, 14, data_end, eth_proto);  /* eth(14) */

out:
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

    RETURN_ACTION(ctx, &xdpcap_hook, action);
}

#include "tc_bum.h"

SEC("tc")
int vinbero_tc_ingress(struct __sk_buff *skb)
{
    // Mode 2: Encap — clone returned to self with PE info in cb[]
    if (skb->cb[0] == TC_CB_ENCAP_MAGIC)
        return tc_do_single_pe_encap(skb, skb->cb[1], skb->cb[2]);

    // Mode 1: Dispatch — XDP wrote BUM meta, clone to self for each PE
    __u16 vlan_id;
    if (!tc_read_bum_meta(skb, &vlan_id))
        return TC_ACT_OK;

    return tc_dispatch_bum_clones(skb, vlan_id);
}
