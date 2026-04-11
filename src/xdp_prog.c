#include <linux/types.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <stdbool.h>
#include <stddef.h>

#include "core/xdp_prog.h"
#include "core/xdp_map.h"
#include "core/srv6.h"
#include "headend/srv6_headend_utils.h"
#include "headend/srv6_headend.h"
#include "headend/srv6_encaps.h"
#include "headend/srv6_encaps_red.h"
#include "headend/srv6_insert.h"
#include "core/xdp_stats.h"
#include "core/xdpcap.h"
#include "endpoint/srv6_endpoint.h"
#include "endpoint/srv6_end_b6.h"
#include "l2vpn/bum_meta.h"
#include "mobile/srv6_gtp.h"
#include "mobile/srv6_gtp_decap.h"
#include "mobile/srv6_gtp_encap.h"

char _license[] SEC("license") = "GPL";

static __noinline int process_headend_v4(
    struct xdp_md *ctx,
    struct ethhdr *eth,
    struct iphdr *iph,
    __u16 l3_offset)
{
    struct lpm_key_v4 key = {
        .prefixlen = 32,
    };
    __builtin_memcpy(key.addr, &iph->daddr, IPV4_ADDR_LEN);

    struct headend_entry *entry = bpf_map_lookup_elem(&headend_v4_map, &key);
    if (!entry)
        return XDP_PASS;

    switch (entry->mode) {
    case SRV6_HEADEND_BEHAVIOR_H_ENCAPS:
        DEBUG_PRINT("Headend.v4: Performing H.Encaps\n");
        return do_h_encaps_v4(ctx, eth, iph, entry, l3_offset);
    case SRV6_HEADEND_BEHAVIOR_H_ENCAPS_RED:
        DEBUG_PRINT("Headend.v4: Performing H.Encaps.Red\n");
        return do_h_encaps_red_v4(ctx, eth, iph, entry, l3_offset);
    case SRV6_HEADEND_BEHAVIOR_H_M_GTP4_D:
        DEBUG_PRINT("Headend.v4: Performing H.M.GTP4.D\n");
        return do_h_m_gtp4_d(ctx, eth, iph, entry, l3_offset);
    default:
        return XDP_PASS;
    }
}

static __noinline int process_headend_v6(
    struct xdp_md *ctx,
    struct ethhdr *eth,
    struct ipv6hdr *ip6h,
    __u16 l3_offset)
{
    struct lpm_key_v6 key = {
        .prefixlen = 128,
    };
    __builtin_memcpy(key.addr, &ip6h->daddr, IPV6_ADDR_LEN);

    struct headend_entry *entry = bpf_map_lookup_elem(&headend_v6_map, &key);
    if (!entry)
        return XDP_PASS;

    switch (entry->mode) {
    case SRV6_HEADEND_BEHAVIOR_H_ENCAPS:
        DEBUG_PRINT("Headend.v6: Performing H.Encaps\n");
        return do_h_encaps_v6(ctx, eth, ip6h, entry, l3_offset);
    case SRV6_HEADEND_BEHAVIOR_H_ENCAPS_RED:
        DEBUG_PRINT("Headend.v6: Performing H.Encaps.Red\n");
        return do_h_encaps_red_v6(ctx, eth, ip6h, entry, l3_offset);
    case SRV6_HEADEND_BEHAVIOR_H_INSERT:
        DEBUG_PRINT("Headend.v6: Performing H.Insert\n");
        return do_h_insert_v6(ctx, eth, ip6h, entry, l3_offset);
    case SRV6_HEADEND_BEHAVIOR_H_INSERT_RED:
        DEBUG_PRINT("Headend.v6: Performing H.Insert.Red\n");
        return do_h_insert_red_v6(ctx, eth, ip6h, entry, l3_offset);
    default:
        return XDP_PASS;
    }
}

// FIB redirect after no-SRH decap.
// After decapsulation, the packet is [Eth(14)][Inner IP].
// Set EtherType, do FIB lookup, and redirect.
// XDP_PASS is converted to XDP_DROP because the packet structure has changed
// (inner IP exposed) and cannot be safely passed to the kernel stack.
static __always_inline int nosrh_fib_v4(
    struct xdp_md *ctx,
    struct sid_function_entry *entry)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_DROP;

    eth->h_proto = bpf_htons(ETH_P_IP);
    STATS_INC(STATS_SRV6_END, 0);

    __u32 fib_ifindex = entry->vrf_ifindex ? entry->vrf_ifindex : ctx->ingress_ifindex;
    int action = srv6_fib_redirect_v4(ctx, iph, eth, fib_ifindex);
    return (action == XDP_PASS) ? XDP_DROP : action;
}

static __always_inline int nosrh_fib_v6(
    struct xdp_md *ctx,
    struct sid_function_entry *entry)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    struct ipv6hdr *inner_ip6h = (void *)(eth + 1);
    if ((void *)(inner_ip6h + 1) > data_end)
        return XDP_DROP;

    eth->h_proto = bpf_htons(ETH_P_IPV6);
    STATS_INC(STATS_SRV6_END, 0);

    __u32 fib_ifindex = entry->vrf_ifindex ? entry->vrf_ifindex : ctx->ingress_ifindex;
    int action = srv6_fib_redirect(ctx, inner_ip6h, eth, fib_ifindex);
    return (action == XDP_PASS) ? XDP_DROP : action;
}

// No-SRH decap for Reduced SRH single-segment packets.
// DA lookup + decap in a separate __noinline to isolate verifier state.
static __noinline int process_srv6_decap_nosrh(
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

    // Aux lookup for actions that need it (DX2, DT2)
    struct sid_aux_entry *aux = NULL;
    if (entry->has_aux) {
        __u32 idx = entry->aux_index;
        aux = bpf_map_lookup_elem(&sid_aux_map, &idx);
    }

    switch (entry->action) {
    case SRV6_LOCAL_ACTION_END_DX4:
    case SRV6_LOCAL_ACTION_END_DT4:
        if (srv6_decap_nosrh(ctx, IPPROTO_IPIP, nh, l3_offset) != 0) return XDP_DROP;
        return nosrh_fib_v4(ctx, entry);
    case SRV6_LOCAL_ACTION_END_DX6:
    case SRV6_LOCAL_ACTION_END_DT6:
        if (srv6_decap_nosrh(ctx, IPPROTO_IPV6, nh, l3_offset) != 0) return XDP_DROP;
        return nosrh_fib_v6(ctx, entry);
    case SRV6_LOCAL_ACTION_END_DT46:
        // RFC 8986 Section 4.9: DT46 handles IPv4/IPv6 only.
        // L2 (IPPROTO_ETHERNET) requires End.DT2.
        if (nh == IPPROTO_IPIP) {
            if (srv6_decap_nosrh(ctx, IPPROTO_IPIP, nh, l3_offset) != 0) return XDP_DROP;
            return nosrh_fib_v4(ctx, entry);
        }
        if (nh == IPPROTO_IPV6) {
            if (srv6_decap_nosrh(ctx, IPPROTO_IPV6, nh, l3_offset) != 0) return XDP_DROP;
            return nosrh_fib_v6(ctx, entry);
        }
        return XDP_DROP;
    case SRV6_LOCAL_ACTION_END_DX2: {
        if (!aux) return XDP_DROP;
        __u32 oif;
        __builtin_memcpy(&oif, aux->nexthop.nexthop, sizeof(__u32));
        if (oif == 0) return XDP_DROP;
        if (srv6_decap_l2_nosrh(ctx, nh, l3_offset) != 0) return XDP_DROP;
        STATS_INC(STATS_SRV6_END, 0);
        return bpf_redirect(oif, 0);
    }
    case SRV6_LOCAL_ACTION_END_DT2:
        return process_end_dt2_nosrh(ctx, ip6h, nh, entry, aux, l3_offset);
    default:
        return XDP_PASS;
    }
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

    // Aux lookup: only when entry->has_aux is set
    struct sid_aux_entry *aux = NULL;
    if (entry->has_aux) {
        __u32 idx = entry->aux_index;
        aux = bpf_map_lookup_elem(&sid_aux_map, &idx);
    }

    switch (entry->action) {
    case SRV6_LOCAL_ACTION_END:
        return process_end(ctx, ip6h, srh, entry, l3_offset);
    case SRV6_LOCAL_ACTION_END_X:
        return process_end_x(ctx, ip6h, srh, entry, aux, l3_offset);
    case SRV6_LOCAL_ACTION_END_T:
        return process_end_t(ctx, ip6h, srh, entry, l3_offset);
    case SRV6_LOCAL_ACTION_END_DX2:
        return process_end_dx2(ctx, ip6h, srh, entry, aux, l3_offset);
    case SRV6_LOCAL_ACTION_END_DX4:
        return process_end_dx4(ctx, ip6h, srh, entry, l3_offset);
    case SRV6_LOCAL_ACTION_END_DX6:
        return process_end_dx6(ctx, ip6h, srh, entry, l3_offset);
    case SRV6_LOCAL_ACTION_END_DT4:
        return process_end_dt4(ctx, ip6h, srh, entry, l3_offset);
    case SRV6_LOCAL_ACTION_END_DT6:
        return process_end_dt6(ctx, ip6h, srh, entry, l3_offset);
    case SRV6_LOCAL_ACTION_END_DT46:
        return process_end_dt46(ctx, ip6h, srh, entry, l3_offset);
    case SRV6_LOCAL_ACTION_END_DT2:
        return process_end_dt2(ctx, ip6h, srh, entry, aux, l3_offset);
    case SRV6_LOCAL_ACTION_END_B6:
        return process_end_b6_insert(ctx, ip6h, srh, entry, aux, l3_offset);
    case SRV6_LOCAL_ACTION_END_B6_ENCAPS:
        return process_end_b6_encaps(ctx, ip6h, srh, entry, aux, l3_offset);
    case SRV6_LOCAL_ACTION_END_M_GTP4_E:
        return process_end_m_gtp4_e(ctx, ip6h, srh, entry, aux, l3_offset);
    case SRV6_LOCAL_ACTION_END_M_GTP6_D:
        return process_end_m_gtp6_d(ctx, ip6h, srh, entry, aux, l3_offset);
    case SRV6_LOCAL_ACTION_END_M_GTP6_D_DI:
        return process_end_m_gtp6_d_di(ctx, ip6h, srh, entry, l3_offset);
    case SRV6_LOCAL_ACTION_END_M_GTP6_E:
        return process_end_m_gtp6_e(ctx, ip6h, srh, entry, aux, l3_offset);
    default:
        return XDP_PASS;
    }
}

#include "headend/srv6_encaps_l2.h"

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
    // Do NOT overwrite static entries (is_static=1) — those are user-configured.
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
        // Refresh timestamp for existing dynamic entry
        existing->last_seen = bpf_ktime_get_ns();
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
                if (pe->mode == SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2_RED)
                    return do_h_encaps_l2_red(ctx, pe, l2_frame_len);
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

// L2 headend check: BD forwarding if bd_id > 0, else direct H.Encaps.L2.
// __noinline: own stack frame to avoid inflating vinbero_main's stack
// (process_bd_forwarding is __always_inline, expands here).
//
// Returns >= 0: final XDP action; -1: no L2 headend configured
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

    // bd_id == 0: no Bridge Domain, direct H.Encaps.L2 for all traffic
    if (l2_entry->mode == SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2_RED)
        return do_h_encaps_l2_red(ctx, l2_entry, (__u16)pkt_len);
    return do_h_encaps_l2(ctx, l2_entry, (__u16)pkt_len);
}

// L3 processing pipeline.
// IPv6: localsid (SRH endpoint) -> decap_nosrh (Reduced SRH) -> headend
// IPv4: headend only (IPv4 is transit traffic for SRv6 encapsulation)
//
// __noinline: BPF subprogram boundary for verifier state isolation
static __noinline int process_l3(struct xdp_md *ctx, __u16 l3_offset, __u16 proto)
{
    if (proto == bpf_htons(ETH_P_IPV6)) {
        struct ethhdr *eth;
        struct ipv6hdr *ip6h;

        // Stage 1: SRH-based endpoint processing (End, End.X, End.DT*, etc.)
        REDERIVE_ETH_IP6(ctx, l3_offset, eth, ip6h);
        int action = process_srv6_localsid(ctx, eth, ip6h, l3_offset);
        if (action != XDP_PASS) return action;

        // Stage 2: Reduced SRH decap (re-derive: localsid may adjust_head)
        REDERIVE_ETH_IP6(ctx, l3_offset, eth, ip6h);
        action = process_srv6_decap_nosrh(ctx, ip6h, l3_offset);
        if (action != XDP_PASS) return action;

        // Stage 3: Headend encapsulation (re-derive: decap may adjust_head)
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

        // L2 miss — re-derive packet pointers after noinline call
        // (inner_proto is a scalar on the stack, still valid)
        data = (void *)(long)ctx->data;
        data_end = (void *)(long)ctx->data_end;
        eth = data;
        if ((void *)(eth + 1) > data_end)
            goto out;

        if (inner_proto == bpf_htons(ETH_P_8021Q) ||
            inner_proto == bpf_htons(ETH_P_8021AD)) {
            // QinQ: skip 2 VLAN tags
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

    action = process_l3(ctx, 14, eth_proto);  /* eth(14) */

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

#include "l2vpn/tc_bum.h"

SEC("tc")
int vinbero_tc_ingress(struct __sk_buff *skb)
{
    // Mode 2: Encap — clone returned to self with PE info in cb[]
    if (skb->cb[0] == TC_CB_ENCAP_MAGIC) {
        struct bd_peer_key pk = { .bd_id = (__u16)skb->cb[1], .index = (__u16)skb->cb[2] };
        struct headend_entry *pe = bpf_map_lookup_elem(&bd_peer_map, &pk);
        if (pe && pe->mode == SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2_RED)
            return tc_do_single_pe_encap_red(skb, skb->cb[1], skb->cb[2]);
        return tc_do_single_pe_encap(skb, skb->cb[1], skb->cb[2]);
    }

    // Mode 1: Dispatch — XDP wrote BUM meta, clone to self for each PE
    __u16 vlan_id;
    if (!tc_read_bum_meta(skb, &vlan_id))
        return TC_ACT_OK;

    return tc_dispatch_bum_clones(skb, vlan_id);
}
