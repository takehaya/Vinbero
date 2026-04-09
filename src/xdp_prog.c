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

// H.Encaps.Red for IPv4 (RFC 8986 Section 5.1.1)
static __always_inline int do_h_encaps_red_v4(
    struct xdp_md *ctx,
    struct ethhdr *eth,
    struct iphdr *iph,
    struct headend_entry *entry)
{
    if (entry->num_segments < 1 || entry->num_segments > MAX_SEGMENTS) {
        DEBUG_PRINT("H.Encaps.Red.v4: Invalid segment count %d\n", entry->num_segments);
        return XDP_DROP;
    }

    struct ethhdr saved_eth;
    __builtin_memcpy(&saved_eth, eth, sizeof(struct ethhdr));
    __u16 inner_total_len = bpf_ntohs(iph->tot_len);

    return do_h_encaps_red_core(ctx, &saved_eth, entry, IPPROTO_IPIP, inner_total_len);
}

static __noinline int process_headend_v4(
    struct xdp_md *ctx,
    struct ethhdr *eth,
    struct iphdr *iph)
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
        return do_h_encaps_v4(ctx, eth, iph, entry);
    case SRV6_HEADEND_BEHAVIOR_H_ENCAPS_RED:
        DEBUG_PRINT("Headend.v4: Performing H.Encaps.Red\n");
        return do_h_encaps_red_v4(ctx, eth, iph, entry);
    case SRV6_HEADEND_BEHAVIOR_H_M_GTP4_D:
        DEBUG_PRINT("Headend.v4: Performing H.M.GTP4.D\n");
        return do_h_m_gtp4_d(ctx, eth, iph, entry);
    default:
        return XDP_PASS;
    }
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

// H.Encaps.Red for IPv6 (RFC 8986 Section 5.1.1)
static __always_inline int do_h_encaps_red_v6(
    struct xdp_md *ctx,
    struct ethhdr *eth,
    struct ipv6hdr *inner_ip6h,
    struct headend_entry *entry)
{
    if (entry->num_segments < 1 || entry->num_segments > MAX_SEGMENTS) {
        DEBUG_PRINT("H.Encaps.Red.v6: Invalid segment count %d\n", entry->num_segments);
        return XDP_DROP;
    }

    struct ethhdr saved_eth;
    __builtin_memcpy(&saved_eth, eth, sizeof(struct ethhdr));
    __u16 inner_total_len = 40 + bpf_ntohs(inner_ip6h->payload_len);

    return do_h_encaps_red_core(ctx, &saved_eth, entry, IPPROTO_IPV6, inner_total_len);
}

// H.Insert for IPv6 (RFC 8986 Section 4.1)
static __always_inline int do_h_insert_v6(
    struct xdp_md *ctx,
    struct ethhdr *eth,
    struct ipv6hdr *ip6h,
    struct headend_entry *entry)
{
    if (entry->num_segments < 1 || entry->num_segments > MAX_SEGMENTS - 1) {
        DEBUG_PRINT("H.Insert.v6: Invalid segment count %d\n", entry->num_segments);
        return XDP_DROP;
    }

    struct ethhdr saved_eth;
    __builtin_memcpy(&saved_eth, eth, sizeof(struct ethhdr));
    struct ipv6hdr saved_ip6h;
    __builtin_memcpy(&saved_ip6h, ip6h, sizeof(struct ipv6hdr));

    return do_h_insert_core(ctx, &saved_eth, &saved_ip6h, entry);
}

// H.Insert.Red for IPv6 (RFC 8986 Section 4.1 + Reduced)
static __always_inline int do_h_insert_red_v6(
    struct xdp_md *ctx,
    struct ethhdr *eth,
    struct ipv6hdr *ip6h,
    struct headend_entry *entry)
{
    if (entry->num_segments < 1 || entry->num_segments > MAX_SEGMENTS) {
        DEBUG_PRINT("H.Insert.Red.v6: Invalid segment count %d\n", entry->num_segments);
        return XDP_DROP;
    }

    struct ethhdr saved_eth;
    __builtin_memcpy(&saved_eth, eth, sizeof(struct ethhdr));
    struct ipv6hdr saved_ip6h;
    __builtin_memcpy(&saved_ip6h, ip6h, sizeof(struct ipv6hdr));

    return do_h_insert_red_core(ctx, &saved_eth, &saved_ip6h, entry);
}

static __noinline int process_headend_v6(
    struct xdp_md *ctx,
    struct ethhdr *eth,
    struct ipv6hdr *ip6h)
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
        return do_h_encaps_v6(ctx, eth, ip6h, entry);
    case SRV6_HEADEND_BEHAVIOR_H_ENCAPS_RED:
        DEBUG_PRINT("Headend.v6: Performing H.Encaps.Red\n");
        return do_h_encaps_red_v6(ctx, eth, ip6h, entry);
    case SRV6_HEADEND_BEHAVIOR_H_INSERT:
        DEBUG_PRINT("Headend.v6: Performing H.Insert\n");
        return do_h_insert_v6(ctx, eth, ip6h, entry);
    case SRV6_HEADEND_BEHAVIOR_H_INSERT_RED:
        DEBUG_PRINT("Headend.v6: Performing H.Insert.Red\n");
        return do_h_insert_red_v6(ctx, eth, ip6h, entry);
    default:
        return XDP_PASS;
    }
}

// No-SRH decap for Reduced SRH single-segment packets.
// DA lookup + decap in a separate __noinline to isolate verifier state.
static __noinline int process_srv6_decap_nosrh(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    void *unused)
{
    __u8 nh = ip6h->nexthdr;
    if (nh != IPPROTO_IPIP && nh != IPPROTO_IPV6 && nh != IPPROTO_ETHERNET)
        return XDP_PASS;

    struct lpm_key_v6 key = { .prefixlen = 128 };
    __builtin_memcpy(key.addr, &ip6h->daddr, IPV6_ADDR_LEN);
    struct sid_function_entry *entry = bpf_map_lookup_elem(&sid_function_map, &key);
    if (!entry)
        return XDP_PASS;

    switch (entry->action) {
    case SRV6_LOCAL_ACTION_END_DX4:
    case SRV6_LOCAL_ACTION_END_DT4:
        if (srv6_decap_nosrh(ctx, IPPROTO_IPIP, nh) != 0) return XDP_DROP;
        goto fib_v4;
    case SRV6_LOCAL_ACTION_END_DX6:
    case SRV6_LOCAL_ACTION_END_DT6:
        if (srv6_decap_nosrh(ctx, IPPROTO_IPV6, nh) != 0) return XDP_DROP;
        goto fib_v6;
    case SRV6_LOCAL_ACTION_END_DT46:
        if (nh == IPPROTO_IPIP) {
            if (srv6_decap_nosrh(ctx, IPPROTO_IPIP, nh) != 0) return XDP_DROP;
            goto fib_v4;
        }
        if (nh == IPPROTO_IPV6) {
            if (srv6_decap_nosrh(ctx, IPPROTO_IPV6, nh) != 0) return XDP_DROP;
            goto fib_v6;
        }
        return XDP_DROP;
    case SRV6_LOCAL_ACTION_END_DX2: {
        __u32 oif;
        __builtin_memcpy(&oif, entry->nexthop, sizeof(__u32));
        if (oif == 0) return XDP_DROP;
        if (srv6_decap_l2_nosrh(ctx, nh) != 0) return XDP_DROP;
        STATS_INC(STATS_SRV6_END, 0);
        return bpf_redirect(oif, 0);
    }
    case SRV6_LOCAL_ACTION_END_DT2: {
        if (nh != IPPROTO_ETHERNET) return XDP_PASS;
        struct bd_peer_reverse_key rev_key = { .bd_id = entry->bd_id };
        __builtin_memcpy(rev_key.src_addr, &ip6h->saddr, IPV6_ADDR_LEN);
        struct bd_peer_reverse_val *rev = bpf_map_lookup_elem(&bd_peer_reverse_map, &rev_key);
        if (srv6_decap_l2_nosrh(ctx, nh) != 0) return XDP_DROP;
        STATS_INC(STATS_SRV6_END, 0);
        void *d2 = (void *)(long)ctx->data;
        void *d2e = (void *)(long)ctx->data_end;
        struct ethhdr *ie = d2;
        if ((void *)(ie + 1) > d2e) return XDP_DROP;
        if (entry->bd_id != 0 && !(ie->h_source[0] & 0x01) && rev) {
            struct fdb_key lk = { .bd_id = entry->bd_id };
            __builtin_memcpy(lk.mac, ie->h_source, ETH_ALEN);
            struct fdb_entry lv = { .is_remote = 1, .peer_index = rev->index, .bd_id = entry->bd_id };
            bpf_map_update_elem(&fdb_map, &lk, &lv, BPF_ANY);
        }
        struct fdb_key dk = { .bd_id = entry->bd_id };
        __builtin_memcpy(dk.mac, ie->h_dest, ETH_ALEN);
        struct fdb_entry *fdb = bpf_map_lookup_elem(&fdb_map, &dk);
        if (!fdb || fdb->is_remote) {
            if (entry->bridge_ifindex > 0)
                return bpf_redirect(entry->bridge_ifindex, 0);
            return XDP_PASS;
        }
        return bpf_redirect(fdb->oif, 0);
    }
    default:
        return XDP_PASS;
    }

fib_v4: {
    void *d = (void *)(long)ctx->data;
    void *de = (void *)(long)ctx->data_end;
    struct ethhdr *e = d;
    if ((void *)(e + 1) > de) return XDP_DROP;
    struct iphdr *iph = (void *)(e + 1);
    if ((void *)(iph + 1) > de) return XDP_DROP;
    e->h_proto = bpf_htons(ETH_P_IP);
    STATS_INC(STATS_SRV6_END, 0);
    __u32 fi = entry->vrf_ifindex ? entry->vrf_ifindex : ctx->ingress_ifindex;
    int a = srv6_fib_redirect_v4(ctx, iph, e, fi);
    return (a == XDP_PASS) ? XDP_DROP : a;
}
fib_v6: {
    void *d = (void *)(long)ctx->data;
    void *de = (void *)(long)ctx->data_end;
    struct ethhdr *e = d;
    if ((void *)(e + 1) > de) return XDP_DROP;
    struct ipv6hdr *inner = (void *)(e + 1);
    if ((void *)(inner + 1) > de) return XDP_DROP;
    e->h_proto = bpf_htons(ETH_P_IPV6);
    STATS_INC(STATS_SRV6_END, 0);
    __u32 fi = entry->vrf_ifindex ? entry->vrf_ifindex : ctx->ingress_ifindex;
    int a = srv6_fib_redirect(ctx, inner, e, fi);
    return (a == XDP_PASS) ? XDP_DROP : a;
}
}

static __always_inline int process_srv6_localsid(
    struct xdp_md *ctx,
    struct ethhdr *eth,
    struct ipv6hdr *ip6h,
    void *data_end)
{
    if (ip6h->nexthdr != IPPROTO_ROUTING)
        return XDP_PASS;

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
    case SRV6_LOCAL_ACTION_END_B6:
        return process_end_b6_insert(ctx, ip6h, srh, entry);
    case SRV6_LOCAL_ACTION_END_B6_ENCAPS:
        return process_end_b6_encaps(ctx, ip6h, srh, entry);
    case SRV6_LOCAL_ACTION_END_M_GTP4_E:
        return process_end_m_gtp4_e(ctx, ip6h, srh, entry);
    case SRV6_LOCAL_ACTION_END_M_GTP6_D:
        return process_end_m_gtp6_d(ctx, ip6h, srh, entry);
    case SRV6_LOCAL_ACTION_END_M_GTP6_D_DI:
        return process_end_m_gtp6_d_di(ctx, ip6h, srh, entry);
    case SRV6_LOCAL_ACTION_END_M_GTP6_E:
        return process_end_m_gtp6_e(ctx, ip6h, srh, entry);
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

// L3 processing: SRv6 localsid -> no-SRH decap -> headend
// Replaces the former DO_L3_PROCESS macro. __noinline creates a BPF subprogram
// boundary so pointer re-derivation after bpf_xdp_adjust_head is self-contained.
static __noinline int process_l3(struct xdp_md *ctx, __u16 l3_offset, __u16 proto)
{
    if (proto == bpf_htons(ETH_P_IPV6)) {
        void *data = (void *)(long)ctx->data;
        void *data_end = (void *)(long)ctx->data_end;
        struct ethhdr *eth = data;
        if ((void *)(eth + 1) > data_end) return XDP_PASS;
        struct ipv6hdr *ip6h = (struct ipv6hdr *)(data + l3_offset);
        if ((void *)(ip6h + 1) > data_end) return XDP_PASS;

        int action = process_srv6_localsid(ctx, eth, ip6h, data_end);
        if (action != XDP_PASS) return action;

        // Re-derive pointers after localsid (bpf_xdp_adjust_head invalidates)
        data = (void *)(long)ctx->data;
        data_end = (void *)(long)ctx->data_end;
        eth = data;
        if ((void *)(eth + 1) > data_end) return XDP_PASS;
        ip6h = (struct ipv6hdr *)(data + l3_offset);
        if ((void *)(ip6h + 1) > data_end) return XDP_PASS;

        // No-SRH decap for Reduced SRH single-segment
        action = process_srv6_decap_nosrh(ctx, ip6h, NULL);
        if (action != XDP_PASS) return action;

        // Re-derive after decap
        data = (void *)(long)ctx->data;
        data_end = (void *)(long)ctx->data_end;
        eth = data;
        if ((void *)(eth + 1) > data_end) return XDP_PASS;
        ip6h = (struct ipv6hdr *)(data + l3_offset);
        if ((void *)(ip6h + 1) > data_end) return XDP_PASS;

        return process_headend_v6(ctx, eth, ip6h);
    }

    if (proto == bpf_htons(ETH_P_IP)) {
        void *data = (void *)(long)ctx->data;
        void *data_end = (void *)(long)ctx->data_end;
        struct ethhdr *eth = data;
        if ((void *)(eth + 1) > data_end) return XDP_PASS;
        struct iphdr *iph = (struct iphdr *)(data + l3_offset);
        if ((void *)(iph + 1) > data_end) return XDP_PASS;

        return process_headend_v4(ctx, eth, iph);
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

        struct headend_l2_key l2_key = { .ifindex = ctx->ingress_ifindex, .vlan_id = vlan_id };
        struct headend_entry *l2_entry = bpf_map_lookup_elem(&headend_l2_map, &l2_key);
        if (headend_should_encaps_l2_any(l2_entry)) {
            int bd_action = process_bd_forwarding(ctx, l2_entry, vlan_id, pkt_len);
            if (bd_action >= 0) {
                action = bd_action;
                goto out;
            }
            // bd_id == 0: no Bridge Domain, direct H.Encaps.L2 for all traffic
            if (l2_entry->mode == SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2_RED)
                action = do_h_encaps_l2_red(ctx, l2_entry, (__u16)pkt_len);
            else
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
                action = process_l3(ctx, 22, proto2);  /* eth(14) + 2*vlan(4) */
                goto out;
            } else {
                action = process_l3(ctx, 18, inner_proto);  /* eth(14) + vlan(4) */
                goto out;
            }
        }
        goto out;
    }

    // ========== Non-VLAN packets ==========
    {
        struct headend_l2_key l2_key = { .ifindex = ctx->ingress_ifindex, .vlan_id = 0 };
        struct headend_entry *l2_entry = bpf_map_lookup_elem(&headend_l2_map, &l2_key);
        if (headend_should_encaps_l2_any(l2_entry)) {
            int bd_action = process_bd_forwarding(ctx, l2_entry, 0, pkt_len);
            if (bd_action >= 0) {
                action = bd_action;
                goto out;
            }
            // bd_id == 0: no Bridge Domain, direct H.Encaps.L2 for all traffic
            if (l2_entry->mode == SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2_RED)
                action = do_h_encaps_l2_red(ctx, l2_entry, (__u16)pkt_len);
            else
                action = do_h_encaps_l2(ctx, l2_entry, (__u16)pkt_len);
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
