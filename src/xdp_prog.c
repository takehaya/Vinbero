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
#include "srv6_encaps_red.h"
#include "srv6_insert.h"
#include "xdp_stats.h"
#include "xdpcap.h"
#include "srv6_endpoint.h"
#include "srv6_end_b6.h"
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
    default:
        return XDP_PASS;
    }
}

// Forward declarations for L2 encap functions (defined below, used by process_bd_forwarding)
static __noinline int do_h_encaps_l2(
    struct xdp_md *ctx,
    struct headend_entry *entry,
    __u16 l2_frame_len);

static __noinline int do_h_encaps_l2_red(
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

// H.Encaps.L2.Red single-segment: no SRH, just outer Eth + IPv6 + inner L2
static __always_inline int do_h_encaps_l2_red_1seg(
    struct xdp_md *ctx,
    struct headend_entry *entry,
    __u16 l2_frame_len)
{
    int new_headers_len = sizeof(struct ethhdr) + sizeof(struct ipv6hdr);

    if (bpf_xdp_adjust_head(ctx, -(new_headers_len)))
        return XDP_DROP;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *new_eth = data;
    CHECK_BOUND(new_eth, data_end, sizeof(*new_eth));

    struct ipv6hdr *outer_ip6h = (struct ipv6hdr *)(new_eth + 1);
    CHECK_BOUND(outer_ip6h, data_end, sizeof(*outer_ip6h));

    __builtin_memset(new_eth->h_dest, 0, ETH_ALEN);
    __builtin_memset(new_eth->h_source, 0, ETH_ALEN);
    new_eth->h_proto = bpf_htons(ETH_P_IPV6);

    outer_ip6h->version = 6;
    outer_ip6h->priority = 0;
    outer_ip6h->flow_lbl[0] = 0;
    outer_ip6h->flow_lbl[1] = 0;
    outer_ip6h->flow_lbl[2] = 0;
    outer_ip6h->payload_len = bpf_htons(l2_frame_len);
    outer_ip6h->nexthdr = IPPROTO_ETHERNET;
    outer_ip6h->hop_limit = 64;
    __builtin_memcpy(&outer_ip6h->saddr, entry->src_addr, sizeof(struct in6_addr));
    __builtin_memcpy(&outer_ip6h->daddr, &entry->segments[0], sizeof(struct in6_addr));

    __u32 ifindex;
    int fib_result = srv6_fib_lookup_and_update(ctx, outer_ip6h, new_eth, &ifindex, ctx->ingress_ifindex);

    switch (fib_result) {
    case FIB_RESULT_REDIRECT:
        return bpf_redirect(ifindex, 0);
    default:
        return XDP_DROP;
    }
}

// H.Encaps.L2.Red multi-segment: reduced SRH with N-1 entries
static __always_inline int do_h_encaps_l2_red_multi(
    struct xdp_md *ctx,
    struct headend_entry *entry,
    __u16 l2_frame_len)
{
    if (entry->num_segments < 2 || entry->num_segments > MAX_SEGMENTS)
        return XDP_DROP;

    // Use constant SRH sizes to help older kernel verifiers track bounds.
    // entry->num_segments is in [2, 10], so reduced_count is in [1, 9].
    __u8 reduced_count = entry->num_segments - 1;
    // Explicit re-check so verifier on kernel 6.1 knows reduced_count >= 1
    if (reduced_count < 1 || reduced_count > 9)
        return XDP_DROP;
    int srh_len = 8 + (16 * (int)reduced_count);
    int new_headers_len = (int)sizeof(struct ethhdr) + (int)sizeof(struct ipv6hdr) + srh_len;

    if (bpf_xdp_adjust_head(ctx, -(new_headers_len)))
        return XDP_DROP;

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
    srh->segments_left = reduced_count;
    srh->first_segment = reduced_count - 1;
    srh->flags = 0;
    srh->tag = 0;

    void *srh_segments = (void *)srh + 8;
    if (copy_segments_to_srh_reduced(srh_segments, data_end, entry->segments, entry->num_segments) != 0)
        return XDP_DROP;

    __u32 ifindex;
    int fib_result = srv6_fib_lookup_and_update(ctx, outer_ip6h, new_eth, &ifindex, ctx->ingress_ifindex);

    switch (fib_result) {
    case FIB_RESULT_REDIRECT:
        return bpf_redirect(ifindex, 0);
    default:
        return XDP_DROP;
    }
}

// H.Encaps.L2.Red dispatcher
static __noinline int do_h_encaps_l2_red(
    struct xdp_md *ctx,
    struct headend_entry *entry,
    __u16 l2_frame_len)
{
    if (entry->num_segments < 1 || entry->num_segments > MAX_SEGMENTS)
        return XDP_DROP;

    if (entry->num_segments == 1)
        return do_h_encaps_l2_red_1seg(ctx, entry, l2_frame_len);

    return do_h_encaps_l2_red_multi(ctx, entry, l2_frame_len);
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
            /* No-SRH decap for Reduced SRH single-segment */                   \
            action = process_srv6_decap_nosrh(ctx, _ip6h, NULL);               \
            if (action != XDP_PASS) goto out;                                   \
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
