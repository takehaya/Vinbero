#ifndef TC_BUM_H
#define TC_BUM_H

#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "xdp_prog.h"
#include "xdp_map.h"
#include "srv6.h"
#include "srv6_headend.h"
#include "srv6_headend_utils.h"
#include "bum_meta.h"

// Magic value in skb->cb[0] to identify clone-to-self encap requests.
// Reuses BUM_META_MARKER so both XDP meta and TC cb[] use the same sentinel.
#define TC_CB_ENCAP_MAGIC BUM_META_MARKER

// TC FIB lookup for IPv6 and update Ethernet header
static __always_inline int tc_srv6_fib_lookup_and_update(
    struct __sk_buff *skb,
    struct ipv6hdr *ip6h,
    struct ethhdr *eth,
    __u32 *out_ifindex)
{
    struct bpf_fib_lookup fib_params = {};
    fib_params.family = AF_INET6;
    fib_params.ifindex = skb->ifindex;

    __builtin_memcpy(fib_params.ipv6_src, &ip6h->saddr, sizeof(fib_params.ipv6_src));
    __builtin_memcpy(fib_params.ipv6_dst, &ip6h->daddr, sizeof(fib_params.ipv6_dst));

    int ret = bpf_fib_lookup(skb, &fib_params, sizeof(fib_params), 0);
    if (ret != BPF_FIB_LKUP_RET_SUCCESS)
        return -1;

    __builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
    __builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
    *out_ifindex = fib_params.ifindex;
    return 0;
}

// Mode 2: Encap a single clone for one PE, then redirect.
// Called when cb[0] == TC_CB_ENCAP_MAGIC. The clone is consumed (redirected).
// Uses bpf_skb_change_head (no skb->protocol restriction, unlike bpf_skb_adjust_room).
//
// VLAN materialization:
// Generic XDP on veth converts xdp_buff→skb internally, and during that
// conversion the kernel unconditionally moves the VLAN tag from packet data
// to skb->vlan_tci (HW VLAN acceleration). ethtool -K rxvlan off does NOT
// prevent this — it only controls NIC driver-level offload, not the generic
// XDP conversion path.
//
// As a result, by the time TC ingress runs, packet data is already untagged.
// If we encapsulate it as-is, the decap side (End.DT2) delivers an untagged
// frame, breaking the return path (headend_l2_map keyed on vlan_id won't match).
//
// Fix: allocate 4 extra bytes in bpf_skb_change_head, shift the inner
// dst+src MAC left, and insert 802.1Q TPID+TCI so the inner frame is tagged.
static __noinline int tc_do_single_pe_encap(
    struct __sk_buff *skb,
    __u32 cb_bd_id,
    __u32 cb_pe_index)
{
    __u16 vlan_id = (__u16)skb->cb[3];

    struct bd_peer_key pk = { .bd_id = (__u16)cb_bd_id, .index = (__u16)cb_pe_index };
    struct headend_entry *entry = bpf_map_lookup_elem(&bd_peer_map, &pk);
    if (!entry || entry->num_segments < 1 || entry->num_segments > MAX_SEGMENTS)
        return TC_ACT_SHOT;

    int srh_len = 8 + (16 * entry->num_segments);
    int new_headers_len = (int)sizeof(struct ethhdr) + (int)sizeof(struct ipv6hdr) + srh_len;

    // Pop HW VLAN if present (generic XDP moves VLAN tag to skb->vlan_tci)
    if (skb->vlan_present)
        bpf_skb_vlan_pop(skb);

    // Allocate extra 4 bytes for VLAN tag materialization in inner frame
    bool needs_vlan = (vlan_id > 0);
    int vlan_extra = needs_vlan ? 4 : 0;

    // l2_frame_len = untagged frame + VLAN tag bytes (for outer IPv6 payload_len)
    __u16 l2_frame_len = (__u16)(skb->len) + (__u16)vlan_extra;

    if (bpf_skb_change_head(skb, new_headers_len + vlan_extra, 0)) {
        DEBUG_PRINT("TC encap: bpf_skb_change_head failed\n");
        return TC_ACT_SHOT;
    }

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Outer Ethernet
    struct ethhdr *new_eth = data;
    if ((void *)(new_eth + 1) > data_end)
        return TC_ACT_SHOT;

    __builtin_memset(new_eth->h_dest, 0, ETH_ALEN);
    __builtin_memset(new_eth->h_source, 0, ETH_ALEN);
    new_eth->h_proto = bpf_htons(ETH_P_IPV6);

    // Outer IPv6
    struct ipv6hdr *outer_ip6h = (struct ipv6hdr *)(new_eth + 1);
    if ((void *)(outer_ip6h + 1) > data_end)
        return TC_ACT_SHOT;

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

    // SRH
    struct ipv6_sr_hdr *srh = (struct ipv6_sr_hdr *)(outer_ip6h + 1);
    if ((void *)srh + 8 > data_end)
        return TC_ACT_SHOT;
    if ((void *)srh + 8 + (16 * entry->num_segments) > data_end)
        return TC_ACT_SHOT;

    srh->nexthdr = IPPROTO_ETHERNET;
    srh->hdrlen = (srh_len >> 3) - 1;
    srh->type = IPV6_SRCRT_TYPE_4;
    srh->segments_left = entry->num_segments - 1;
    srh->first_segment = entry->num_segments - 1;
    srh->flags = 0;
    srh->tag = 0;

    void *srh_segments = (void *)srh + 8;
    if (copy_segments_to_srh(srh_segments, data_end, entry->segments, entry->num_segments) != 0)
        return TC_ACT_SHOT;

    // FIB lookup for next-hop MAC (must use direct pointers before store_bytes)
    __u32 ifindex;
    if (tc_srv6_fib_lookup_and_update(skb, outer_ip6h, new_eth, &ifindex) != 0) {
        DEBUG_PRINT("TC encap: FIB lookup failed\n");
        return TC_ACT_SHOT;
    }

    // Materialize VLAN tag in inner L2 frame.
    // After bpf_skb_change_head(new_headers_len + 4), packet layout is:
    //   [outer headers (N bytes)][4-byte gap][dst MAC][src MAC][ethertype][payload]
    // We shift dst+src MAC left by 4, then insert 802.1Q TPID+TCI:
    //   [outer headers (N bytes)][dst MAC][src MAC][0x8100][TCI][ethertype][payload]
    if (needs_vlan) {
        int inner_off = new_headers_len;
        __u8 mac_buf[12];
        if (bpf_skb_load_bytes(skb, inner_off + 4, mac_buf, 12))
            return TC_ACT_SHOT;
        if (bpf_skb_store_bytes(skb, inner_off, mac_buf, 12, 0))
            return TC_ACT_SHOT;
        __u16 vlan_tag[2];
        vlan_tag[0] = bpf_htons(ETH_P_8021Q);
        vlan_tag[1] = bpf_htons(vlan_id);
        if (bpf_skb_store_bytes(skb, inner_off + 12, vlan_tag, 4, 0))
            return TC_ACT_SHOT;
    }

    DEBUG_PRINT("TC encap: redirect to ifindex=%d vlan=%d\n", ifindex, vlan_id);
    return bpf_redirect(ifindex, 0);
}

// Mode 1: Dispatch clones to self for each remote PE in the BD.
// Each clone re-enters TC ingress with cb[] set, triggering Mode 2.
// The original frame continues to bridge via TC_ACT_OK.
static __noinline int tc_dispatch_bum_clones(
    struct __sk_buff *skb,
    __u16 vlan_id)
{
    struct headend_l2_key l2_key = {
        .ifindex = skb->ifindex,
        .vlan_id = vlan_id,
    };
    struct headend_entry *l2 = bpf_map_lookup_elem(&headend_l2_map, &l2_key);
    if (!headend_should_encaps_l2(l2) || l2->bd_id == 0)
        return TC_ACT_OK;

    __u16 bd_id = l2->bd_id;
    DEBUG_PRINT("TC dispatch: bd_id=%d\n", bd_id);

    for (int i = 0; i < MAX_BUM_NEXTHOPS; i++) {
        struct bd_peer_key key = { .bd_id = bd_id, .index = i };
        struct headend_entry *peer = bpf_map_lookup_elem(&bd_peer_map, &key);
        if (!peer)
            continue; // Slot may be empty due to deletion; keep scanning

        // Tag this clone for Mode 2 processing
        skb->cb[0] = TC_CB_ENCAP_MAGIC;
        skb->cb[1] = bd_id;
        skb->cb[2] = i;
        skb->cb[3] = vlan_id;
        long clone_ret = bpf_clone_redirect(skb, skb->ifindex, BPF_F_INGRESS);
        (void)clone_ret;
        DEBUG_PRINT("TC dispatch: clone pe=%d ret=%ld\n", i, clone_ret);
    }

    // Clear cb so the original packet doesn't trigger Mode 2
    skb->cb[0] = 0;

    // Original frame continues to bridge for local flood
    return TC_ACT_OK;
}

#endif // TC_BUM_H
