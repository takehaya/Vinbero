#ifndef TC_BUM_H
#define TC_BUM_H

#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "core/xdp_prog.h"
#include "core/xdp_map.h"
#include "core/srv6.h"
#include "core/srv6_fib.h"
#include "core/esi.h"
#include "core/xdp_stats.h"
#include "headend/srv6_headend.h"
#include "headend/srv6_headend_utils.h"
#include "l2vpn/bum_meta.h"
#include "l2vpn/bum_xdp.h"

// bd_id -> the flood slots that hold a bd_peer entry, bit i = slot i. The
// control plane sets a bit before it writes the slot's peer and clears it
// after the peer is gone (MapOperations), so the bits cover every flood
// peer; a bit whose peer is missing costs one lookup. The clone loop visits
// only these slots, so a BD with few peers does not pay for the empty ones.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1 << 16);
    __type(key, __u32);
    __type(value, __u32);
} bd_flood_slots_map SEC(".maps");

_Static_assert(MAX_BUM_NEXTHOPS <= 32, "bd_flood_slots_map holds a 32-bit slot set");

// Magic value in skb->cb[0] to identify clone-to-self encap requests.
// Reuses BUM_META_MARKER so both XDP meta and TC cb[] use the same sentinel.
#define TC_CB_ENCAP_MAGIC BUM_META_MARKER

// Materialize 802.1Q VLAN tag in the inner L2 frame after encapsulation.
// Generic XDP on veth moves VLAN from packet data to skb->vlan_tci,
// so by TC time the inner frame is untagged. This re-inserts the tag.
//
// Layout after bpf_skb_change_head(new_headers_len + 4):
//   [outer headers][4-byte gap][dst MAC][src MAC][ethertype][payload]
// After materialization:
//   [outer headers][dst MAC][src MAC][0x8100][TCI][ethertype][payload]
static __always_inline int tc_materialize_vlan(
    struct __sk_buff *skb,
    int inner_off,
    __u16 vlan_id)
{
    __u8 mac_buf[12];
    if (bpf_skb_load_bytes(skb, inner_off + 4, mac_buf, 12))
        return -1;
    if (bpf_skb_store_bytes(skb, inner_off, mac_buf, 12, 0))
        return -1;
    __u16 vlan_tag[2];
    vlan_tag[0] = bpf_htons(ETH_P_8021Q);
    vlan_tag[1] = bpf_htons(vlan_id);
    if (bpf_skb_store_bytes(skb, inner_off + 12, vlan_tag, 4, 0))
        return -1;
    return 0;
}

// TC FIB lookup for IPv6 and update Ethernet header
static __always_inline int tc_srv6_fib_lookup_and_update(
    struct __sk_buff *skb,
    struct ipv6hdr *ip6h,
    struct ethhdr *eth,
    __u32 *out_ifindex)
{
    struct bpf_fib_lookup fib_params = {};
    int ret = srv6_fib_lookup_v6_params(skb, &fib_params, &ip6h->saddr, &ip6h->daddr, skb->ifindex, 0);
    if (ret != BPF_FIB_LKUP_RET_SUCCESS)
        return -1;

    __builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
    __builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
    *out_ifindex = fib_params.ifindex;
    return 0;
}

// Unified Mode 2 encap: single clone for one PE, then redirect.
// Handles both full SRH (reduced=false) and reduced SRH (reduced=true).
// Uses bpf_skb_change_head (no skb->protocol restriction).
//
// VLAN materialization: Generic XDP on veth converts xdp_buff→skb internally,
// moving VLAN tag from packet data to skb->vlan_tci unconditionally.
// We re-insert the tag so the decap side (End.DT2) delivers a tagged frame.
static __noinline int tc_do_single_pe_encap_impl(
    struct __sk_buff *skb,
    __u32 cb_bd_id,
    __u32 cb_pe_index,
    bool reduced)
{
    __u16 vlan_id = (__u16)skb->cb[3];

    struct bd_peer_key pk = { .bd_id = (__u16)cb_bd_id, .index = (__u16)cb_pe_index };
    struct headend_entry *entry = bpf_map_lookup_elem(&bd_peer_map, &pk);
    if (!entry || entry->num_segments < 1 || entry->num_segments > MAX_SEGMENTS)
        return TC_ACT_SHOT;

    // Pop HW VLAN if present (generic XDP moves VLAN tag to skb->vlan_tci)
    if (skb->vlan_present)
        bpf_skb_vlan_pop(skb);

    bool needs_vlan = (vlan_id > 0);
    int vlan_extra = needs_vlan ? 4 : 0;
    __u16 l2_frame_len = (__u16)(skb->len) + (__u16)vlan_extra;

    // Compute SRH size
    bool no_srh = reduced && (entry->num_segments == 1);
    int srh_len = 0;
    int reduced_count = 0;

    if (!no_srh) {
        if (reduced) {
            reduced_count = entry->num_segments - 1;
            if (reduced_count < 1 || reduced_count > MAX_SEGMENTS - 1)
                return TC_ACT_SHOT;
            srh_len = 8 + (16 * reduced_count);
        } else {
            srh_len = 8 + (16 * entry->num_segments);
        }
    }

    int new_headers_len = (int)sizeof(struct ethhdr) + (int)sizeof(struct ipv6hdr) + srh_len;

    if (bpf_skb_change_head(skb, new_headers_len + vlan_extra, 0))
        return TC_ACT_SHOT;

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

    if (no_srh) {
        build_outer_ipv6(outer_ip6h, IPPROTO_ETHERNET, l2_frame_len,
                         entry->src_addr, &entry->segments[0],
                         0 /* L2 dispatch does not hash; label 0 */);
    } else {
        build_outer_ipv6(outer_ip6h, IPPROTO_ROUTING, srh_len + l2_frame_len,
                         entry->src_addr, &entry->segments[0],
                         0 /* L2 dispatch does not hash; label 0 */);

        // SRH
        struct ipv6_sr_hdr *srh = (struct ipv6_sr_hdr *)(outer_ip6h + 1);
        if ((void *)srh + 8 > data_end)
            return TC_ACT_SHOT;
        if ((void *)srh + 8 + srh_len - 8 > data_end)
            return TC_ACT_SHOT;

        srh->nexthdr = IPPROTO_ETHERNET;
        srh->hdrlen = (srh_len >> 3) - 1;
        srh->type = IPV6_SRCRT_TYPE_4;
        srh->flags = 0;
        srh->tag = 0;

        if (reduced) {
            // TODO: should be reduced_count per RFC 8986, but BPF verifier rejects it
            // in TC context. XDP path uses the correct value.
            srh->segments_left = reduced_count - 1;
            srh->first_segment = reduced_count - 1;

            void *srh_segments = (void *)srh + 8;
            if (copy_segments_to_srh_reduced(srh_segments, data_end, entry->segments, entry->num_segments) != 0)
                return TC_ACT_SHOT;
        } else {
            srh->segments_left = entry->num_segments - 1;
            srh->first_segment = entry->num_segments - 1;

            void *srh_segments = (void *)srh + 8;
            if (copy_segments_to_srh(srh_segments, data_end, entry->segments, entry->num_segments) != 0)
                return TC_ACT_SHOT;
        }
    }

    // FIB lookup for next-hop MAC
    __u32 ifindex;
    if (tc_srv6_fib_lookup_and_update(skb, outer_ip6h, new_eth, &ifindex) != 0)
        return TC_ACT_SHOT;

    if (needs_vlan && tc_materialize_vlan(skb, new_headers_len, vlan_id) != 0)
        return TC_ACT_SHOT;

    return bpf_redirect(ifindex, 0);
}

static __noinline int tc_do_single_pe_encap(
    struct __sk_buff *skb, __u32 cb_bd_id, __u32 cb_pe_index)
{
    return tc_do_single_pe_encap_impl(skb, cb_bd_id, cb_pe_index, false);
}

static __noinline int tc_do_single_pe_encap_red(
    struct __sk_buff *skb, __u32 cb_bd_id, __u32 cb_pe_index)
{
    return tc_do_single_pe_encap_impl(skb, cb_bd_id, cb_pe_index, true);
}

// One flood slot of tc_dispatch_bum_clones: clone the frame to the slot's
// peer unless it is missing, flood_exclude, or on the source AC's Ethernet
// Segment (src_ext, NULL when the AC has none). A global function on
// purpose: the verifier checks it once, not once per slot of the loop.
// The caller holds no packet pointer across the clone.
__noinline int tc_bum_clone_slot(struct __sk_buff *skb, __u32 bd_id, __u32 index, __u32 vlan_id,
                                 const struct headend_l2_ext_val *src_ext)
{
    if (!skb)
        return 0;
    struct bd_peer_key key = { .bd_id = (__u16)bd_id, .index = (__u16)index };
    struct headend_entry *peer = bpf_map_lookup_elem(&bd_peer_map, &key);
    if (!peer)
        return 0; // Slot may be empty due to deletion

    // RT2 installs the unicast End.DT2U peer with flood_exclude set: it is a
    // known-unicast forwarding target, not a BUM flood destination. The RT3
    // End.DT2M peer (and manually-created peers) leave it 0 and are flooded.
    if (peer->flood_exclude)
        return 0;

    if (src_ext) {
        struct bd_peer_l2_ext_key ext_key = { .bd_id = (__u16)bd_id, .index = (__u16)index };
        struct bd_peer_l2_ext_val *peer_ext = bpf_map_lookup_elem(&bd_peer_l2_ext_map, &ext_key);
        if (peer_ext && esi_equal(peer_ext->esi, src_ext->esi)) {
            STATS_INC(STATS_SPLIT_HORIZON_TX, skb->len);
            DEBUG_PRINT("TC dispatch: split-horizon skip peer=%d\n", index);
            return 0;
        }
    }

    skb->cb[0] = TC_CB_ENCAP_MAGIC;
    skb->cb[1] = bd_id;
    skb->cb[2] = index;
    skb->cb[3] = vlan_id;
    long clone_ret = bpf_clone_redirect(skb, skb->ifindex, BPF_F_INGRESS);
    (void)clone_ret;
    DEBUG_PRINT("TC dispatch: clone pe=%d ret=%ld\n", index, clone_ret);
    return 0;
}

// Mode 1: clone-to-self, one clone per remote PE in the BD. RFC 9252
// split-horizon: if the source AC's ESI matches a peer's ESI, the peer is on
// the same Ethernet Segment and would re-flood to the shared CE — skip it.
static __noinline int tc_dispatch_bum_clones(
    struct __sk_buff *skb,
    __u16 vlan_id)
{
    struct headend_l2_key l2_key = {
        .ifindex = skb->ifindex,
        .vlan_id = vlan_id,
    };
    struct headend_entry *l2 = bpf_map_lookup_elem(&headend_l2_map, &l2_key);
    if (!headend_should_encaps_l2_any(l2) || l2->bd_id == 0)
        return TC_ACT_OK;

    __u16 bd_id = l2->bd_id;
    DEBUG_PRINT("TC dispatch: bd_id=%d\n", bd_id);

    // An xdp-mode BD on the tc path. Counted here, on the frame XDP marked,
    // not in XDP: in generic XDP the clones below pass through the XDP
    // program again, and on an untagged AC they would be counted as well
    // (the stack has moved the tag of a tagged one out of the packet, so
    // they no longer match it).
    // The bytes are the frame's length on the wire, as XDP counts it: by
    // now the stack has moved a VLAN tag out of the packet.
    if (bum_bd_mode(bd_id) != BUM_MODE_TC)
        STATS_INC(STATS_BUM_XDP_FALLBACK, skb->len + (skb->vlan_present ? 4 : 0));

    // Resolve source AC's ESI once, out of the per-peer loop.
    struct headend_l2_ext_val *src_ext = bpf_map_lookup_elem(&headend_l2_ext_map, &l2_key);
    bool src_esi_set = src_ext && !esi_is_zero(src_ext->esi);

    __u32 bd_key = bd_id;
    __u32 *slotsp = bpf_map_lookup_elem(&bd_flood_slots_map, &bd_key);
    __u32 slots = slotsp ? *slotsp : 0;

    for (__u32 i = 0; i < MAX_BUM_NEXTHOPS; i++) {
        if (!(slots >> i))
            break;
        if (slots & (1u << i))
            tc_bum_clone_slot(skb, bd_id, i, vlan_id, src_esi_set ? src_ext : NULL);
    }

    // Clear cb so the original packet doesn't trigger Mode 2
    skb->cb[0] = 0;

    // Original frame continues to bridge for local flood
    return TC_ACT_OK;
}

#endif // TC_BUM_H
