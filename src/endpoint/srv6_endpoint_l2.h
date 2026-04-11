#ifndef SRV6_ENDPOINT_L2_H
#define SRV6_ENDPOINT_L2_H

#include "endpoint/srv6_endpoint_core.h"
#include "core/xdp_map.h"

// ========================================================================
// L2 Bridge Domain Endpoint Functions (End.DT2)
// ========================================================================

// Find peer_index by {bd_id, outer_src} via bd_peer_reverse_map.
// O(1) single hash lookup instead of iterating up to MAX_BUM_NEXTHOPS entries.
// Returns BD_PEER_INDEX_INVALID if not found.
static __always_inline __u16 find_peer_index_by_src(
    __u16 bd_id,
    struct in6_addr *outer_src)
{
    struct bd_peer_reverse_key rk = { .bd_id = bd_id };
    __builtin_memcpy(rk.src_addr, outer_src, sizeof(struct in6_addr));

    struct bd_peer_reverse_val *rv = bpf_map_lookup_elem(&bd_peer_reverse_map, &rk);
    if (!rv)
        return BD_PEER_INDEX_INVALID;
    return rv->index;
}

// ========================================================================
// Shared L2 FDB Helpers
// ========================================================================

// Learn inner source MAC as a remote FDB entry.
// Called after decap when the inner Ethernet header is accessible.
// Skips update if existing FDB entry already matches (avoids redundant map writes).
//
// Parameters:
//   inner_eth: pointer to inner Ethernet header (must be bounds-checked by caller)
//   bd_id:     Bridge Domain ID (must be non-zero)
//   peer_idx:  peer index from find_peer_index_by_src / bd_peer_reverse_map
static __always_inline void fdb_learn_remote_mac(
    struct ethhdr *inner_eth,
    __u16 bd_id,
    __u16 peer_idx)
{
    // Only learn unicast source MACs (bit 0 of first octet = multicast flag)
    if (inner_eth->h_source[0] & 0x01)
        return;

    struct fdb_key learn_key = { .bd_id = bd_id };
    __builtin_memcpy(learn_key.mac, inner_eth->h_source, ETH_ALEN);

    // Check if existing entry already matches — avoid redundant map write
    struct fdb_entry *existing = bpf_map_lookup_elem(&fdb_map, &learn_key);
    if (existing && existing->is_remote && existing->peer_index == peer_idx)
        return;

    struct fdb_entry learn_val = {
        .is_remote = 1,
        .peer_index = peer_idx,
        .bd_id = bd_id,
    };
    bpf_map_update_elem(&fdb_map, &learn_key, &learn_val, BPF_ANY);
    DEBUG_PRINT("FDB: learned remote MAC, bd_id=%d peer_index=%d\n", bd_id, peer_idx);
}

// FDB-based L2 forwarding decision after decapsulation.
// Looks up destination MAC in fdb_map and returns the appropriate XDP action.
//
// Returns:
//   bpf_redirect(oif)            on local FDB hit (fast path)
//   bpf_redirect(bridge_ifindex) on FDB miss or remote hit (when bridge configured)
//   XDP_PASS                     when no bridge configured
static __always_inline int fdb_forward_l2(
    struct xdp_md *ctx,
    struct ethhdr *inner_eth,
    __u16 bd_id,
    __u32 bridge_ifindex)
{
    struct fdb_key dk = { .bd_id = bd_id };
    __builtin_memcpy(dk.mac, inner_eth->h_dest, ETH_ALEN);

    struct fdb_entry *fdb = bpf_map_lookup_elem(&fdb_map, &dk);
    if (!fdb) {
        // FDB miss: redirect to bridge device for flooding.
        if (bridge_ifindex != 0) {
            DEBUG_PRINT("FDB: miss, redirect to bridge ifindex %d\n", bridge_ifindex);
            return bpf_redirect(bridge_ifindex, 0);
        }
        DEBUG_PRINT("FDB: miss, no bridge, passing to kernel\n");
        return XDP_PASS;
    }

    if (!fdb->is_remote) {
        // Local FDB hit: fast-path redirect
        DEBUG_PRINT("FDB: hit local, redirect to ifindex %d\n", fdb->oif);
        STATS_INC(STATS_SRV6_END, 0);
        return bpf_redirect(fdb->oif, 0);
    }

    // Remote FDB hit on receiving PE — routing loop or stale entry
    DEBUG_PRINT("FDB: hit remote on receiver, redirect to bridge\n");
    if (bridge_ifindex != 0)
        return bpf_redirect(bridge_ifindex, 0);
    return XDP_PASS;
}

// ========================================================================
// End.DT2 Implementations
// ========================================================================

// End.DT2: Decapsulation with L2 table lookup (FDB) + remote MAC learning
// RFC 8986 Section 4.11
// Strips outer headers (Eth + IPv6 + SRH), learns inner src MAC as remote,
// then looks up dst MAC in fdb_map for fast-path forwarding.
static __always_inline int process_end_dt2(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ipv6_sr_hdr *srh,
    struct sid_function_entry *entry,
    struct sid_aux_entry *aux,
    __u16 l3_offset)
{
    if (!aux) return XDP_DROP;

    // 1. SL must be 0
    if (srh->segments_left != 0) {
        DEBUG_PRINT("End.DT2: SL != 0, passing\n");
        return XDP_PASS;
    }

    // 2. nexthdr must be IPPROTO_ETHERNET
    if (srh->nexthdr != IPPROTO_ETHERNET) {
        DEBUG_PRINT("End.DT2: nexthdr is not Ethernet (%d)\n", srh->nexthdr);
        return XDP_DROP;
    }

    __u16 bd_id = aux->l2.bd_id;
    __u32 bridge_ifindex = aux->l2.bridge_ifindex;

    // 3. Save outer IPv6 source for remote MAC learning (before decap)
    struct in6_addr outer_src;
    __builtin_memcpy(&outer_src, &ip6h->saddr, sizeof(struct in6_addr));

    // 4. Strip outer headers (Eth + IPv6 + SRH)
    int strip_len = calc_decap_strip_len(srh, l3_offset);
    if (bpf_xdp_adjust_head(ctx, strip_len)) {
        DEBUG_PRINT("End.DT2: bpf_xdp_adjust_head failed\n");
        return XDP_DROP;
    }

    // 5. Re-fetch pointers after adjust_head
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *inner_eth = data;
    if ((void *)(inner_eth + 1) > data_end)
        return XDP_DROP;

    // 6. Remote MAC learning
    if (bd_id != 0) {
        __u16 peer_idx = find_peer_index_by_src(bd_id, &outer_src);
        if (peer_idx != BD_PEER_INDEX_INVALID)
            fdb_learn_remote_mac(inner_eth, bd_id, peer_idx);
    }

    // 7. FDB forwarding decision
    return fdb_forward_l2(ctx, inner_eth, bd_id, bridge_ifindex);
}

// End.DT2 for Reduced SRH (no-SRH) single-segment packets.
// Same semantics as process_end_dt2 but strips only Eth + IPv6 (no SRH).
static __always_inline int process_end_dt2_nosrh(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    __u8 nexthdr,
    struct sid_function_entry *entry,
    struct sid_aux_entry *aux,
    __u16 l3_offset)
{
    if (!aux) return XDP_DROP;

    // 1. nexthdr must be IPPROTO_ETHERNET
    if (nexthdr != IPPROTO_ETHERNET)
        return XDP_PASS;

    __u16 bd_id = aux->l2.bd_id;
    __u32 bridge_ifindex = aux->l2.bridge_ifindex;

    // 2. Resolve peer index BEFORE decap (ip6h->saddr is lost after adjust_head)
    __u16 peer_idx = BD_PEER_INDEX_INVALID;
    if (bd_id != 0)
        peer_idx = find_peer_index_by_src(bd_id, &ip6h->saddr);

    // 3. Strip outer Ethernet + IPv6 (no SRH to strip)
    if (srv6_decap_l2_nosrh(ctx, nexthdr, l3_offset) != 0)
        return XDP_DROP;

    // 4. Re-fetch inner Ethernet header after adjust_head
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *inner_eth = data;
    if ((void *)(inner_eth + 1) > data_end)
        return XDP_DROP;

    // 5. Remote MAC learning (if BD configured and peer was resolved)
    if (bd_id != 0 && peer_idx != BD_PEER_INDEX_INVALID)
        fdb_learn_remote_mac(inner_eth, bd_id, peer_idx);

    // 6. FDB forwarding decision
    return fdb_forward_l2(ctx, inner_eth, bd_id, bridge_ifindex);
}

#endif // SRV6_ENDPOINT_L2_H
