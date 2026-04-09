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

// End.DT2: Decapsulation with L2 table lookup (FDB) + remote MAC learning
// RFC 8986 Section 4.11
// Strips outer headers, learns inner src MAC as remote, then looks up
// dst MAC in fdb_map for fast-path forwarding.
// Unknown unicast (FDB miss) falls through to kernel bridge via XDP_PASS.
static __always_inline int process_end_dt2(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ipv6_sr_hdr *srh,
    struct sid_function_entry *entry)
{
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

    // 3. Save outer IPv6 source for remote MAC learning (before decap)
    struct in6_addr outer_src;
    __builtin_memcpy(&outer_src, &ip6h->saddr, sizeof(struct in6_addr));

    // 4. Strip outer headers (Eth + IPv6 + SRH)
    int strip_len = calc_decap_strip_len(srh);
    if (bpf_xdp_adjust_head(ctx, strip_len)) {
        DEBUG_PRINT("End.DT2: bpf_xdp_adjust_head failed\n");
        return XDP_DROP;
    }

    // 5. Re-fetch pointers after adjust_head
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *inner_eth = data;
    if ((void *)(inner_eth + 1) > data_end) {
        return XDP_DROP;
    }

    // 6. Remote MAC learning: learn inner src MAC as remote entry
    if (entry->bd_id != 0 && !(inner_eth->h_source[0] & 0x01)) {
        __u16 peer_idx = find_peer_index_by_src(entry->bd_id, &outer_src);
        if (peer_idx != BD_PEER_INDEX_INVALID) {
            struct fdb_key learn_key = { .bd_id = entry->bd_id };
            __builtin_memcpy(learn_key.mac, inner_eth->h_source, ETH_ALEN);

            struct fdb_entry *existing = bpf_map_lookup_elem(&fdb_map, &learn_key);
            if (!existing || !existing->is_remote ||
                existing->peer_index != peer_idx) {
                struct fdb_entry learn_val = {
                    .is_remote = 1,
                    .peer_index = peer_idx,
                    .bd_id = entry->bd_id,
                };
                bpf_map_update_elem(&fdb_map, &learn_key, &learn_val, BPF_ANY);
                DEBUG_PRINT("End.DT2: Learned remote MAC, peer_index=%d\n", peer_idx);
            }
        }
    }

    // 7. Build FDB lookup key for dst MAC (bd_id + MAC)
    struct fdb_key key = { .bd_id = entry->bd_id };
    __builtin_memcpy(key.mac, inner_eth->h_dest, ETH_ALEN);

    // 8. Lookup dst MAC in fdb_map
    struct fdb_entry *fdb = bpf_map_lookup_elem(&fdb_map, &key);
    if (!fdb) {
        // FDB miss: redirect to bridge device for flooding.
        // XDP_PASS would send to the uplink's kernel stack (not a bridge member),
        // so the decapped L2 frame would be dropped.
        if (entry->bridge_ifindex != 0) {
            DEBUG_PRINT("End.DT2: FDB miss, redirect to bridge ifindex %d\n", entry->bridge_ifindex);
            return bpf_redirect(entry->bridge_ifindex, 0);
        }
        DEBUG_PRINT("End.DT2: FDB miss, no bridge, passing to kernel\n");
        return XDP_PASS;
    }

    // 9. Known unicast: fast-path redirect (local entries only)
    if (!fdb->is_remote) {
        DEBUG_PRINT("End.DT2: FDB hit local, redirect to ifindex %d\n", fdb->oif);
        STATS_INC(STATS_SRV6_END, 0);
        return bpf_redirect(fdb->oif, 0);
    }

    // Remote FDB hit on receiving PE — should not happen in normal operation
    // (packet arrived from remote, dst is also remote = routing loop)
    DEBUG_PRINT("End.DT2: FDB hit remote, passing to kernel\n");
    return XDP_PASS;
}

#endif // SRV6_ENDPOINT_L2_H
