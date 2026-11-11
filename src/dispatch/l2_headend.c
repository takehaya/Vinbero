#include "core/fdb.h"

// L2 headend pipeline — BD forwarding and L2 encapsulation dispatch.
// Included from xdp_prog.c — not compiled standalone.
// Depends on headend/srv6_encaps_l2.h (must be included before this file).

// Look up the BD peer to encap towards, given the local L2 entry. Returns:
//   non-NULL  -> encap with this headend_entry (caller does the tail-call)
//   NULL      -> no BD encap was selected; *out_action carries the action
//                the caller should bubble up (-1 means "no BD; fall through
//                to the no-BD path", XDP_PASS means "leave to kernel").
//
// FDB src learning, broadcast/multicast BUM meta, and missing-FDB BUM meta
// (or, for an xdp-mode BD, the devmap flood and the local unicast redirect)
// are all handled here so the caller stays simple. Keeping the bpf_tail_call
// out of this helper is intentional and enforced as an invariant: any second
// lexical bpf_tail_call site into headend_l2_progs in the same translation
// unit causes the kernel to silently drop the redirected frame on the first
// callsite, even when that branch is dead code at runtime.
//
// Repro (kernel 6.x, observed 2026-05): two lexical bpf_tail_call sites in
// xdp_main.c targeting the same PROG_ARRAY (headend_l2_progs) cause the
// first site's XDP_REDIRECT (set by the target program's bpf_redirect()
// call) to be silently dropped. The xdp:xdp_redirect{_err,_map_err}
// tracepoints do not fire. Collapsing all callers to a single inline
// bpf_tail_call instruction in try_l2_headend below restores delivery.
// Root cause is not yet pinned down — verifier register-state merge / JIT
// dispatch / per-CPU bpf_redirect_info aliasing are all suspects.
static __always_inline struct headend_entry *try_bd_peer_lookup(
    struct xdp_md *ctx,
    struct headend_entry *l2_entry,
    __u16 vlan_id,
    int *out_action)
{
    if (l2_entry->bd_id == 0) {
        *out_action = -1;
        return NULL;
    }

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        *out_action = XDP_PASS;
        return NULL;
    }

    struct fdb_key key = { .bd_id = l2_entry->bd_id };
    // tc unless settings.l2 put this BD in xdp mode (see l2vpn/bum_xdp.h).
    __u8 bum_mode = bum_bd_mode(l2_entry->bd_id);

    __builtin_memcpy(key.mac, eth->h_source, ETH_ALEN);
    struct fdb_entry *existing = bpf_map_lookup_elem(&fdb_map, &key);
    if (!existing) {
        struct fdb_entry learn_val = {
            .oif = ctx->ingress_ifindex,
            .last_seen = bpf_ktime_get_ns(),
        };
        if (bpf_map_update_elem(&fdb_map, &key, &learn_val, BPF_NOEXIST) == 0 &&
            bum_mode == BUM_MODE_XDP)
            bum_fdb_event_emit(key.bd_id, eth->h_source, ctx->ingress_ifindex, FDB_EVENT_ADD);
    } else {
        union fdb_forward old = fdb_read_forward(existing);
        if (!old.is_static) {
            if (!old.is_remote && old.oif != ctx->ingress_ifindex) {
                union fdb_forward next = { .oif = ctx->ingress_ifindex };
                if (fdb_replace_forward(existing, old, next)) {
                    existing->last_seen = bpf_ktime_get_ns();
                    if (bum_mode == BUM_MODE_XDP)
                        bum_fdb_event_emit(key.bd_id, eth->h_source, ctx->ingress_ifindex,
                                           FDB_EVENT_MOVE);
                }
            } else if (!old.is_remote || !bd_peer_index_is_es(old.peer_index)) {
                existing->last_seen = bpf_ktime_get_ns();
            }
        }
    }

    if (eth->h_dest[0] & 0x01) {
        *out_action = bum_mode == BUM_MODE_XDP ? bum_xdp_flood_from_ac(ctx, key.bd_id, vlan_id)
                                               : bum_mark_for_tc(ctx, bum_mode, vlan_id);
        return NULL;
    }

    __builtin_memcpy(key.mac, eth->h_dest, ETH_ALEN);
    struct fdb_entry *dst_fdb = bpf_map_lookup_elem(&fdb_map, &key);
    if (dst_fdb) {
        union fdb_forward dst = fdb_read_forward(dst_fdb);
        if (dst.is_remote) {
            struct bd_peer_key pk = { .bd_id = key.bd_id, .index = dst.peer_index };
            struct headend_entry *pe = bpf_map_lookup_elem(&bd_peer_map, &pk);
            if (pe) {
                return pe;
            }
        } else if (bum_mode == BUM_MODE_XDP && bum_xdp_served(key.bd_id)) {
            // The bridge is off the path in xdp mode: deliver to the learned
            // port directly. A MAC learned on the ingress port itself is
            // dropped, as the bridge would (no hairpin). A BD without a
            // devmap is left to the bridge, like its BUM.
            *out_action = dst.oif == ctx->ingress_ifindex ? XDP_DROP : xdp_redirect_dev(dst.oif);
            return NULL;
        }
        *out_action = XDP_PASS;
        return NULL;
    }

    *out_action = bum_mode == BUM_MODE_XDP ? bum_xdp_flood_from_ac(ctx, key.bd_id, vlan_id)
                                           : bum_mark_for_tc(ctx, bum_mode, vlan_id);
    return NULL;
}

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

    int bd_action = XDP_PASS;
    struct headend_entry *encap = try_bd_peer_lookup(ctx, l2_entry, vlan_id, &bd_action);
    if (!encap) {
        if (bd_action == -1)
            encap = l2_entry; // no-BD path: encap with the local L2 entry
        else
            return bd_action; // BUM / pass / etc. handled by the lookup helper
    }

    // EVPN aliasing: a bd_peer that fronts a multi-homed segment carries an
    // ECMP group of the member PEs' entries; resolve it here so the single
    // bpf_tail_call site below stays the only one (see the invariant note on
    // try_bd_peer_lookup). An entry without a group resolves to itself, and
    // the hash also feeds the outer flow label for underlay entropy.
    __u32 flow_hash = ecmp_flow_hash_l2(ctx);
    encap = ecmp_resolve_headend(encap, flow_hash);
    if (!encap)
        return XDP_DROP;

    if (tailcall_ctx_write_headend(encap, 0, DISPATCH_HEADEND_L2, encap->mode, flow_hash) == 0)
        bpf_tail_call(ctx, &headend_l2_progs, encap->mode);
    return XDP_DROP;
}
