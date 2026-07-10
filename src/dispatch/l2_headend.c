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
        existing->last_seen = bpf_ktime_get_ns();
    }

    if (eth->h_dest[0] & 0x01) {
        xdp_write_bum_meta(ctx, vlan_id);
        *out_action = XDP_PASS;
        return NULL;
    }

    __builtin_memcpy(key.mac, eth->h_dest, ETH_ALEN);
    struct fdb_entry *dst_fdb = bpf_map_lookup_elem(&fdb_map, &key);
    if (dst_fdb) {
        if (dst_fdb->is_remote) {
            struct bd_peer_key pk = { .bd_id = dst_fdb->bd_id, .index = dst_fdb->peer_index };
            struct headend_entry *pe = bpf_map_lookup_elem(&bd_peer_map, &pk);
            if (pe) {
                return pe;
            }
        }
        *out_action = XDP_PASS;
        return NULL;
    }

    xdp_write_bum_meta(ctx, vlan_id);
    *out_action = XDP_PASS;
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

    if (tailcall_ctx_write_headend(encap, 0, DISPATCH_HEADEND_L2, encap->mode, 0) == 0)
        bpf_tail_call(ctx, &headend_l2_progs, encap->mode);
    return XDP_DROP;
}
