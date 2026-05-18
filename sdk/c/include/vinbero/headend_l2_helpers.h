#ifndef VINBERO_SDK_HEADEND_L2_HELPERS_H
#define VINBERO_SDK_HEADEND_L2_HELPERS_H

/*
 * Vinbero Plugin SDK — L2 headend helpers (Phase 2).
 *
 * Plugins registered into headend_l2_progs slots (HEADEND_PLUGIN_BASE
 * == 16 .. HEADEND_PROG_MAX == 32) sit between BD forwarding's
 * remote-peer decision and do_h_encaps_l2{,_red}. The dispatcher writes
 * the chosen headend_entry into tctx->headend, so the encap target
 * (segments / src_addr / bd_id) is immediately readable. Anything else
 * the plugin wants to observe — VLAN ID, source / destination ESI,
 * local DF status — has to be re-derived from RO maps that vinberod
 * populates from the control plane.
 *
 * These inline helpers cover the common observations so plugin authors
 * don't reinvent header parsing or map lookup chains. All of them are
 * verifier-friendly (every memory access guarded, every map lookup
 * NULL-checked) and side-effect free.
 */

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "core/xdp_map.h"
#include "core/xdp_prog.h"

#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif
#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif

/* Inner L2 frame length seen by the plugin (Eth + payload, pre-encap). */
static __always_inline __u16 vinbero_l2_frame_len(const struct xdp_md *ctx)
{
    return (__u16)((long)ctx->data_end - (long)ctx->data);
}

/* Outer VLAN ID parsed from the packet. Returns 0 for untagged frames or
 * if the buffer is too short to safely read the VLAN header. QinQ outer
 * tag is preferred; inner-tag parsing is left to the plugin. */
static __always_inline __u16 vinbero_l2_vlan_id(const struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 0;
    __u16 proto = eth->h_proto;
    if (proto != bpf_htons(ETH_P_8021Q) && proto != bpf_htons(ETH_P_8021AD))
        return 0;
    struct vlan_hdr {
        __be16 h_vlan_TCI;
        __be16 h_vlan_encapsulated_proto;
    } __attribute__((packed));
    struct vlan_hdr *vh = (struct vlan_hdr *)(eth + 1);
    if ((void *)(vh + 1) > data_end)
        return 0;
    return bpf_ntohs(vh->h_vlan_TCI) & 0x0FFF;
}

/* Source ESI (the ES the local AC is attached to). Looks up
 * headend_l2_ext_map[(ifindex, vlan_id)] and copies the ESI bytes into
 * `out_esi`. Returns 0 on hit, -1 on miss (out_esi zeroed). Plugins
 * that don't care about multihoming can ignore the return value and
 * just check whether out_esi is all-zero. */
static __always_inline int vinbero_l2_lookup_esi(__u32 ifindex, __u16 vlan_id,
                                                 __u8 out_esi[ESI_LEN])
{
    struct headend_l2_key key = { .ifindex = ifindex, .vlan_id = vlan_id };
    struct headend_l2_ext_val *val = bpf_map_lookup_elem(&headend_l2_ext_map, &key);
    if (!val) {
        __builtin_memset(out_esi, 0, ESI_LEN);
        return -1;
    }
    __builtin_memcpy(out_esi, val->esi, ESI_LEN);
    return 0;
}

/* Destination peer's ESI. Two-step lookup:
 *   1. fdb_map[(bd_id, inner_dst_mac)] -> peer_index
 *   2. bd_peer_l2_ext_map[(bd_id, peer_index)] -> esi
 *
 * Returns 0 on hit, -1 otherwise (out_esi zeroed). The packet must
 * still have its inner Ethernet header at ctx->data — i.e. call this
 * BEFORE bpf_xdp_adjust_head or any other header manipulation.
 *
 * Note: BD-peer ESI is only available after BD forwarding has chosen a
 * remote peer; the dispatcher already gives the plugin a chance to
 * observe this state via tctx->headend, but the peer_index that maps
 * back to the ESI isn't carried in tctx, so this helper re-derives it. */
static __always_inline int vinbero_l2_dst_peer_esi(const struct xdp_md *ctx, __u16 bd_id,
                                                   __u8 out_esi[ESI_LEN])
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        __builtin_memset(out_esi, 0, ESI_LEN);
        return -1;
    }
    struct fdb_key fkey = { .bd_id = bd_id };
    __builtin_memcpy(fkey.mac, eth->h_dest, ETH_ALEN);
    struct fdb_entry *f = bpf_map_lookup_elem(&fdb_map, &fkey);
    if (!f || !f->is_remote) {
        __builtin_memset(out_esi, 0, ESI_LEN);
        return -1;
    }
    struct bd_peer_l2_ext_key pkey = { .bd_id = f->bd_id, .index = f->peer_index };
    struct bd_peer_l2_ext_val *pval = bpf_map_lookup_elem(&bd_peer_l2_ext_map, &pkey);
    if (!pval) {
        __builtin_memset(out_esi, 0, ESI_LEN);
        return -1;
    }
    __builtin_memcpy(out_esi, pval->esi, ESI_LEN);
    return 0;
}

/* Whether this PE is the DF for the given BD's local ES. Reads
 * bd_local_esi_map[bd_id] (populated by vinberod from HeadendL2.esi
 * config) and compares its ESI against the plugin-supplied one. Returns
 * true only if they match — i.e. the caller's ESI is the BD's local ES
 * AND this PE is the active DF. Callers that already know the local
 * ESI (via vinbero_l2_lookup_esi above) can pass it straight in. */
static __always_inline bool vinbero_l2_is_df_for_esi(__u16 bd_id, const __u8 esi[ESI_LEN])
{
    __u32 key = bd_id;
    struct bd_local_esi_val *val = bpf_map_lookup_elem(&bd_local_esi_map, &key);
    if (!val)
        return false;
    for (int i = 0; i < ESI_LEN; i++) {
        if (val->esi[i] != esi[i])
            return false;
    }
    return true;
}

#endif /* VINBERO_SDK_HEADEND_L2_HELPERS_H */
