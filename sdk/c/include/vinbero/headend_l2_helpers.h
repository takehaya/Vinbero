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

/* ESI byte-level helpers. core/esi.h's esi_{is_zero,equal} aren't exposed
 * to plugins (only headers under vinbero/ ship in the SDK), so plugins
 * that compare ESIs use these. 8+2 split matches the in-tree pattern: it
 * gives the verifier two scalar loads instead of a 10-byte unrolled loop. */
static __always_inline bool vinbero_l2_esi_is_zero(const __u8 esi[ESI_LEN])
{
    __u64 hi = *(const __u64 *)esi;
    __u16 lo = *(const __u16 *)(esi + 8);
    return (hi | (__u64)lo) == 0;
}

static __always_inline bool vinbero_l2_esi_equal(const __u8 a[ESI_LEN], const __u8 b[ESI_LEN])
{
    __u64 a_hi = *(const __u64 *)a;
    __u64 b_hi = *(const __u64 *)b;
    __u16 a_lo = *(const __u16 *)(a + 8);
    __u16 b_lo = *(const __u16 *)(b + 8);
    return (a_hi == b_hi) && (a_lo == b_lo);
}

/* IPv6 byte-level helpers. Same rationale as the ESI ones: core/esi.h's
 * ipv6_{is_zero,equal} aren't on the SDK include path, and the DF check
 * below needs them. 8+8 split keeps the verifier happy. */
static __always_inline bool vinbero_l2_ipv6_is_zero(const __u8 addr[IPV6_ADDR_LEN])
{
    __u64 hi = *(const __u64 *)addr;
    __u64 lo = *(const __u64 *)(addr + 8);
    return (hi | lo) == 0;
}

static __always_inline bool vinbero_l2_ipv6_equal(const __u8 a[IPV6_ADDR_LEN], const __u8 b[IPV6_ADDR_LEN])
{
    __u64 a_hi = *(const __u64 *)a;
    __u64 b_hi = *(const __u64 *)b;
    __u64 a_lo = *(const __u64 *)(a + 8);
    __u64 b_lo = *(const __u64 *)(b + 8);
    return (a_hi == b_hi) && (a_lo == b_lo);
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

/* RFC 7432 §8.5 / RFC 9252: is this PE the Designated Forwarder for the
 * BD's local Ethernet Segment? Mirrors src/endpoint/srv6_endpoint_l2.h
 * ::dt2m_non_df_drop so plugins observe the same DF state the built-in
 * BUM filter uses. Returns true only when:
 *
 *   1. bd_local_esi_map[bd_id] resolves to a non-zero ESI (BD has a
 *      local ES configured).
 *   2. That ESI is registered in esi_map with local_attached=1
 *      (this PE actually attaches to the ES).
 *   3. esi_map[esi].df_pe_src_addr is set (DF election has completed —
 *      all-zero is treated as "not yet configured" and returns false to
 *      fail closed for plugins; the built-in NON_DF filter fails open
 *      in this state, the SDK contract is stricter on purpose).
 *   4. df_pe_src_addr == local_pe_src_addr (this PE is the active DF).
 *
 * bd_id==0 (no BD) returns false. Callers don't need to pre-lookup the
 * ESI; this helper handles the entire chain. */
static __always_inline bool vinbero_l2_is_df(__u16 bd_id)
{
    if (bd_id == 0)
        return false;

    __u32 key = bd_id;
    struct bd_local_esi_val *lv = bpf_map_lookup_elem(&bd_local_esi_map, &key);
    if (!lv || vinbero_l2_esi_is_zero(lv->esi))
        return false;

    struct esi_key ek = {};
    __builtin_memcpy(ek.esi, lv->esi, ESI_LEN);
    struct esi_entry *e = bpf_map_lookup_elem(&esi_map, &ek);
    if (!e || !e->local_attached)
        return false;

    if (vinbero_l2_ipv6_is_zero(e->df_pe_src_addr))
        return false;

    return vinbero_l2_ipv6_equal(e->df_pe_src_addr, e->local_pe_src_addr);
}

#endif /* VINBERO_SDK_HEADEND_L2_HELPERS_H */
