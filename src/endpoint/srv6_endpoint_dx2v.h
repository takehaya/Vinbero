#ifndef SRV6_ENDPOINT_DX2V_H
#define SRV6_ENDPOINT_DX2V_H

#include "endpoint/srv6_endpoint_core.h"
#include "core/xdp_map.h"

// ========================================================================
// End.DX2V: Decapsulation with VLAN L2 cross-connect (RFC 8986 Section 4.10)
// ========================================================================

// VLAN cross-connect forwarding: extract inner VLAN, lookup (table_id, vlan_id) -> oif
static __always_inline int dx2v_forward_l2(
    struct xdp_md *ctx,
    struct ethhdr *inner_eth,
    void *data_end,
    __u16 table_id)
{
    // Inner frame must be VLAN-tagged
    if (inner_eth->h_proto != bpf_htons(ETH_P_8021Q) &&
        inner_eth->h_proto != bpf_htons(ETH_P_8021AD)) {
        DEBUG_PRINT("End.DX2V: inner frame not VLAN-tagged\n");
        return XDP_DROP;
    }

    struct vlan_hdr *vhdr = (struct vlan_hdr *)(inner_eth + 1);
    if ((void *)(vhdr + 1) > data_end)
        return XDP_DROP;

    __u16 vlan_id = bpf_ntohs(vhdr->h_vlan_TCI) & 0x0FFF;

    struct dx2v_key key = { .table_id = table_id, .vlan_id = vlan_id };
    struct dx2v_entry *entry = bpf_map_lookup_elem(&dx2v_map, &key);
    if (!entry || entry->oif == 0) {
        DEBUG_PRINT("End.DX2V: VLAN %d not found in table %d\n", vlan_id, table_id);
        return XDP_DROP;
    }

    DEBUG_PRINT("End.DX2V: VLAN %d -> oif %d\n", vlan_id, entry->oif);
    return bpf_redirect(entry->oif, 0);
}

// End.DX2V with SRH: decap + VLAN cross-connect lookup
static __always_inline int process_end_dx2v(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ipv6_sr_hdr *srh,
    struct sid_function_entry *entry,
    struct sid_aux_entry *aux,
    __u16 l3_offset)
{
    if (!aux) return XDP_DROP;

    if (srh->segments_left != 0) {
        DEBUG_PRINT("End.DX2V: SL != 0, passing\n");
        return XDP_PASS;
    }

    if (srh->nexthdr != IPPROTO_ETHERNET) {
        DEBUG_PRINT("End.DX2V: nexthdr is not Ethernet (%d)\n", srh->nexthdr);
        return XDP_DROP;
    }

    __u16 table_id = aux->dx2v.table_id;

    // Strip outer headers (Eth + IPv6 + SRH)
    int strip_len = calc_decap_strip_len(srh, l3_offset);
    if (bpf_xdp_adjust_head(ctx, strip_len)) {
        DEBUG_PRINT("End.DX2V: bpf_xdp_adjust_head failed\n");
        return XDP_DROP;
    }

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *inner_eth = data;
    if ((void *)(inner_eth + 1) > data_end)
        return XDP_DROP;

    return dx2v_forward_l2(ctx, inner_eth, data_end, table_id);
}

// End.DX2V no-SRH variant (Reduced SRH single-segment)
static __always_inline int process_end_dx2v_nosrh(
    struct xdp_md *ctx,
    __u8 nexthdr,
    struct sid_aux_entry *aux,
    __u16 l3_offset)
{
    if (!aux) return XDP_DROP;

    if (nexthdr != IPPROTO_ETHERNET)
        return XDP_PASS;

    __u16 table_id = aux->dx2v.table_id;

    // Strip outer Ethernet + IPv6 (no SRH)
    if (srv6_decap_l2_nosrh(ctx, nexthdr, l3_offset) != 0)
        return XDP_DROP;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *inner_eth = data;
    if ((void *)(inner_eth + 1) > data_end)
        return XDP_DROP;

    return dx2v_forward_l2(ctx, inner_eth, data_end, table_id);
}

#endif // SRV6_ENDPOINT_DX2V_H
