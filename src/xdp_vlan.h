#ifndef XDP_VLAN_H
#define XDP_VLAN_H

#include <linux/types.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>

#include "xdp_utils.h"  // For struct vlan_hdr

// Maximum number of VLAN tags to parse (supports QinQ)
#define MAX_VLAN_DEPTH 2

// Packet parsing context with VLAN support
struct pkt_ctx {
    void *data;
    void *data_end;
    struct ethhdr *eth;
    __u16 eth_proto;        // Final protocol (after VLAN tags)
    __u16 vlan_depth;       // Number of VLAN tags found
    __u16 l3_offset;        // Offset from data to L3 header
};

// Parse Ethernet header and any VLAN tags
// Returns 0 on success, -1 on failure (packet too short)
static __always_inline int parse_eth_vlan(struct pkt_ctx *pctx)
{
    void *data = pctx->data;
    void *data_end = pctx->data_end;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return -1;
    }
    pctx->eth = eth;

    __u16 eth_proto = eth->h_proto;
    __u16 offset = sizeof(struct ethhdr);

    // Parse VLAN tags (up to MAX_VLAN_DEPTH)
    #pragma unroll
    for (int i = 0; i < MAX_VLAN_DEPTH; i++) {
        if (eth_proto != bpf_htons(ETH_P_8021Q) &&
            eth_proto != bpf_htons(ETH_P_8021AD)) {
            break;
        }

        struct vlan_hdr *vhdr = data + offset;
        if ((void *)(vhdr + 1) > data_end) {
            return -1;
        }

        eth_proto = vhdr->h_vlan_encapsulated_proto;
        offset += sizeof(struct vlan_hdr);
        pctx->vlan_depth++;
    }

    pctx->eth_proto = eth_proto;
    pctx->l3_offset = offset;
    return 0;
}

// Get pointer to L3 header (IPv4 or IPv6)
static __always_inline void *get_l3_header(struct pkt_ctx *pctx)
{
    return pctx->data + pctx->l3_offset;
}

// Get VLAN ID from first VLAN tag (0 if no VLAN)
static __always_inline __u16 get_vlan_id(struct pkt_ctx *pctx)
{
    if (pctx->vlan_depth == 0) {
        return 0;
    }

    struct vlan_hdr *vhdr = (void *)(pctx->eth + 1);
    if ((void *)(vhdr + 1) > pctx->data_end) {
        return 0;
    }

    return bpf_ntohs(vhdr->h_vlan_TCI) & 0x0FFF;
}

#endif // XDP_VLAN_H
