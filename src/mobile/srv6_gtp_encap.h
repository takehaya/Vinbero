#ifndef SRV6_GTP_ENCAP_H
#define SRV6_GTP_ENCAP_H

#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "core/xdp_prog.h"
#include "core/srv6.h"
#include "mobile/srv6_gtp.h"
#include "endpoint/srv6_decaps.h"
#include "core/srv6_fib.h"

// ========== End.M.GTP4.E: SRv6 → GTP-U/IPv4 (RFC 9433) ==========
//
// Receives: [Eth][IPv6(DA=SID)][SRH][Inner IP]
// Produces: [Eth][IPv4][UDP:2152][GTP-U(E=1)][PDU Session Container][Inner IP]
//
// 1. Verify SL == 0 (last segment)
// 2. Decode Args.Mob.Session from DA → gtp4_dst, TEID, QFI, RQI
// 3. Strip outer IPv6 + SRH (srv6_decap)
// 4. Prepend IPv4 + UDP + GTP-U + PDU Session Container
// 5. IPv4 FIB lookup + redirect
//
// GTP-U encap overhead: IPv4(20) + UDP(8) + GTP-U header (8 or 16)
// With PSC: 20+8+16 = 44, Without PSC: 20+8+8 = 36
#define GTP4E_OVERHEAD_WITH_PSC 44
#define GTP4E_OVERHEAD_NO_PSC   36

static __always_inline int process_end_m_gtp4_e(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ipv6_sr_hdr *srh,
    struct sid_function_entry *entry)
{
    // 1. SL must be 0
    if (srh->segments_left != 0)
        return XDP_PASS;

    // 2. Decode Args.Mob.Session from IPv6 DA (per-entry offset)
    void *args_de = (void *)(long)ctx->data_end;
    __u8 off = entry->args_offset & 0x07;  // max 7 (offset + 9 <= 16)
    __u8 *da_ptr = (__u8 *)&ip6h->daddr + off;
    if ((void *)(da_ptr + 9) > args_de)
        return XDP_DROP;

    __u8 gtp4_dst[IPV4_ADDR_LEN];
    gtp4_dst[0] = da_ptr[0];
    gtp4_dst[1] = da_ptr[1];
    gtp4_dst[2] = da_ptr[2];
    gtp4_dst[3] = da_ptr[3];

    __be32 teid_be;
    __builtin_memcpy(&teid_be, da_ptr + 4, 4);
    __u32 teid = bpf_ntohl(teid_be);

    __u8 flags_byte = da_ptr[8];
    __u8 qfi = flags_byte & 0x3F;
    __u8 rqi = (flags_byte >> 6) & 0x01;

    // 3. Get GTP4 source IPv4 from sid_function_entry
    __u8 gtp4_src[IPV4_ADDR_LEN];
    __builtin_memcpy(gtp4_src, entry->gtp_v4_src_addr, IPV4_ADDR_LEN);

    // 4. Strip outer IPv6 + SRH → [Eth][Inner IP]
    // We accept any inner protocol (IPPROTO_IPIP or IPPROTO_IPV6)
    __u8 inner_nexthdr = srh->nexthdr;
    if (inner_nexthdr != IPPROTO_IPIP && inner_nexthdr != IPPROTO_IPV6)
        return XDP_DROP;

    if (srv6_decap(ctx, srh, inner_nexthdr) != 0)
        return XDP_DROP;

    // 5. Re-derive pointers, get inner packet length
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    __u16 inner_len = (__u16)(data_end - (void *)(eth + 1));

    // 6. Prepend GTP-U/IPv4 headers (size depends on QFI presence)
    __u16 gtpu_hdr_len = gtpu_encap_hdr_len(qfi, rqi);
    int encap_overhead = (int)(sizeof(struct iphdr) + sizeof(struct udphdr) + gtpu_hdr_len);

    if (bpf_xdp_adjust_head(ctx, -encap_overhead))
        return XDP_DROP;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    if (data + sizeof(struct ethhdr) + GTP4E_OVERHEAD_WITH_PSC > data_end)
        return XDP_DROP;

    struct ethhdr *new_eth = data;
    struct iphdr *outer_iph = (struct iphdr *)(new_eth + 1);
    struct udphdr *udph = (struct udphdr *)((void *)outer_iph + sizeof(struct iphdr));
    void *gtpu_start = (void *)(udph + 1);

    // 7. Build Ethernet header
    // Copy saved MACs from inner Eth (which was shifted)
    // Actually, we need to set the protocol and let FIB fill MACs
    new_eth->h_proto = bpf_htons(ETH_P_IP);

    // 8. Build IPv4 header
    outer_iph->version = 4;
    outer_iph->ihl = 5;  // No options
    outer_iph->tos = 0;
    outer_iph->tot_len = bpf_htons(encap_overhead + inner_len);
    outer_iph->id = 0;
    outer_iph->frag_off = bpf_htons(0x4000);  // DF bit
    outer_iph->ttl = 64;
    outer_iph->protocol = IPPROTO_UDP;
    outer_iph->check = 0;
    __builtin_memcpy(&outer_iph->saddr, gtp4_src, 4);
    __builtin_memcpy(&outer_iph->daddr, gtp4_dst, 4);

    // IPv4 checksum (fixed 20-byte header, no options)
    {
        __u32 csum = 0;
        __u16 *hdr16 = (__u16 *)outer_iph;
        #pragma unroll
        for (int i = 0; i < 10; i++)
            csum += hdr16[i];
        csum = (csum >> 16) + (csum & 0xFFFF);
        csum += (csum >> 16);
        outer_iph->check = (__u16)~csum;
    }

    // 9. Build UDP header
    udph->source = bpf_htons(GTPU_PORT);
    udph->dest = bpf_htons(GTPU_PORT);
    udph->len = bpf_htons(sizeof(struct udphdr) + gtpu_hdr_len + inner_len);
    udph->check = 0;  // Optional for IPv4

    // 10. Build GTP-U + PDU Session Container
    if (gtpu_build_headers(gtpu_start, data_end, teid, qfi, rqi, inner_len) != 0)
        return XDP_DROP;

    // 11. IPv4 FIB lookup + redirect
    return srv6_fib_redirect_v4(ctx, outer_iph, new_eth, ctx->ingress_ifindex);
}

#endif // SRV6_GTP_ENCAP_H
