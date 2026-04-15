#ifndef SRV6_GTP_HEADEND_H
#define SRV6_GTP_HEADEND_H

#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "core/xdp_prog.h"
#include "core/srv6.h"
#include "core/srv6_gtp.h"
#include "headend/srv6_headend_utils.h"
#include "core/srv6_fib.h"

// ========== H.M.GTP4.D: GTP-U/IPv4 → SRv6 (RFC 9433) ==========
//
// Receives: [Eth][IPv4][UDP:2152][GTP-U(+ext)][Inner IP]
// Produces: [Eth][Outer IPv6][SRH(with Args.Mob.Session)][Inner IP]
//
// Uses a single bpf_xdp_adjust_head to replace outer headers:
//   strip_len = IPv4 + UDP + GTP-U
//   add_len   = IPv6 + SRH
//   delta     = strip_len - add_len (positive = shrink, negative = grow)
static __always_inline int do_h_m_gtp4_d(
    struct xdp_md *ctx,
    struct ethhdr *eth,
    struct iphdr *iph,
    struct headend_entry *entry,
    __u16 l3_offset)
{
    void *data_end = (void *)(long)ctx->data_end;

    if (entry->num_segments < 1 || entry->num_segments > MAX_SEGMENTS)
        return XDP_DROP;

    if (iph->protocol != IPPROTO_UDP)
        return XDP_PASS;

    if (iph->ihl < 5)
        return XDP_DROP;

    void *udp_ptr = (void *)iph + (iph->ihl * 4);
    if (udp_ptr + sizeof(struct udphdr) > data_end)
        return XDP_PASS;

    struct gtpu_parsed gtp_info = {};
    if (gtpu_parse(udp_ptr, data_end, &gtp_info) != 0)
        return XDP_PASS;

    // Save state
    struct ethhdr saved_eth;
    __builtin_memcpy(&saved_eth, eth, sizeof(struct ethhdr));

    __u8 ipv4_dst[IPV4_ADDR_LEN];
    __builtin_memcpy(ipv4_dst, &iph->daddr, IPV4_ADDR_LEN);

    __u16 ipv4_hdr_len = iph->ihl * 4;
    __u16 strip_len = ipv4_hdr_len + sizeof(struct udphdr) + gtp_info.hdr_total_len;
    __u16 ipv4_total = bpf_ntohs(iph->tot_len);
    if (strip_len >= ipv4_total)
        return XDP_DROP;
    __u16 inner_total_len = ipv4_total - strip_len;

    __u8 inner_proto;
    if (detect_inner_proto((void *)iph + strip_len, data_end, &inner_proto) != 0)
        return XDP_DROP;

    // Calculate single adjustment delta.
    // Positive delta = advance data pointer (shrink headers).
    // Negative delta = retreat data pointer (grow headers).
    int srh_len = 8 + (16 * entry->num_segments);
    int add_len = (int)sizeof(struct ipv6hdr) + srh_len;
    int delta = (int)strip_len - add_len;

    __u32 teid = gtp_info.teid;
    __u8 qfi = gtp_info.qfi;
    __u8 rqi = gtp_info.rqi;
    __u8 args_offset = entry->args_offset;

    // Single adjust_head: replace IPv4+UDP+GTP-U with IPv6+SRH
    if (bpf_xdp_adjust_head(ctx, delta))
        return XDP_DROP;

    // Re-derive pointers
    void *data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    struct ethhdr *new_eth = data;
    if ((void *)(new_eth + 1) > data_end)
        return XDP_DROP;

    struct ipv6hdr *outer_ip6h = (struct ipv6hdr *)(new_eth + 1);
    if ((void *)(outer_ip6h + 1) > data_end)
        return XDP_DROP;

    struct ipv6_sr_hdr *srh = (struct ipv6_sr_hdr *)(outer_ip6h + 1);
    if ((void *)srh + 8 > data_end)
        return XDP_DROP;
    if ((void *)srh + srh_len > data_end)
        return XDP_DROP;

    // Build outer IPv6 header
    outer_ip6h->version = 6;
    outer_ip6h->priority = 0;
    outer_ip6h->flow_lbl[0] = 0;
    outer_ip6h->flow_lbl[1] = 0;
    outer_ip6h->flow_lbl[2] = 0;
    outer_ip6h->payload_len = bpf_htons(srh_len + inner_total_len);
    outer_ip6h->nexthdr = IPPROTO_ROUTING;
    outer_ip6h->hop_limit = 64;
    __builtin_memcpy(&outer_ip6h->saddr, entry->src_addr, sizeof(struct in6_addr));
    __builtin_memcpy(&outer_ip6h->daddr, &entry->segments[0], sizeof(struct in6_addr));

    // Build SRH
    srh->nexthdr = inner_proto;
    srh->hdrlen = (srh_len >> 3) - 1;
    srh->type = IPV6_SRCRT_TYPE_4;
    srh->segments_left = entry->num_segments - 1;
    srh->first_segment = entry->num_segments - 1;
    srh->flags = 0;
    srh->tag = 0;

    // Copy segments in reverse order
    void *srh_segments = (void *)srh + 8;
    if (copy_segments_to_srh(srh_segments, data_end, entry->segments, entry->num_segments) != 0)
        return XDP_DROP;

    // Patch Args.Mob.Session into DA and first SRH segment.
    // args_offset is per-entry (from map), masked to 0-7 for verifier safety
    // (max valid: 7, since offset + 9 <= 16 = IPv6 addr len).
    {
        args_offset &= 0x07;
        __be32 teid_be = bpf_htonl(teid);
        __u8 qfi_rqi = ENCODE_QFI_RQI(qfi, rqi);

        // Patch DA — bounds check AFTER variable addition
        __u8 *da = (__u8 *)&outer_ip6h->daddr;
        __u8 *da_ptr = da + args_offset;
        if ((void *)(da_ptr + 9) > data_end)
            return XDP_DROP;
        da_ptr[0] = ipv4_dst[0];
        da_ptr[1] = ipv4_dst[1];
        da_ptr[2] = ipv4_dst[2];
        da_ptr[3] = ipv4_dst[3];
        __builtin_memcpy(da_ptr + 4, &teid_be, 4);
        da_ptr[8] = qfi_rqi;

        // Patch first SRH segment
        __u8 first_seg = srh->first_segment;
        if (first_seg < MAX_SEGMENTS) {
            void *seg_ptr = srh_segments + ((__u32)first_seg * 16);
            __u8 *seg = (__u8 *)seg_ptr + args_offset;
            if ((void *)(seg + 9) > data_end)
                return XDP_DROP;
            seg[0] = ipv4_dst[0];
            seg[1] = ipv4_dst[1];
            seg[2] = ipv4_dst[2];
            seg[3] = ipv4_dst[3];
            __builtin_memcpy(seg + 4, &teid_be, 4);
            seg[8] = qfi_rqi;
        }
    }

    // Restore Ethernet header
    __builtin_memcpy(new_eth, &saved_eth, sizeof(struct ethhdr));
    new_eth->h_proto = bpf_htons(ETH_P_IPV6);

    return srv6_fib_redirect(ctx, outer_ip6h, new_eth, ctx->ingress_ifindex);
}

#endif // SRV6_GTP_HEADEND_H
