#ifndef SRV6_GTP_DECAP_H
#define SRV6_GTP_DECAP_H

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

// ========== End.M.GTP6.D: GTP-U/IPv6 → SRv6 (RFC 9433) ==========
//
// Receives: [Eth][IPv6(DA=SID)][SRH][UDP:2152][GTP-U(+ext)][Inner IP]
// Produces: [Eth][IPv6(DA=next SID)][SRH(SL--)][Inner IP]
//
// The SRv6 packet carries GTP-U payload. This endpoint:
// 1. Verifies SL > 0 and the payload is GTP-U
// 2. Extracts TEID/QFI from GTP-U headers
// 3. Strips UDP + GTP-U portion, advances SRv6 (decrement SL, update DA)
// 4. Encodes Args.Mob.Session into the next SID
// 5. FIB lookup + redirect
//
// Note: This function processes the GTP-U tunnel carried WITHIN the SRv6 packet,
// NOT a GTP-U outer tunnel. The SRH nexthdr must be IPPROTO_UDP (17).
static __always_inline int process_end_m_gtp6_d(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ipv6_sr_hdr *srh,
    struct sid_function_entry *entry,
    struct sid_aux_entry *aux,
    __u16 l3_offset)
{
    void *data_end = (void *)(long)ctx->data_end;

    // SRH nexthdr must indicate UDP (GTP-U payload)
    if (srh->nexthdr != IPPROTO_UDP)
        return XDP_PASS;

    // SL must be > 0 (not the last segment)
    if (srh->segments_left == 0)
        return XDP_PASS;

    // Parse GTP-U from the payload after SRH
    int srh_total_len = 8 + (srh->hdrlen * 8);
    void *udp_ptr = (void *)srh + srh_total_len;
    if (udp_ptr + sizeof(struct udphdr) > data_end)
        return XDP_PASS;

    struct gtpu_parsed gtp_info = {};
    if (gtpu_parse(udp_ptr, data_end, &gtp_info) != 0)
        return XDP_PASS;

    // Save GTP info
    __u32 teid = gtp_info.teid;
    __u8 qfi = gtp_info.qfi;
    __u8 rqi = gtp_info.rqi;

    __u8 inner_nexthdr;
    if (detect_inner_proto((void *)udp_ptr + sizeof(struct udphdr) + gtp_info.hdr_total_len,
                           data_end, &inner_nexthdr) != 0)
        return XDP_DROP;

    __u16 gtp_strip = sizeof(struct udphdr) + gtp_info.hdr_total_len;
    __u16 outer_headers = l3_offset + sizeof(struct ipv6hdr) + srh_total_len;

    // Compute next segment BEFORE any mutation (for fallback safety)
    __u8 new_sl = srh->segments_left - 1;
    void *seg_base = (void *)srh + 8;
    void *next_seg = seg_base + ((__u32)new_sl * 16);
    if (next_seg + 16 > data_end)
        return XDP_DROP;

    // Validate payload_len adjustment
    __u16 old_payload = bpf_ntohs(ip6h->payload_len);
    if (gtp_strip > old_payload)
        return XDP_DROP;

    // Check scratch feasibility BEFORE mutating any headers.
    // If we can't do mid-packet stripping, return XDP_PASS with the packet untouched.
    if (outer_headers > SCRATCH_BUF_SIZE)
        return XDP_PASS;

    __u32 scratch_key = 0;
    struct scratch_buf *scratch = bpf_map_lookup_elem(&scratch_map, &scratch_key);
    if (!scratch)
        return XDP_DROP;

    void *data = (void *)(long)ctx->data;

    // Bounds check: need outer_headers readable for save.
    // Use tiered fixed-size memcpy to avoid overwriting inner payload on restore.
    // ETH(14)+IPv6(40)+SRH: 1seg=78, 2seg=94, 3seg=110, 4seg=126
    #define TIER1 78
    #define TIER2 94
    #define TIER3 110
    #define TIER4 126

    __u16 copy_size;
    if (outer_headers <= TIER1) {
        if (data + TIER1 > data_end) return XDP_DROP;
        copy_size = TIER1;
    } else if (outer_headers <= TIER2) {
        if (data + TIER2 > data_end) return XDP_DROP;
        copy_size = TIER2;
    } else if (outer_headers <= TIER3) {
        if (data + TIER3 > data_end) return XDP_DROP;
        copy_size = TIER3;
    } else if (outer_headers <= TIER4) {
        if (data + TIER4 > data_end) return XDP_DROP;
        copy_size = TIER4;
    } else {
        return XDP_PASS;
    }

    // Step 1: Save outer headers (unmodified) to scratch
    if (copy_size == TIER1)
        __builtin_memcpy(scratch->data, data, TIER1);
    else if (copy_size == TIER2)
        __builtin_memcpy(scratch->data, data, TIER2);
    else if (copy_size == TIER3)
        __builtin_memcpy(scratch->data, data, TIER3);
    else
        __builtin_memcpy(scratch->data, data, TIER4);

    // Step 2: Mutate headers in scratch buffer (not in the packet).
    // scratch layout: [ETH(14)][IPv6(40)][SRH(8+segments)]
    // Modify: SRH.segments_left, SRH.nexthdr, IPv6.daddr, IPv6.payload_len
    #define SCR_IPV6_OFF  14
    #define SCR_SRH_OFF   54

    // SRH.segments_left
    scratch->data[SCR_SRH_OFF + 3] = new_sl;

    // SRH.nexthdr
    scratch->data[SCR_SRH_OFF + 0] = inner_nexthdr;

    // IPv6.payload_len (bytes 4-5 of IPv6 header)
    __u16 new_payload = bpf_htons(old_payload - gtp_strip);
    scratch->data[SCR_IPV6_OFF + 4] = (__u8)(new_payload >> 8);
    scratch->data[SCR_IPV6_OFF + 5] = (__u8)(new_payload & 0xFF);

    // IPv6 DA = next segment (bytes 24-39 of IPv6 header)
    __builtin_memcpy(scratch->data + SCR_IPV6_OFF + 24, next_seg, 16);

    // Encode Args.Mob.Session into scratch DA and SRH segment
    {
        __u8 g6off = aux ? (aux->gtp6d.args_offset & 0x0B) : 0;
        __be32 teid_be = bpf_htonl(teid);
        __u8 qfi_rqi = ENCODE_QFI_RQI(qfi, rqi);

        // Patch DA in scratch (offset 14+24+g6off)
        __u8 da_off = SCR_IPV6_OFF + 24 + g6off;
        if (da_off + 5 <= SCRATCH_BUF_SIZE) {
            __builtin_memcpy(scratch->data + da_off, &teid_be, 4);
            scratch->data[da_off + 4] = qfi_rqi;
        }

        // Patch SRH segment[new_sl] in scratch (offset 54+8+new_sl*16+g6off)
        __u16 seg_off = SCR_SRH_OFF + 8 + (__u16)new_sl * 16 + g6off;
        if (seg_off + 5 <= SCRATCH_BUF_SIZE) {
            __builtin_memcpy(scratch->data + seg_off, &teid_be, 4);
            scratch->data[seg_off + 4] = qfi_rqi;
        }
    }

    #undef SCR_IPV6_OFF
    #undef SCR_SRH_OFF

    // Step 3: Strip ETH + IPv6 + SRH + UDP + GTP-U
    int total_strip = (int)(outer_headers + gtp_strip);
    if (bpf_xdp_adjust_head(ctx, total_strip))
        return XDP_DROP;

    // Step 4: Re-add space for outer headers
    if (bpf_xdp_adjust_head(ctx, -(int)outer_headers))
        return XDP_DROP;

    // Step 5: Write modified headers back from scratch (exact size, no inner overwrite)
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    if (copy_size == TIER1) {
        if (data + TIER1 > data_end) return XDP_DROP;
        __builtin_memcpy(data, scratch->data, TIER1);
    } else if (copy_size == TIER2) {
        if (data + TIER2 > data_end) return XDP_DROP;
        __builtin_memcpy(data, scratch->data, TIER2);
    } else if (copy_size == TIER3) {
        if (data + TIER3 > data_end) return XDP_DROP;
        __builtin_memcpy(data, scratch->data, TIER3);
    } else {
        if (data + TIER4 > data_end) return XDP_DROP;
        __builtin_memcpy(data, scratch->data, TIER4);
    }

    #undef TIER1
    #undef TIER2
    #undef TIER3
    #undef TIER4

    // FIB lookup and redirect
    struct ethhdr *new_eth = data;
    if ((void *)(new_eth + 1) > data_end)
        return XDP_DROP;
    struct ipv6hdr *new_ip6h = (struct ipv6hdr *)(new_eth + 1);
    if ((void *)(new_ip6h + 1) > data_end)
        return XDP_DROP;

    __u32 ifindex;
    int fib_result = srv6_fib_lookup_and_update(ctx, new_ip6h, new_eth, &ifindex, ctx->ingress_ifindex);

    switch (fib_result) {
    case FIB_RESULT_REDIRECT:
        return bpf_redirect(ifindex, 0);
    case FIB_RESULT_DROP:
        return XDP_DROP;
    default:
        return XDP_PASS;
    }
}

// ========== End.M.GTP6.D.Di: GTP-U/IPv6 → SRv6 Drop-In (RFC 9433) ==========
//
// Receives: [Eth][IPv6(DA=SID)][SRH][UDP:2152][GTP-U(+ext)][Inner IP]
// Produces: [Eth][IPv6(DA=SID, SL unchanged)][SRH][Inner IP]
//
// Drop-In mode: minimal changes to existing infrastructure.
// - Does NOT decrement SL or update DA
// - Simply strips GTP-U tunnel and updates SRH nexthdr
// - Passes to kernel for further SRv6 processing
//
// This allows deploying SRv6 with minimal changes to the existing GTP-U infrastructure.
// The kernel SRv6 stack handles the subsequent segment processing.
static __always_inline int process_end_m_gtp6_d_di(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ipv6_sr_hdr *srh,
    struct sid_function_entry *entry,
    __u16 l3_offset)
{
    void *data_end = (void *)(long)ctx->data_end;

    // SRH nexthdr must indicate UDP (GTP-U payload)
    if (srh->nexthdr != IPPROTO_UDP)
        return XDP_PASS;

    // Parse GTP-U to determine header size
    int srh_total_len = 8 + (srh->hdrlen * 8);
    void *udp_ptr = (void *)srh + srh_total_len;
    if (udp_ptr + sizeof(struct udphdr) > data_end)
        return XDP_PASS;

    struct gtpu_parsed gtp_info = {};
    if (gtpu_parse(udp_ptr, data_end, &gtp_info) != 0)
        return XDP_PASS;

    // Drop-In: pass the packet to kernel without any modification.
    // Modifying nexthdr while GTP-U bytes remain would create an inconsistent
    // packet (nexthdr says IPv4/IPv6 but actual bytes are UDP+GTP-U).
    // The kernel processes the packet as-is with nexthdr=UDP.
    return XDP_PASS;
}

// ========== End.M.GTP6.E: SRv6 → GTP-U/IPv6 (RFC 9433) ==========
//
// Receives: [Eth][IPv6(DA=SID)][SRH][Inner IP]
// Produces: [Eth][IPv6][UDP:2152][GTP-U(E=1)][PDU Session Container][Inner IP]
//
// Similar to End.M.GTP4.E but with IPv6 outer instead of IPv4.
// GTP6E max encap: IPv6(40) + UDP(8) + GTP-U with PSC(16) = 64
#define GTP6E_OVERHEAD_MAX 64

static __always_inline int process_end_m_gtp6_e(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ipv6_sr_hdr *srh,
    struct sid_function_entry *entry,
    struct sid_aux_entry *aux,
    __u16 l3_offset)
{
    if (!aux) return XDP_DROP;
    // 1. SL must be 0
    if (srh->segments_left != 0)
        return XDP_PASS;

    // 2. Decode Args.Mob.Session from DA (GTP6 format: TEID + QFI/R/U)
    void *data_end_e = (void *)(long)ctx->data_end;
    __u8 g6off = aux->gtp6e.args_offset & 0x0B;  // per-entry, max 11
    __u8 *da_ptr = (__u8 *)&ip6h->daddr + g6off;
    if ((void *)(da_ptr + 5) > data_end_e)
        return XDP_DROP;

    __be32 teid_be;
    __builtin_memcpy(&teid_be, da_ptr, 4);
    __u32 teid = bpf_ntohl(teid_be);

    __u8 flags_byte = da_ptr[4];
    __u8 qfi = flags_byte & 0x3F;
    __u8 rqi = (flags_byte >> 6) & 0x01;

    // 3. Get outer IPv6 addresses from entry
    // src_addr: outer IPv6 source (from sid_function_entry)
    // dst_addr: outer IPv6 destination (from sid_function_entry)

    // 4. Strip outer IPv6 + SRH
    __u8 inner_nexthdr = srh->nexthdr;
    if (inner_nexthdr != IPPROTO_IPIP && inner_nexthdr != IPPROTO_IPV6)
        return XDP_DROP;

    if (srv6_decap(ctx, srh, inner_nexthdr, l3_offset) != 0)
        return XDP_DROP;

    // 5. Re-derive pointers
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    __u16 inner_len = (__u16)(data_end - (void *)(eth + 1));

    // 6. Prepend IPv6 + UDP + GTP-U headers (size depends on QFI)
    __u16 gtpu_hdr_len = gtpu_encap_hdr_len(qfi, rqi);
    int encap_len = (int)(sizeof(struct ipv6hdr) + sizeof(struct udphdr) + gtpu_hdr_len);

    if (bpf_xdp_adjust_head(ctx, -encap_len))
        return XDP_DROP;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    if (data + sizeof(struct ethhdr) + GTP6E_OVERHEAD_MAX > data_end)
        return XDP_DROP;

    struct ethhdr *new_eth = data;
    struct ipv6hdr *outer_ip6h = (struct ipv6hdr *)(new_eth + 1);
    struct udphdr *udph = (struct udphdr *)((void *)outer_ip6h + sizeof(struct ipv6hdr));
    void *gtpu_start = (void *)(udph + 1);

    // 7. Build Ethernet header
    new_eth->h_proto = bpf_htons(ETH_P_IPV6);

    // 8. Build outer IPv6 header
    outer_ip6h->version = 6;
    outer_ip6h->priority = 0;
    outer_ip6h->flow_lbl[0] = 0;
    outer_ip6h->flow_lbl[1] = 0;
    outer_ip6h->flow_lbl[2] = 0;
    outer_ip6h->payload_len = bpf_htons(sizeof(struct udphdr) + gtpu_hdr_len + inner_len);
    outer_ip6h->nexthdr = IPPROTO_UDP;
    outer_ip6h->hop_limit = 64;
    __builtin_memcpy(&outer_ip6h->saddr, aux->gtp6e.src_addr, sizeof(struct in6_addr));
    __builtin_memcpy(&outer_ip6h->daddr, aux->gtp6e.dst_addr, sizeof(struct in6_addr));

    // 9. Build UDP header
    udph->source = bpf_htons(GTPU_PORT);
    udph->dest = bpf_htons(GTPU_PORT);
    udph->len = bpf_htons(sizeof(struct udphdr) + gtpu_hdr_len + inner_len);
    // IPv6 UDP checksum: set to 0 per RFC 6935/6936 (zero checksum for
    // tunneling protocols over IPv6). Computing the full checksum over
    // variable-length inner payload is not feasible in XDP.
    udph->check = 0;

    // 10. Build GTP-U + PDU Session Container
    if (gtpu_build_headers(gtpu_start, data_end, teid, qfi, rqi, inner_len) != 0)
        return XDP_DROP;

    // 11. FIB lookup + redirect
    __u32 ifindex;
    int fib_result = srv6_fib_lookup_and_update(ctx, outer_ip6h, new_eth, &ifindex, ctx->ingress_ifindex);

    switch (fib_result) {
    case FIB_RESULT_REDIRECT:
        return bpf_redirect(ifindex, 0);
    case FIB_RESULT_DROP:
        return XDP_DROP;
    default:
        return XDP_PASS;
    }
}

#endif // SRV6_GTP_DECAP_H
