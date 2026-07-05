#ifndef SRV6_GTP6_HEADEND_H
#define SRV6_GTP6_HEADEND_H

#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "core/xdp_prog.h"
#include "core/srv6.h"
#include "core/srv6_gtp.h"
#include "headend/srv6_headend_utils.h"
#include "core/srv6_ecmp.h" // ecmp_flow_label (outer flow-label entropy)
#include "core/srv6_fib.h"

// ========== H.M.GTP6.D: GTP-U/IPv6 → SRv6 (RFC 9433) ==========
//
// Receives: [Eth][IPv6][UDP:2152][GTP-U(+ext)][Inner IP]
// Produces: [Eth][Outer IPv6][SRH(with Args.Mob.Session)][Inner IP]
//
// IPv6 counterpart of H.M.GTP4.D: a single bpf_xdp_adjust_head replaces the
// outer GTP-U/IPv6 stack with SRv6.
//   strip_len = IPv6 + UDP + GTP-U
//   add_len   = IPv6 + SRH
// Unlike End.M.GTP6.D (a SID-triggered endpoint that strips GTP-U carried
// *inside* an SRv6 packet), this is a headend that intercepts a raw GTP-U/IPv6
// tunnel by its outer IPv6 destination.

// gtp6_d_build_srv6 performs the transform once the GTP-U header is parsed.
// patch_args != 0 writes the GTP6 Args.Mob.Session (TEID + QFI/RQI, 5 bytes;
// the gNB IPv6 is not carried in the SID) at entry->args_offset. The F-TEID
// uplink toward a plain direct (End.DT6) SID passes patch_args=0.
static __always_inline int gtp6_d_build_srv6(
    struct xdp_md *ctx,
    struct ethhdr *eth,
    struct ipv6hdr *ip6h,
    struct headend_entry *entry,
    struct gtpu_parsed *gtp_info,
    __u16 l3_offset,
    int patch_args)
{
    void *data_end = (void *)(long)ctx->data_end;

    if (entry->num_segments < 1 || entry->num_segments > MAX_SEGMENTS)
        return XDP_DROP;

    struct ethhdr saved_eth;
    __builtin_memcpy(&saved_eth, eth, sizeof(struct ethhdr));

    // The outer IPv6 payload_len covers UDP + GTP-U + inner; after stripping
    // UDP + GTP-U the remainder is the inner packet.
    __u16 old_payload = bpf_ntohs(ip6h->payload_len);
    __u16 strip_after_ip6 = sizeof(struct udphdr) + gtp_info->hdr_total_len;
    if (strip_after_ip6 >= old_payload)
        return XDP_DROP;
    __u16 inner_total_len = old_payload - strip_after_ip6;
    __u16 strip_len = sizeof(struct ipv6hdr) + strip_after_ip6;

    __u8 inner_proto;
    if (detect_inner_proto((void *)ip6h + strip_len, data_end, &inner_proto) != 0)
        return XDP_DROP;

    int srh_len = 8 + (16 * entry->num_segments);
    int add_len = (int)sizeof(struct ipv6hdr) + srh_len;
    int delta = (int)strip_len - add_len;

    __u32 teid = gtp_info->teid;
    __u8 qfi = gtp_info->qfi;
    __u8 rqi = gtp_info->rqi;
    __u8 args_offset = entry->args_offset;

    // Single adjust_head: replace IPv6+UDP+GTP-U with IPv6+SRH.
    if (bpf_xdp_adjust_head(ctx, delta))
        return XDP_DROP;

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
    // Flow label from the dispatcher's flow hash (RFC 6437), with the TEID
    // mixed in: under fixed GTP-U ports the outer 5-tuple is one constant
    // tuple per eNB-UPF pair, so the TEID supplies the per-session entropy.
    ipv6_set_flow_label(outer_ip6h, headend_ctx_flow_label(teid));
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

    void *srh_segments = (void *)srh + 8;
    if (copy_segments_to_srh(srh_segments, data_end, entry->segments, entry->num_segments) != 0)
        return XDP_DROP;

    // Patch GTP6 Args.Mob.Session (5 bytes: QFI/RQI + TEID, RFC 9433 §6.1 order)
    // into DA and the first SRH segment. Max valid offset is 11 (offset + 5 <=
    // 16). Skipped for the F-TEID uplink toward a plain direct (End.DT6) SID.
    if (patch_args) {
        if (args_offset > 11)
            return XDP_DROP;
        __be32 teid_be = bpf_htonl(teid);
        __u8 qfi_rqi = ENCODE_QFI_RQI(qfi, rqi);

        __u8 *da = (__u8 *)&outer_ip6h->daddr;
        __u8 *da_ptr = da + args_offset;
        if ((void *)(da_ptr + 5) > data_end)
            return XDP_DROP;
        da_ptr[0] = qfi_rqi;
        __builtin_memcpy(da_ptr + 1, &teid_be, 4);

        __u8 first_seg = srh->first_segment;
        if (first_seg < MAX_SEGMENTS) {
            void *seg_ptr = srh_segments + ((__u32)first_seg * 16);
            __u8 *seg = (__u8 *)seg_ptr + args_offset;
            if ((void *)(seg + 5) > data_end)
                return XDP_DROP;
            seg[0] = qfi_rqi;
            __builtin_memcpy(seg + 1, &teid_be, 4);
        }
    }

    __builtin_memcpy(new_eth, &saved_eth, sizeof(struct ethhdr));
    new_eth->h_proto = bpf_htons(ETH_P_IPV6);

    return srv6_fib_redirect(ctx, outer_ip6h, new_eth, ctx->ingress_ifindex);
}

// gtp6_d_parse validates the GTP-U/IPv6 packet and parses its header. Returns 0
// on success (gtp_info populated), or an XDP action (>0) to return immediately.
static __always_inline int gtp6_d_parse(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct gtpu_parsed *gtp_info)
{
    void *data_end = (void *)(long)ctx->data_end;

    // Plain GTP-U/IPv6: IPv6 directly followed by UDP (no extension headers).
    if (ip6h->nexthdr != IPPROTO_UDP)
        return XDP_PASS;

    void *udp_ptr = (void *)(ip6h + 1);
    if (udp_ptr + sizeof(struct udphdr) > data_end)
        return XDP_PASS;

    if (gtpu_parse(udp_ptr, data_end, gtp_info) != 0)
        return XDP_PASS;

    return 0;
}

// do_h_m_gtp6_d: prefix-keyed H.M.GTP6.D. The headend_v6_map entry carries the
// segment list and the Args.Mob.Session is patched from the parsed TEID/QFI.
static __always_inline int do_h_m_gtp6_d(
    struct xdp_md *ctx,
    struct ethhdr *eth,
    struct ipv6hdr *ip6h,
    struct headend_entry *entry,
    __u16 l3_offset)
{
    struct gtpu_parsed gtp_info = {};
    int ret = gtp6_d_parse(ctx, ip6h, &gtp_info);
    if (ret != 0)
        return ret;

    return gtp6_d_build_srv6(ctx, eth, ip6h, entry, &gtp_info, l3_offset, /*patch_args=*/1);
}

// do_h_m_gtp6_d_teid: F-TEID-keyed H.M.GTP6.D (BGP MUP T2ST over GTP6). `entry`
// is the gate from headend_v6_map; its segments are unused. The per-session
// direct SID is resolved from mup_uplink_v6_map keyed on
// {instance, outer dst, TEID-prefix}.
static __always_inline int do_h_m_gtp6_d_teid(
    struct xdp_md *ctx,
    struct ethhdr *eth,
    struct ipv6hdr *ip6h,
    struct headend_entry *entry,
    __u16 l3_offset)
{
    // entry is the headend_v6_map gate (mode trigger) only; the real per-session
    // segments come from the F-TEID lookup below, so it is unused.
    struct gtpu_parsed gtp_info = {};
    int ret = gtp6_d_parse(ctx, ip6h, &gtp_info);
    if (ret != 0)
        return ret;

    // Full-length lookup key: the LPM trie returns the longest installed prefix,
    // so the instance and endpoint are matched fully and the TEID as a prefix.
    // The instance is the packet's VRF id, resolved once at the XDP entry and
    // carried in tailcall_ctx.vrf_id (0 = global VRF), so overlapping
    // {endpoint, TEID} spaces stay separated per VRF (per ingress AC).
    struct mup_uplink_v6_key key = {};
    key.prefixlen = 192;
    struct tailcall_ctx *tctx = tailcall_ctx_read();
    __be32 inst_be = bpf_htonl(tctx ? tctx->vrf_id : 0);
    __builtin_memcpy(key.instance, &inst_be, 4);
    __builtin_memcpy(key.endpoint, &ip6h->daddr, IPV6_ADDR_LEN);
    __be32 teid_be = bpf_htonl(gtp_info.teid);
    __builtin_memcpy(key.teid, &teid_be, 4);

    struct headend_entry *session = bpf_map_lookup_elem(&mup_uplink_v6_map, &key);
    if (!session)
        return XDP_PASS;

    int patch_args = (session->args_offset != MUP_ARGS_OFFSET_NONE);
    return gtp6_d_build_srv6(ctx, eth, ip6h, session, &gtp_info, l3_offset, patch_args);
}

#endif // SRV6_GTP6_HEADEND_H
