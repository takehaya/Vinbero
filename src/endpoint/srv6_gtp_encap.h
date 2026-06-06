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
#include "core/srv6_gtp.h"
#include "endpoint/srv6_decaps.h"
#include "core/srv6_fib.h"

// ========== End.M.GTP4.E: SRv6 → GTP-U/IPv4 (RFC 9433) ==========
//
// Receives: [Eth][IPv6(DA=SID)][SRH?][Inner IP]
// Produces: [Eth][IPv4][UDP:2152][GTP-U(E=1)][PDU Session Container][Inner IP]
//
// 1. Verify SL == 0 (last segment) when SRH is present
// 2. Decode Args.Mob.Session from DA → gtp4_dst, TEID, QFI, RQI
// 3. Strip outer IPv6 (+ SRH if present) → [Eth][Inner IP]
// 4. Prepend IPv4 + UDP + GTP-U + PDU Session Container
// 5. IPv4 FIB lookup + redirect
//
// GTP-U encap overhead: IPv4(20) + UDP(8) + GTP-U header (8 or 16)
// With PSC: 20+8+16 = 44, Without PSC: 20+8+8 = 36
#define GTP4E_OVERHEAD_WITH_PSC 44
#define GTP4E_OVERHEAD_NO_PSC   36

// Parsed Args.Mob.Session view shared by both SRH-present and reduced-encap paths.
struct gtp4e_args {
    __u8 gtp4_dst[IPV4_ADDR_LEN];
    __u8 gtp4_src[IPV4_ADDR_LEN];
    __u32 teid;
    __u8 qfi;
    __u8 rqi;
};

// Decode Args.Mob.Session (9 bytes) from the IPv6 DA at aux->gtp4e.args_offset,
// and pull the GTP4 source IPv4 from the auxiliary entry. Returns 0 on success.
//
// The 9 DA bytes are first copied into a stack buffer in a single memcpy. This
// matters for the no-SRH path: the verifier can lose packet-pointer provenance
// across subsequent header adjustments when individual byte reads are
// interleaved with stack writes inside an inlined caller.
static __always_inline int gtp4e_parse_args(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct sid_aux_entry *aux,
    struct gtp4e_args *out)
{
    void *data_end = (void *)(long)ctx->data_end;
    __u8 off = aux->gtp4e.args_offset & 0x07;  // max 7 (offset + 9 <= 16)
    __u8 *da_ptr = (__u8 *)&ip6h->daddr + off;
    if ((void *)(da_ptr + 9) > data_end)
        return -1;

    __u8 args[9];
    __builtin_memcpy(args, da_ptr, 9);

    __builtin_memcpy(out->gtp4_dst, args, 4);

    __be32 teid_be;
    __builtin_memcpy(&teid_be, args + 4, 4);
    out->teid = bpf_ntohl(teid_be);

    out->qfi = args[8] & 0x3F;
    out->rqi = (args[8] >> 6) & 0x01;

    __builtin_memcpy(out->gtp4_src, aux->gtp4e.gtp_v4_src_addr, IPV4_ADDR_LEN);
    return 0;
}

// Build the outer GTP-U/IPv4 encap on top of the already-decapsulated packet
// ([Eth][Inner IP]) and FIB-redirect to the GTP4 destination. The caller must
// have just finished the outer-IPv6 (+optional SRH) strip; this helper takes
// over from re-deriving data pointers through XDP_REDIRECT.
static __always_inline int gtp4e_build_and_redirect(
    struct xdp_md *ctx,
    const struct gtp4e_args *args)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    __u16 inner_len = (__u16)(data_end - (void *)(eth + 1));

    __u16 gtpu_hdr_len = gtpu_encap_hdr_len(args->qfi, args->rqi);
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

    // Ethernet: only protocol matters here; FIB redirect rewrites MACs.
    new_eth->h_proto = bpf_htons(ETH_P_IP);

    // IPv4 header (no options).
    outer_iph->version = 4;
    outer_iph->ihl = 5;
    outer_iph->tos = 0;
    outer_iph->tot_len = bpf_htons(encap_overhead + inner_len);
    outer_iph->id = 0;
    outer_iph->frag_off = bpf_htons(0x4000);  // DF bit
    outer_iph->ttl = 64;
    outer_iph->protocol = IPPROTO_UDP;
    outer_iph->check = 0;
    __builtin_memcpy(&outer_iph->saddr, args->gtp4_src, 4);
    __builtin_memcpy(&outer_iph->daddr, args->gtp4_dst, 4);

    // IPv4 checksum (fixed 20-byte header, no options).
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

    // UDP header (checksum optional for IPv4).
    udph->source = bpf_htons(GTPU_PORT);
    udph->dest = bpf_htons(GTPU_PORT);
    udph->len = bpf_htons(sizeof(struct udphdr) + gtpu_hdr_len + inner_len);
    udph->check = 0;

    if (gtpu_build_headers(gtpu_start, data_end, args->teid, args->qfi, args->rqi, inner_len) != 0)
        return XDP_DROP;

    return srv6_fib_redirect_v4(ctx, outer_iph, new_eth, ctx->ingress_ifindex);
}

// SRH-present (RFC 9433 §6.2 nominal) variant.
static __always_inline int process_end_m_gtp4_e(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ipv6_sr_hdr *srh,
    struct sid_function_entry *entry,
    struct sid_aux_entry *aux,
    __u16 l3_offset)
{
    if (!aux) return XDP_DROP;

    // SL must be 0 (we are the last segment).
    if (srh->segments_left != 0)
        return XDP_PASS;

    struct gtp4e_args args;
    if (gtp4e_parse_args(ctx, ip6h, aux, &args) != 0)
        return XDP_DROP;

    // Accept either IPIP or IPv6 inner.
    __u8 inner_nexthdr = srh->nexthdr;
    if (inner_nexthdr != IPPROTO_IPIP && inner_nexthdr != IPPROTO_IPV6)
        return XDP_DROP;

    // Strip outer L2+IPv6+SRH, then leave [Eth][Inner IP] for the builder.
    if (srv6_decap(ctx, srh, inner_nexthdr, l3_offset) != 0)
        return XDP_DROP;

    return gtp4e_build_and_redirect(ctx, &args);
}

// Reduced-encap variant: outer IPv6 with no SRH (RFC 8986 §4.1.1 single-SID
// H.Encaps). The IPv6 nexthdr is the inner protocol directly; args are still
// embedded in the IPv6 DA at aux->gtp4e.args_offset. Used when a Sender does
// single-segment encap (e.g. VPP's `sr policy add ... next SID encap` for one
// SID).
//
// Strip is two-step like srv6_decap_nosrh() so the packet head ends up as
// [Eth][Inner IP] for gtp4e_build_and_redirect(): (1) drop outer L2 + IPv6
// (l3_offset + sizeof(ipv6hdr)), then (2) re-expand ETH_HLEN so an Ethernet
// frame fits in front of the inner IP. The new Ethernet header is left
// uninitialized -- gtp4e_build_and_redirect() rewrites h_proto and bpf_redirect
// (via the FIB lookup) populates the MACs, so saving / restoring the original
// eth (as srv6_decap_nosrh does) is unnecessary.
static __always_inline int process_end_m_gtp4_e_nosrh(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    __u8 inner_nexthdr,
    struct sid_function_entry *entry,
    struct sid_aux_entry *aux,
    __u16 l3_offset)
{
    if (!aux) return XDP_DROP;

    if (inner_nexthdr != IPPROTO_IPIP && inner_nexthdr != IPPROTO_IPV6)
        return XDP_DROP;

    struct gtp4e_args args;
    if (gtp4e_parse_args(ctx, ip6h, aux, &args) != 0)
        return XDP_DROP;

    // Two-step strip so the head ends at [Eth][Inner IP], matching what
    // gtp4e_build_and_redirect() expects (eth = data).
    int strip_len = (int)l3_offset + (int)sizeof(struct ipv6hdr);
    if (bpf_xdp_adjust_head(ctx, strip_len))
        return XDP_DROP;
    if (bpf_xdp_adjust_head(ctx, -(int)ETH_HLEN))
        return XDP_DROP;

    return gtp4e_build_and_redirect(ctx, &args);
}

#endif // SRV6_GTP_ENCAP_H
