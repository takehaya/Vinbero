#ifndef SRV6_ENCAPS_H
#define SRV6_ENCAPS_H

#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "xdp_prog.h"
#include "srv6.h"
#include "srv6_headend_utils.h"

// H.Encaps core implementation - shared by both IPv4 and IPv6 encapsulation
// RFC 8986 Section 5.1
//
// Parameters:
//   ctx: XDP context
//   saved_eth: Pre-saved Ethernet header (must be saved before calling)
//   entry: Headend entry with segments and source address
//   inner_proto: Inner protocol (IPPROTO_IPIP for IPv4, IPPROTO_IPV6 for IPv6)
//   inner_total_len: Total length of inner packet (IPv4: tot_len, IPv6: 40 + payload_len)
//
// Returns: XDP action (XDP_REDIRECT, XDP_DROP, or XDP_PASS)
static __always_inline int do_h_encaps_core(
    struct xdp_md *ctx,
    struct ethhdr *saved_eth,
    struct headend_entry *entry,
    __u8 inner_proto,
    __u16 inner_total_len)
{
    // 1. Calculate new header sizes
    // IPv6 basic header: 40 bytes
    // SRH: 8 + 16 * num_segments bytes
    int ipv6_hdr_len = sizeof(struct ipv6hdr);
    int srh_len = 8 + (16 * entry->num_segments);
    int new_headers_len = ipv6_hdr_len + srh_len;

    // 2. Make room for new headers at the front of the packet
    if (bpf_xdp_adjust_head(ctx, -(new_headers_len))) {
        DEBUG_PRINT("H.Encaps: bpf_xdp_adjust_head failed\n");
        return XDP_DROP;
    }

    // 3. Re-fetch pointers after adjust_head (critical!)
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // 4. Boundary checks
    struct ethhdr *new_eth = data;
    CHECK_BOUND(new_eth, data_end, sizeof(*new_eth));

    struct ipv6hdr *outer_ip6h = (struct ipv6hdr *)(new_eth + 1);
    CHECK_BOUND(outer_ip6h, data_end, sizeof(*outer_ip6h));

    struct ipv6_sr_hdr *srh = (struct ipv6_sr_hdr *)(outer_ip6h + 1);
    // Check SRH fixed header (8 bytes) first
    CHECK_BOUND(srh, data_end, 8);
    // Then check the entire SRH including segments
    CHECK_BOUND(srh, data_end, srh_len);

    // 5. Build outer IPv6 header
    outer_ip6h->version = 6;
    outer_ip6h->priority = 0;
    outer_ip6h->flow_lbl[0] = 0;
    outer_ip6h->flow_lbl[1] = 0;
    outer_ip6h->flow_lbl[2] = 0;

    // Payload length = SRH + inner packet
    outer_ip6h->payload_len = bpf_htons(srh_len + inner_total_len);

    outer_ip6h->nexthdr = IPPROTO_ROUTING;  // SRH
    outer_ip6h->hop_limit = 64;

    // Source address from entry
    __builtin_memcpy(&outer_ip6h->saddr, entry->src_addr, sizeof(struct in6_addr));

    // Destination address = first segment
    __builtin_memcpy(&outer_ip6h->daddr, &entry->segments[0], sizeof(struct in6_addr));

    // 6. Build SRH
    srh->nexthdr = inner_proto;
    srh->hdrlen = (srh_len >> 3) - 1;  // Length in 8-byte units, excluding first 8 bytes
    srh->type = IPV6_SRCRT_TYPE_4;  // Segment Routing
    srh->segments_left = entry->num_segments - 1;
    srh->first_segment = entry->num_segments - 1;
    srh->flags = 0;
    srh->tag = 0;

    // 7. Copy segment list in reverse order (RFC 8754)
    // Input: [S1, S2, S3] -> SRH storage: [S3, S2, S1]
    void *srh_segments = (void *)srh + 8;
    if (copy_segments_to_srh(srh_segments, data_end, entry->segments, entry->num_segments) != 0) {
        DEBUG_PRINT("H.Encaps: Failed to copy segments\n");
        return XDP_DROP;
    }

    // 8. Copy saved Ethernet header
    __builtin_memcpy(new_eth, saved_eth, sizeof(struct ethhdr));
    new_eth->h_proto = bpf_htons(ETH_P_IPV6);

    // 9. FIB lookup and redirect
    struct bpf_fib_lookup fib_params = {};
    fib_params.family = AF_INET6;
    fib_params.ifindex = ctx->ingress_ifindex;

    __builtin_memcpy(fib_params.ipv6_src, &outer_ip6h->saddr, sizeof(fib_params.ipv6_src));
    __builtin_memcpy(fib_params.ipv6_dst, &outer_ip6h->daddr, sizeof(fib_params.ipv6_dst));

    int ret = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);

    switch (ret) {
    case BPF_FIB_LKUP_RET_SUCCESS:
        __builtin_memcpy(new_eth->h_dest, fib_params.dmac, ETH_ALEN);
        __builtin_memcpy(new_eth->h_source, fib_params.smac, ETH_ALEN);
        DEBUG_PRINT("H.Encaps: Success, redirect to ifindex %d\n", fib_params.ifindex);
        return bpf_redirect(fib_params.ifindex, 0);

    case BPF_FIB_LKUP_RET_BLACKHOLE:
    case BPF_FIB_LKUP_RET_UNREACHABLE:
    case BPF_FIB_LKUP_RET_PROHIBIT:
        DEBUG_PRINT("H.Encaps: FIB lookup drop (%d)\n", ret);
        return XDP_DROP;

    default:
        DEBUG_PRINT("H.Encaps: FIB lookup needs kernel (%d)\n", ret);
        return XDP_PASS;
    }
}

#endif // SRV6_ENCAPS_H
