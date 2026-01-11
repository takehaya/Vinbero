#include <linux/types.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "xdp_prog.h"
#include "xdp_map.h"
#include "srv6.h"
#include "xdp_utils.h"
#include "srv6_headend_utils.h"
#include "srv6_encaps.h"
#include "xdp_stats.h"
#include "xdpcap.h"
#include "srv6_endpoint.h"
#include "xdp_vlan.h"

char _license[] SEC("license") = "GPL";

// Perform H.Encaps operation for IPv4 packets
// RFC 8986 Section 5.1
static __always_inline int do_h_encaps_v4(
    struct xdp_md *ctx,
    struct ethhdr *eth,
    struct iphdr *iph,
    struct headend_entry *entry)
{
    // 1. Validate segment count (1-10)
    if (entry->num_segments < 1 || entry->num_segments > MAX_SEGMENTS) {
        DEBUG_PRINT("H.Encaps.v4: Invalid segment count %d\n", entry->num_segments);
        return XDP_DROP;
    }

    // 2. Save original Ethernet header before adjust_head
    struct ethhdr saved_eth;
    __builtin_memcpy(&saved_eth, eth, sizeof(struct ethhdr));

    // 3. Get inner IPv4 packet length before adjust_head
    __u16 inner_total_len = bpf_ntohs(iph->tot_len);

    // 4. Call shared encapsulation core
    return do_h_encaps_core(ctx, &saved_eth, entry, IPPROTO_IPIP, inner_total_len);
}

// Process Headend for IPv4 packets
static __always_inline int process_headend_v4(
    struct xdp_md *ctx,
    struct ethhdr *eth,
    struct iphdr *iph)
{
    // 1. Build LPM key from destination address
    struct lpm_key_v4 key = {
        .prefixlen = 32,
    };
    __builtin_memcpy(key.addr, &iph->daddr, IPV4_ADDR_LEN);

    // 2. Lookup in headend_v4_map
    struct headend_entry *entry = bpf_map_lookup_elem(&headend_v4_map, &key);
    if (!entry) {
        return XDP_PASS;  // No rule, passthrough
    }

    // 3. Check mode (only H.Encaps supported for now)
    if (entry->mode != SRV6_HEADEND_BEHAVIOR_H_ENCAPS) {
        DEBUG_PRINT("Headend.v4: Unsupported mode %d\n", entry->mode);
        return XDP_PASS;
    }

    DEBUG_PRINT("Headend.v4: Found entry, performing H.Encaps\n");

    // 4. Perform H.Encaps
    return do_h_encaps_v4(ctx, eth, iph, entry);
}

// Perform H.Encaps operation for IPv6 packets
// RFC 8986 Section 5.1
static __always_inline int do_h_encaps_v6(
    struct xdp_md *ctx,
    struct ethhdr *eth,
    struct ipv6hdr *inner_ip6h,
    struct headend_entry *entry)
{
    // 1. Validate segment count (1-10)
    if (entry->num_segments < 1 || entry->num_segments > MAX_SEGMENTS) {
        DEBUG_PRINT("H.Encaps.v6: Invalid segment count %d\n", entry->num_segments);
        return XDP_DROP;
    }

    // 2. Save original Ethernet header before adjust_head
    struct ethhdr saved_eth;
    __builtin_memcpy(&saved_eth, eth, sizeof(struct ethhdr));

    // 3. Get inner IPv6 packet length before adjust_head
    // IPv6 total length = 40 (header) + payload_len
    __u16 inner_total_len = 40 + bpf_ntohs(inner_ip6h->payload_len);

    // 4. Call shared encapsulation core
    return do_h_encaps_core(ctx, &saved_eth, entry, IPPROTO_IPV6, inner_total_len);
}

// Process Headend for IPv6 packets
static __always_inline int process_headend_v6(
    struct xdp_md *ctx,
    struct ethhdr *eth,
    struct ipv6hdr *ip6h)
{
    // 1. Build LPM key from destination address
    struct lpm_key_v6 key = {
        .prefixlen = 128,
    };
    __builtin_memcpy(key.addr, &ip6h->daddr, IPV6_ADDR_LEN);

    // 2. Lookup in headend_v6_map
    struct headend_entry *entry = bpf_map_lookup_elem(&headend_v6_map, &key);
    if (!entry) {
        return XDP_PASS;  // No rule, passthrough
    }

    // 3. Check mode (only H.Encaps supported for now)
    if (entry->mode != SRV6_HEADEND_BEHAVIOR_H_ENCAPS) {
        DEBUG_PRINT("Headend.v6: Unsupported mode %d\n", entry->mode);
        return XDP_PASS;
    }

    DEBUG_PRINT("Headend.v6: Found entry, performing H.Encaps\n");

    // 4. Perform H.Encaps
    return do_h_encaps_v6(ctx, eth, ip6h, entry);
}

// Process SRv6 Local SID (Endpoint functions)
// Handles packets destined to a local SID
static __always_inline int process_srv6_localsid(
    struct xdp_md *ctx,
    struct ethhdr *eth,
    struct ipv6hdr *ip6h,
    void *data_end)
{
    // Check if next header is Routing Header
    if (ip6h->nexthdr != IPPROTO_ROUTING) {
        return XDP_PASS;
    }

    // Parse SRH - check minimum 8 bytes first
    void *srh_ptr = (void *)(ip6h + 1);
    if (srh_ptr + 8 > data_end) {
        return XDP_PASS;
    }

    struct ipv6_sr_hdr *srh = (struct ipv6_sr_hdr *)srh_ptr;

    // Verify this is Segment Routing (type 4)
    if (srh->type != IPV6_SRCRT_TYPE_4) {
        DEBUG_PRINT("SRv6: Not SR type (type=%d)\n", srh->type);
        return XDP_PASS;
    }

    // Lookup DA in sid_function_map
    struct lpm_key_v6 key = {
        .prefixlen = 128,
    };
    __builtin_memcpy(key.addr, &ip6h->daddr, IPV6_ADDR_LEN);

    struct sid_function_entry *entry = bpf_map_lookup_elem(&sid_function_map, &key);
    if (!entry) {
        DEBUG_PRINT("SRv6: No SID function entry for DA\n");
        return XDP_PASS;
    }

    DEBUG_PRINT("SRv6: Found SID function, action=%d\n", entry->action);

    // Dispatch based on action type
    switch (entry->action) {
    case SRV6_LOCAL_ACTION_END:
        return process_end(ctx, ip6h, srh, entry);

    // Phase 1 endpoint functions (with skeleton implementations)
    case SRV6_LOCAL_ACTION_END_X:
        return process_end_x(ctx, ip6h, srh, entry);

    case SRV6_LOCAL_ACTION_END_T:
        return process_end_t(ctx, ip6h, srh, entry);

    case SRV6_LOCAL_ACTION_END_DX4:
        return process_end_dx4(ctx, ip6h, srh, entry);

    case SRV6_LOCAL_ACTION_END_DX6:
        return process_end_dx6(ctx, ip6h, srh, entry);

    case SRV6_LOCAL_ACTION_END_DT4:
        return process_end_dt4(ctx, ip6h, srh, entry);

    case SRV6_LOCAL_ACTION_END_DT6:
        return process_end_dt6(ctx, ip6h, srh, entry);

    case SRV6_LOCAL_ACTION_END_DT46:
        return process_end_dt46(ctx, ip6h, srh, entry);

    // Phase 2+ endpoint functions (not yet implemented)
    case SRV6_LOCAL_ACTION_END_B6:
    case SRV6_LOCAL_ACTION_END_B6_ENCAPS:
    case SRV6_LOCAL_ACTION_END_BM:
    case SRV6_LOCAL_ACTION_END_S:
    case SRV6_LOCAL_ACTION_END_AS:
    case SRV6_LOCAL_ACTION_END_AM:
    case SRV6_LOCAL_ACTION_END_BPF:
    default:
        DEBUG_PRINT("SRv6: Unsupported action %d\n", entry->action);
        return XDP_PASS;
    }
}

SEC("xdp_vinbero_main")
int vinbero_main(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 pkt_len = data_end - data;
    int action = XDP_PASS;

    // Count all received packets
    STATS_INC(STATS_RX_PACKETS, pkt_len);

    // Parse Ethernet header with VLAN support
    struct pkt_ctx pctx = {
        .data = data,
        .data_end = data_end,
        .vlan_depth = 0,
    };

    if (parse_eth_vlan(&pctx) < 0) {
        action = XDP_PASS;
        goto out;
    }

    // Process IPv6 packets
    if (pctx.eth_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6h = get_l3_header(&pctx);
        CHECK_BOUND(ip6h, data_end, sizeof(*ip6h));

        // 1. Try SRv6 Local SID processing first (Endpoint operations)
        action = process_srv6_localsid(ctx, pctx.eth, ip6h, data_end);
        if (action != XDP_PASS) {
            goto out;
        }

        // 2. If not SRv6 packet, try Headend processing
        action = process_headend_v6(ctx, pctx.eth, ip6h);
        goto out;
    }

    // Process IPv4 packets
    if (pctx.eth_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *iph = get_l3_header(&pctx);
        CHECK_BOUND(iph, data_end, sizeof(*iph));

        // Try Headend processing for IPv4
        action = process_headend_v4(ctx, pctx.eth, iph);
        goto out;
    }

    // Pass through other protocols
    action = XDP_PASS;

out:
    // Update action-specific statistics
    switch (action) {
    case XDP_PASS:
        STATS_INC(STATS_PASS, pkt_len);
        break;
    case XDP_DROP:
        STATS_INC(STATS_DROP, pkt_len);
        break;
    case XDP_REDIRECT:
        STATS_INC(STATS_REDIRECT, pkt_len);
        break;
    default:
        break;
    }

    // Return through xdpcap hook if enabled
    RETURN_ACTION(ctx, &xdpcap_hook, action);
}
