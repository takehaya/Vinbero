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

char _license[] SEC("license") = "GPL";

// Process End operation
// RFC 8986 Section 4.1
static __always_inline int process_end(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ipv6_sr_hdr *srh,
    struct sid_function_entry *entry)
{
    void *data_end = (void *)(long)ctx->data_end;
    // S01. If (Segments Left == 0)
    if (srh->segments_left == 0) {
        DEBUG_PRINT("End: SL is 0, passing to upper layer\n");
        // Pass to upper layer processing
        return XDP_PASS;
    }

    // S02. Decrement Segments Left
    __u8 new_sl = srh->segments_left - 1;

    // Verify segment index is within bounds
    // first_segment is the index of the last segment in the list (0-indexed)
    if (new_sl > srh->first_segment) {
        DEBUG_PRINT("End: Invalid SL %d > first_segment %d\n", new_sl, srh->first_segment);
        return XDP_DROP;
    }

    // Calculate pointer to segment[new_sl]
    // Segments are stored in reverse order: segments[0] is the last SID
    struct in6_addr *segments = srh->segments;

    // Boundary check for accessing segments[new_sl]
    // Each segment is 16 bytes (sizeof(struct in6_addr))
    // We need to check that the END of the segment we want to access is within bounds
    struct in6_addr *target_segment = &segments[new_sl];
    if ((void *)(target_segment + 1) > data_end) {
        DEBUG_PRINT("End: Segment access out of bounds\n");
        return XDP_DROP;
    }

    // S03. Update DA with Segment List[Segments Left]
    __builtin_memcpy(&ip6h->daddr, target_segment, sizeof(struct in6_addr));

    // Update SL in SRH
    srh->segments_left = new_sl;

    DEBUG_PRINT("End: Updated DA, new SL=%d\n", new_sl);

    // S04. Submit the packet to the IPv6 module for transmission
    // Use bpf_fib_lookup to determine the egress interface and next hop

    struct bpf_fib_lookup fib_params = {};
    fib_params.family = AF_INET6;
    fib_params.ifindex = ctx->ingress_ifindex;

    // Copy source and destination addresses
    __builtin_memcpy(fib_params.ipv6_src, &ip6h->saddr, sizeof(fib_params.ipv6_src));
    __builtin_memcpy(fib_params.ipv6_dst, &ip6h->daddr, sizeof(fib_params.ipv6_dst));

    int ret = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);

    switch (ret) {
    case BPF_FIB_LKUP_RET_SUCCESS: {
        // Update Ethernet addresses
        struct ethhdr *eth = (void *)(long)ctx->data;
        void *data = (void *)(long)ctx->data;
        // Boundary check for Ethernet header
        if (data + sizeof(*eth) > data_end) {
            return XDP_DROP;
        }

        __builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
        __builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);

        DEBUG_PRINT("End: FIB lookup success, redirect to ifindex %d\n", fib_params.ifindex);

        // Redirect to the egress interface
        return bpf_redirect(fib_params.ifindex, 0);
    }

    case BPF_FIB_LKUP_RET_BLACKHOLE:
    case BPF_FIB_LKUP_RET_UNREACHABLE:
    case BPF_FIB_LKUP_RET_PROHIBIT:
        DEBUG_PRINT("End: FIB lookup returned drop (%d)\n", ret);
        return XDP_DROP;

    case BPF_FIB_LKUP_RET_NOT_FWDED:
    case BPF_FIB_LKUP_RET_FWD_DISABLED:
    case BPF_FIB_LKUP_RET_UNSUPP_LWT:
    case BPF_FIB_LKUP_RET_NO_NEIGH:
    case BPF_FIB_LKUP_RET_FRAG_NEEDED:
    default:
        // Let the kernel handle it
        DEBUG_PRINT("End: FIB lookup needs kernel help (%d)\n", ret);
        return XDP_PASS;
    }
}

// Process SRv6 packet
static __always_inline int process_srv6(
    struct xdp_md *ctx,
    struct ethhdr *eth,
    struct ipv6hdr *ip6h,
    void *data_end)
{
    // Check if next header is Routing Header
    if (ip6h->nexthdr != IPPROTO_ROUTING) {
        return XDP_PASS;
    }

    // Parse SRH
    struct ipv6_sr_hdr *srh = (struct ipv6_sr_hdr *)(ip6h + 1);
    CHECK_BOUND(srh, data_end, sizeof(*srh));

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

    // Future: Add more endpoint functions here
    case SRV6_LOCAL_ACTION_END_X:
    case SRV6_LOCAL_ACTION_END_T:
    case SRV6_LOCAL_ACTION_END_DX6:
    case SRV6_LOCAL_ACTION_END_DX4:
    case SRV6_LOCAL_ACTION_END_DT6:
    case SRV6_LOCAL_ACTION_END_DT4:
    case SRV6_LOCAL_ACTION_END_DT46:
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

    // Parse Ethernet header
    struct ethhdr *eth = data;
    CHECK_BOUND(eth, data_end, sizeof(*eth));

    // Only process IPv6 packets
    if (eth->h_proto != bpf_htons(ETH_P_IPV6)) {
        return XDP_PASS;
    }

    // Parse IPv6 header
    struct ipv6hdr *ip6h = (struct ipv6hdr *)(eth + 1);
    CHECK_BOUND(ip6h, data_end, sizeof(*ip6h));

    // Process SRv6
    return process_srv6(ctx, eth, ip6h, data_end);
}
