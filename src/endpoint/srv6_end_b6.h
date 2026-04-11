#ifndef SRV6_END_B6_H
#define SRV6_END_B6_H

#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "core/xdp_prog.h"
#include "core/srv6.h"
#include "headend/srv6_headend_utils.h"
#include "core/srv6_fib.h"
#include "endpoint/srv6_endpoint.h"
#include "headend/srv6_insert.h"
#include "headend/srv6_encaps.h"
#include "headend/srv6_encaps_red.h"
#include "core/xdp_map.h"

// End.B6.Insert / End.B6.Insert.Red (RFC 8986 Section 4.12)
//
// 1. Policy data is in aux->b6_policy (from sid_aux_map, already looked up)
// 2. Standard endpoint processing: decrement SL, update DA
// 3. Insert policy SRH (reuse H.Insert core functions)
//
// Policy headend_entry.mode selects the variant:
//   H_INSERT     -> do_h_insert_core
//   H_INSERT_RED -> do_h_insert_red_core
static __noinline int process_end_b6_insert(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ipv6_sr_hdr *srh,
    struct sid_function_entry *entry,
    struct sid_aux_entry *aux,
    __u16 l3_offset)
{
    if (!aux) return XDP_DROP;
    struct headend_entry *policy = &aux->b6_policy;

    // --- Phase 1: Endpoint processing ---
    struct endpoint_ctx ectx;
    int ret = endpoint_init(&ectx, ctx, ip6h, srh, entry, l3_offset);

    if (ret == -1) {
        DEBUG_PRINT("End.B6.Insert: SL=0, pass to upper layer\n");
        return XDP_PASS;
    }
    if (ret == -2) {
        DEBUG_PRINT("End.B6.Insert: Invalid SL\n");
        return XDP_DROP;
    }

    if (endpoint_update_da(&ectx) != 0) {
        DEBUG_PRINT("End.B6.Insert: Failed to update DA\n");
        return XDP_DROP;
    }

    // --- Phase 2: H.Insert on the updated packet ---
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    struct ipv6hdr *cur_ip6h = (struct ipv6hdr *)((void *)eth + l3_offset);
    if ((void *)(cur_ip6h + 1) > data_end)
        return XDP_DROP;

    // Validate policy segments
    if (policy->num_segments < 1 || policy->num_segments > MAX_SEGMENTS - 1) {
        DEBUG_PRINT("End.B6.Insert: Invalid policy segment count %d\n", policy->num_segments);
        return XDP_DROP;
    }

    // Save headers before bpf_xdp_adjust_head
    struct ethhdr saved_eth;
    __builtin_memcpy(&saved_eth, eth, sizeof(struct ethhdr));
    // Save VLAN tag(s) (H.Insert preserves VLAN)
    __u32 saved_vlan[2];
    save_vlan_tags(saved_vlan, (void *)eth, (void *)(long)ctx->data_end, l3_offset);
    struct ipv6hdr saved_ip6h;
    __builtin_memcpy(&saved_ip6h, cur_ip6h, sizeof(struct ipv6hdr));

    // Dispatch based on policy mode
    if (policy->mode == SRV6_HEADEND_BEHAVIOR_H_INSERT_RED) {
        DEBUG_PRINT("End.B6.Insert.Red: Inserting reduced policy SRH\n");
        return do_h_insert_red_core(ctx, &saved_eth, saved_vlan, &saved_ip6h, policy, l3_offset);
    }

    DEBUG_PRINT("End.B6.Insert: Inserting policy SRH\n");
    return do_h_insert_core(ctx, &saved_eth, saved_vlan, &saved_ip6h, policy, l3_offset);
}

// End.B6.Encaps / End.B6.Encaps.Red (RFC 8986 Section 4.13)
//
// 1. Lookup policy from end_b6_policy_map
// 2. Standard endpoint processing: decrement SL, update DA
// 3. Encapsulate with outer IPv6+SRH (reuse H.Encaps core functions)
//
// Policy headend_entry.mode selects the variant:
//   H_ENCAPS     -> do_h_encaps_core
//   H_ENCAPS_RED -> do_h_encaps_red_core
static __noinline int process_end_b6_encaps(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ipv6_sr_hdr *srh,
    struct sid_function_entry *entry,
    struct sid_aux_entry *aux,
    __u16 l3_offset)
{
    if (!aux) return XDP_DROP;
    struct headend_entry *policy = &aux->b6_policy;

    // --- Phase 1: Endpoint processing ---
    struct endpoint_ctx ectx;
    int ret = endpoint_init(&ectx, ctx, ip6h, srh, entry, l3_offset);

    if (ret == -1) {
        DEBUG_PRINT("End.B6.Encaps: SL=0, pass to upper layer\n");
        return XDP_PASS;
    }
    if (ret == -2) {
        DEBUG_PRINT("End.B6.Encaps: Invalid SL\n");
        return XDP_DROP;
    }

    if (endpoint_update_da(&ectx) != 0) {
        DEBUG_PRINT("End.B6.Encaps: Failed to update DA\n");
        return XDP_DROP;
    }

    // --- Phase 2: H.Encaps on the updated packet ---
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    struct ipv6hdr *cur_ip6h = (struct ipv6hdr *)((void *)eth + l3_offset);
    if ((void *)(cur_ip6h + 1) > data_end)
        return XDP_DROP;

    // Validate policy segments
    if (policy->num_segments < 1 || policy->num_segments > MAX_SEGMENTS) {
        DEBUG_PRINT("End.B6.Encaps: Invalid policy segment count %d\n", policy->num_segments);
        return XDP_DROP;
    }

    // Save Ethernet header before bpf_xdp_adjust_head
    struct ethhdr saved_eth;
    __builtin_memcpy(&saved_eth, eth, sizeof(struct ethhdr));

    // Inner packet total length
    __u16 inner_total_len = 40 + bpf_ntohs(cur_ip6h->payload_len);

    // Dispatch based on policy mode
    if (policy->mode == SRV6_HEADEND_BEHAVIOR_H_ENCAPS_RED) {
        DEBUG_PRINT("End.B6.Encaps.Red: Encapsulating with reduced SRH\n");
        return do_h_encaps_red_core(ctx, &saved_eth, policy, IPPROTO_IPV6, inner_total_len, l3_offset);
    }

    DEBUG_PRINT("End.B6.Encaps: Encapsulating with outer IPv6+SRH\n");
    return do_h_encaps_core(ctx, &saved_eth, policy, IPPROTO_IPV6, inner_total_len, l3_offset);
}

#endif // SRV6_END_B6_H
