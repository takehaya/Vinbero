// Service-programming return path (draft-ietf-spring-srv6-service-programming).
// Included from xdp_prog.c — not compiled standalone.
//
// A proxy IFACE-IN is a dedicated attachment circuit: every frame arriving
// on it belongs to the one proxy segment bound to that circuit. The front
// door (xdp_main) calls try_service_return before try_l2_headend; a miss
// returns -1 and the packet continues down the ordinary pipeline, so
// non-proxy traffic pays exactly one hash lookup.
//
// The bpf_tail_call into service_return_progs below must stay the single
// lexical site referencing that PROG_ARRAY in this translation unit: a
// second site silently breaks XDP_REDIRECT from the targets (see the
// repro note in dispatch/l2_headend.c).

// Map the outermost ethertype to the SVC_INNER_* capability required to
// accept the frame. An Ethernet-typed circuit accepts any frame (the whole
// frame is the payload); an L3-typed circuit accepts only its own family.
static __always_inline int svc_inner_type_ok(__u8 mask, __u16 eth_proto)
{
    if (mask & SVC_INNER_ETHERNET)
        return 1;
    if (eth_proto == bpf_htons(ETH_P_IP))
        return mask & SVC_INNER_IPV4;
    if (eth_proto == bpf_htons(ETH_P_IPV6))
        return mask & SVC_INNER_IPV6;
    return 0;
}

// Return-path front door. Returns -1 when {ifindex, vlan} is not a proxy
// IFACE-IN (caller continues the normal pipeline) or an XDP action.
// eth_proto is the ethertype at l3_offset (inner proto for VLAN frames).
static __noinline int try_service_return(
    struct xdp_md *ctx,
    __u32 ifindex,
    __u16 vlan_id,
    __u16 l3_offset,
    __u16 eth_proto)
{
    struct service_ingress_key key = {
        .ifindex = ifindex,
        .vlan_id = vlan_id,
    };
    struct service_ingress_entry *entry =
        bpf_map_lookup_elem(&service_ingress_map, &key);
    if (!entry)
        return -1;

    // Dedicated circuit: an unexpected payload type is a misconfiguration
    // or a stray frame, never "someone else's traffic". Fail closed.
    if (!svc_inner_type_ok(entry->inner_type_mask, eth_proto))
        return XDP_DROP;

    if (tailcall_ctx_write_headend(&entry->encap, l3_offset,
                                   DISPATCH_SERVICE_RETURN, entry->behavior,
                                   0) == 0)
        bpf_tail_call(ctx, &service_return_progs, entry->behavior);
    // Unpopulated slot (behavior not implemented yet) or ctx write failure:
    // the circuit is dedicated, so fail closed rather than leaking the raw
    // service frame into the normal pipeline.
    return XDP_DROP;
}
