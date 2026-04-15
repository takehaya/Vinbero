// TC ingress entry point — BUM flooding for L2VPN.
// Included from xdp_prog.c — not compiled standalone.
// Depends on l2vpn/tc_bum.h (must be included before this file).

SEC("tc")
int vinbero_tc_ingress(struct __sk_buff *skb)
{
    // Mode 2: Encap — clone returned to self with PE info in cb[]
    if (skb->cb[0] == TC_CB_ENCAP_MAGIC) {
        struct bd_peer_key pk = { .bd_id = (__u16)skb->cb[1], .index = (__u16)skb->cb[2] };
        struct headend_entry *pe = bpf_map_lookup_elem(&bd_peer_map, &pk);
        if (pe && pe->mode == SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2_RED)
            return tc_do_single_pe_encap_red(skb, skb->cb[1], skb->cb[2]);
        return tc_do_single_pe_encap(skb, skb->cb[1], skb->cb[2]);
    }

    // Mode 1: Dispatch — XDP wrote BUM meta, clone to self for each PE
    __u16 vlan_id;
    if (!tc_read_bum_meta(skb, &vlan_id))
        return TC_ACT_OK;

    return tc_dispatch_bum_clones(skb, vlan_id);
}
