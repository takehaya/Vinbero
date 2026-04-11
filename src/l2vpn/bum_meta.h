#ifndef BUM_META_H
#define BUM_META_H

#include <linux/types.h>
#include <bpf/bpf_helpers.h>

// BUM metadata marker (upper 32 bits of __u64)
// "VNBU" in ASCII
#define BUM_META_MARKER 0x564E4255

// XDP: Write BUM metadata before XDP_PASS
// Signals to TC ingress that this packet needs SRv6 encap + clone to remote PE.
// On failure, XDP_PASS still proceeds (local bridge flood works, remote forwarding skipped).
static __always_inline void xdp_write_bum_meta(struct xdp_md *ctx, __u16 vlan_id)
{
    if (bpf_xdp_adjust_meta(ctx, -(int)sizeof(__u64)) == 0) {
        void *data = (void *)(long)ctx->data;
        __u64 *meta = (void *)(long)ctx->data_meta;
        if ((void *)(meta + 1) <= data)
            *meta = ((__u64)BUM_META_MARKER << 32) | vlan_id;
    }
}

// TC: Read BUM metadata from skb->data_meta
// Returns true if BUM marker is present, with vlan_id extracted.
static __always_inline bool tc_read_bum_meta(struct __sk_buff *skb, __u16 *vlan_id)
{
    void *data_meta = (void *)(long)skb->data_meta;
    void *data = (void *)(long)skb->data;
    if (data_meta + sizeof(__u64) > data)
        return false;
    __u64 meta = *(__u64 *)data_meta;
    if ((meta >> 32) != BUM_META_MARKER)
        return false;
    *vlan_id = (__u16)(meta & 0xFFFF);
    return true;
}

#endif // BUM_META_H
