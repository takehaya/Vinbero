#ifndef XDP_REDIRECT_H
#define XDP_REDIRECT_H

// XDP redirect to a device, for every redirect of the main program.
//
// xdp-mode BUM replication in native XDP (l2vpn/bum_xdp.h) runs one devmap
// egress program on the remote copies. Native XDP queues redirected frames
// per CPU and output device until the end of the NAPI poll, and the queue
// runs the egress program of the first frame queued (kernel/bpf/devmap.c,
// bq_enqueue) on all of them. A plain bpf_redirect to an uplink that lands
// first in a poll would make that poll's BUM copies leave without their
// encapsulation. So in that mode every redirect to an uplink goes through
// uplink_tx_map, whose entries carry the same egress program; it passes the
// frames that are not BUM copies through untouched.
//
// Not included by plugins (the SDK headers do not pull it in).

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Loader-set: 1 when xdp-mode BUM replication runs in native XDP. With 0,
// xdp_redirect_dev is a plain bpf_redirect.
const volatile __u8 bum_xdp_native = 0;

// ifindex -> {ifindex, bum_remote_egress}, one entry per uplink of an
// xdp-mode BD. The control plane adds an uplink before the first BD devmap
// that sends through it.
#define UPLINK_TX_MAX_ENTRIES 256

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
    __uint(max_entries, UPLINK_TX_MAX_ENTRIES);
    __type(key, __u32);
    __uint(value_size, sizeof(struct bpf_devmap_val));
} uplink_tx_map SEC(".maps");

static __always_inline long xdp_redirect_dev(__u32 ifindex)
{
    if (bum_xdp_native) {
        // XDP_PASS on a miss: the device is not an uplink.
        long act = bpf_redirect_map(&uplink_tx_map, ifindex, XDP_PASS);
        if (act != XDP_PASS)
            return act;
    }
    return bpf_redirect(ifindex, 0);
}

// Drop the metadata a frame arrived with. A frame redirected in from
// another native XDP program keeps that program's metadata, and the BUM
// egress program must only ever see metadata this program wrote.
static __always_inline void xdp_meta_clear(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *meta = (void *)(long)ctx->data_meta;
    if (meta < data)
        bpf_xdp_adjust_meta(ctx, (int)(data - meta));
}

#endif // XDP_REDIRECT_H
