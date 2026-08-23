#ifndef SRV6_ENDPOINT_USID_H
#define SRV6_ENDPOINT_USID_H

#include "endpoint/srv6_endpoint_core.h"
#include "endpoint/srv6_endpoint_basic.h"

// ========================================================================
// NEXT-C-SID endpoint behaviors: uN (End) and uA (End.X), RFC 9800 Sec.4.1
// and Sec.4.2, F3216 SID structure only (32-bit locator block, 16-bit
// uSIDs). The active uSID sits at DA bytes [4..5]; the Argument is DA
// bytes [6..15]. While the Argument is non-zero the endpoint shifts it 16
// bits toward the block, zero-fills the tail, and forwards on the updated
// DA without touching the SRH. The hop limit is decremented once per
// logical uN/uA execution (RFC 9800 Sec.4.1.1 pseudocode N02-N08); an
// exhausted hop limit drops without ICMPv6 generation, matching the other
// End behaviors here. A zero Argument means the container ended on this
// node and processing falls through to classic End / End.X.
// ========================================================================

#define USID_F3216_BLOCK_BYTES 4
// An F3216 container carries at most 6 uSIDs, so at most 5 shifts can
// resolve to this same node before the Argument must hit zero.
#define USID_SHIFT_MAX 5

// F3216 Argument (DA bytes [6..15]) == 0?
static __always_inline int usid_arg_is_zero(const __u8 *da)
{
    __u64 hi;
    __u16 lo;
    __builtin_memcpy(&hi, da + 6, sizeof(hi));
    __builtin_memcpy(&lo, da + 14, sizeof(lo));
    return (hi | lo) == 0;
}

// Shift the Argument 16 bits toward the block and zero-fill the tail
// (RFC 9800 Sec.4.1.1 N04-N06 for LNFL=16).
static __always_inline void usid_shift(__u8 *da)
{
    __u8 tmp[10];
    __builtin_memcpy(tmp, da + 6, sizeof(tmp));
    __builtin_memcpy(da + 4, tmp, sizeof(tmp));
    da[14] = 0;
    da[15] = 0;
}

// Shift loop shared by uN and uA. Consecutive uSIDs of this node are
// consumed in place (re-matching the shifted DA against sid_function_map)
// instead of bouncing through the FIB back to ourselves, which XDP cannot
// re-enter on the same packet.
// Returns:
//   1  shifted; caller forwards on the updated DA
//   0  Argument is zero; caller falls through to classic End / End.X
//  -1  drop (hop limit exhausted, or the shift landed on a local terminal
//      SID that cannot be re-dispatched from here; the DA is already
//      mutated so failing closed keeps the packet off the kernel stack)
static __always_inline int usid_shift_loop(struct ipv6hdr *ip6h)
{
    __u8 *da = (__u8 *)&ip6h->daddr;

    for (int i = 0; i < USID_SHIFT_MAX; i++) {
        if (usid_arg_is_zero(da))
            return 0;

        if (ip6h->hop_limit <= 1)
            return -1;
        ip6h->hop_limit--;

        usid_shift(da);

        struct lpm_key_v6 key = { .prefixlen = 128 };
        __builtin_memcpy(key.addr, da, IPV6_ADDR_LEN);
        struct sid_function_entry *next =
            bpf_map_lookup_elem(&sid_function_map, &key);
        if (!next)
            return 1;
        if (next->action != SRV6_LOCAL_ACTION_END_UN &&
            next->action != SRV6_LOCAL_ACTION_END_UA)
            return -1;
        // Another local uN/uA uSID: keep shifting.
    }
    return -1;
}

// Forward on the shifted DA. dst == NULL looks up the DA itself (uN);
// otherwise dst is the uA nexthop. Fail closed on anything but a
// successful redirect: the DA was rewritten, so handing the packet to the
// kernel would forward a half-processed container.
static __always_inline int usid_forward(struct xdp_md *ctx, void *dst,
                                        __u16 l3_offset)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;
    struct ipv6hdr *ip6h = (struct ipv6hdr *)(data + l3_offset);
    if ((void *)(ip6h + 1) > data_end)
        return XDP_DROP;

    __u32 out_ifindex;
    int r = srv6_fib_lookup_v6_core(ctx, ip6h, eth, &out_ifindex,
                                    dst ? dst : &ip6h->daddr,
                                    ctx->ingress_ifindex);
    if (r == FIB_RESULT_REDIRECT)
        return bpf_redirect(out_ifindex, 0);
    return XDP_DROP;
}

// uN core, shared by the SRH and no-SRH dispatch paths.
static __always_inline int process_end_un_core(
    struct xdp_md *ctx,
    struct sid_function_entry *entry,
    __u8 dispatch_type,
    __u16 l3_offset)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ipv6hdr *ip6h = (struct ipv6hdr *)(data + l3_offset);
    if ((void *)(ip6h + 1) > data_end)
        return XDP_DROP;

    int r = usid_shift_loop(ip6h);
    if (r < 0)
        return XDP_DROP;
    if (r == 1)
        return usid_forward(ctx, NULL, l3_offset);

    // Argument == 0: the container ends here.
    if (dispatch_type == DISPATCH_NOSRH) {
        // Plain (non-SR) traffic addressed inside the locator, e.g. a
        // control-plane session to the node address; not ours to consume.
        return XDP_PASS;
    }

    void *srh_ptr = (void *)(ip6h + 1);
    if (srh_ptr + 8 > data_end)
        return XDP_DROP;
    struct ipv6_sr_hdr *srh = (struct ipv6_sr_hdr *)srh_ptr;
    return process_end(ctx, ip6h, srh, entry, l3_offset);
}

// uA core: same as uN but the shift-path forwarding and the classic
// fall-through both use the aux nexthop.
static __always_inline int process_end_ua_core(
    struct xdp_md *ctx,
    struct sid_function_entry *entry,
    struct sid_aux_entry *aux,
    __u8 dispatch_type,
    __u16 l3_offset)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ipv6hdr *ip6h = (struct ipv6hdr *)(data + l3_offset);
    if ((void *)(ip6h + 1) > data_end)
        return XDP_DROP;

    int r = usid_shift_loop(ip6h);
    if (r < 0)
        return XDP_DROP;
    if (r == 1)
        return usid_forward(ctx, aux->usid.nexthop, l3_offset);

    if (dispatch_type == DISPATCH_NOSRH)
        return XDP_PASS;

    void *srh_ptr = (void *)(ip6h + 1);
    if (srh_ptr + 8 > data_end)
        return XDP_DROP;
    struct ipv6_sr_hdr *srh = (struct ipv6_sr_hdr *)srh_ptr;
    return process_end_x(ctx, ip6h, srh, entry, aux, l3_offset);
}

#endif // SRV6_ENDPOINT_USID_H
