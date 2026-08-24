#ifndef SRV6_ENDPOINT_USID_H
#define SRV6_ENDPOINT_USID_H

#include "endpoint/srv6_endpoint_core.h"
#include "endpoint/srv6_endpoint_basic.h"

// ========================================================================
// NEXT-C-SID endpoint behaviors: uN (End) and uA (End.X), RFC 9800 Sec.4.1
// and Sec.4.2, F3216 SID structure only (32-bit locator block, 16-bit
// uSIDs). The Argument is everything after the matched SID: bytes [6..15]
// for uN (/48) and bytes [8..15] for uA (/64, node + function). While the
// Argument is non-zero the endpoint shifts it toward the block (16 bits
// for uN, 32 bits for uA), zero-fills the tail, and forwards on the
// updated DA without touching the SRH. The hop limit is decremented once per
// logical uN/uA execution (RFC 9800 Sec.4.1.1 pseudocode N02-N08); an
// exhausted hop limit drops without ICMPv6 generation, matching the other
// End behaviors here. A zero Argument means the container ended on this
// node and processing falls through to classic End / End.X.
// ========================================================================

#define USID_F3216_BLOCK_BYTES 4
// Argument offsets within the DA for the two supported SID shapes.
#define USID_UN_ARG_OFF 6   // uN: after LBL(4) + LNL(2)
#define USID_UA_ARG_OFF 8   // uA: after LBL(4) + LNL(2) + FL(2)
// An F3216 container carries at most 6 uSIDs, so at most 5 shifts can
// resolve to this same node before the Argument must hit zero.
#define USID_SHIFT_MAX 5

// The Argument starts where the matched SID ends: byte 6 for uN
// (LBL+LNL = /48) and byte 8 for uA (LBL+LNL+FL = /64). arg_off is a
// compile-time constant at every call site so the memcpy lengths fold.
static __always_inline int usid_arg_is_zero(const __u8 *da, int arg_off)
{
    __u64 hi;
    __u16 lo = 0;
    if (arg_off == USID_UA_ARG_OFF) {
        __builtin_memcpy(&hi, da + USID_UA_ARG_OFF, sizeof(hi));
    } else {
        __builtin_memcpy(&hi, da + USID_UN_ARG_OFF, sizeof(hi));
        __builtin_memcpy(&lo, da + 14, sizeof(lo));
    }
    return (hi | lo) == 0;
}

// Shift the whole Argument toward the block and zero-fill the vacated
// LNFL tail (RFC 9800 Sec.4.1.1 / Sec.4.2.1: uN consumes 16 bits, uA
// consumes its node + function, 32 bits).
static __always_inline void usid_shift(__u8 *da, int arg_off)
{
    if (arg_off == USID_UA_ARG_OFF) {
        __u8 tmp[8];
        __builtin_memcpy(tmp, da + USID_UA_ARG_OFF, sizeof(tmp));
        __builtin_memcpy(da + 4, tmp, sizeof(tmp));
        __builtin_memset(da + 12, 0, 4);
    } else {
        __u8 tmp[10];
        __builtin_memcpy(tmp, da + USID_UN_ARG_OFF, sizeof(tmp));
        __builtin_memcpy(da + 4, tmp, sizeof(tmp));
        da[14] = 0;
        da[15] = 0;
    }
}

// Shift loop shared by uN and uA. Consecutive uSIDs of the SAME entry
// (a container listing this node's uN twice) are consumed in place by
// re-matching the shifted DA against sid_function_map, because XDP cannot
// re-enter itself on the same packet and forwarding to ourselves would
// hand the mutated DA to the kernel. A shift that lands on any OTHER
// local entry (a different uN/uA, or a terminal SID) would need that
// entry's action and aux to be honored, which this tail-call target
// cannot re-dispatch, so it fails closed instead of silently applying
// the wrong behavior.
// Returns:
//   1  shifted; caller forwards on the updated DA
//   0  Argument is zero; caller falls through to classic End / End.X
//  -1  drop (hop limit exhausted, or the shift landed on a different
//      local SID that cannot be re-dispatched from here)
static __always_inline int usid_shift_loop(struct ipv6hdr *ip6h,
                                           const struct sid_function_entry *entry,
                                           int arg_off)
{
    __u8 *da = (__u8 *)&ip6h->daddr;

    for (int i = 0; i < USID_SHIFT_MAX; i++) {
        if (usid_arg_is_zero(da, arg_off))
            return 0;

        if (ip6h->hop_limit <= 1)
            return -1;
        ip6h->hop_limit--;

        usid_shift(da, arg_off);

        struct lpm_key_v6 key = { .prefixlen = 128 };
        __builtin_memcpy(key.addr, da, IPV6_ADDR_LEN);
        struct sid_function_entry *next =
            bpf_map_lookup_elem(&sid_function_map, &key);
        if (!next)
            return 1;
        if (next->action != entry->action ||
            next->aux_index != entry->aux_index)
            return -1;
        // The same uN/uA entry again: keep shifting.
    }
    // An F3216 container holds up to 6 uSIDs of this same entry: after the
    // 5th shift the Argument must be zero, which is the classic End
    // fall-through, not a drop.
    return usid_arg_is_zero(da, arg_off) ? 0 : -1;
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

    int r = usid_shift_loop(ip6h, entry, USID_UN_ARG_OFF);
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

    int r = usid_shift_loop(ip6h, entry, USID_UA_ARG_OFF);
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
