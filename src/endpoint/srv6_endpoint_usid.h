#ifndef SRV6_ENDPOINT_USID_H
#define SRV6_ENDPOINT_USID_H

#include "endpoint/srv6_endpoint_core.h"
#include "endpoint/srv6_endpoint_basic.h"

// ========================================================================
// NEXT-C-SID endpoint behaviors: uN (End, RFC 9800 Sec.4.1.1) and uA
// (End.X, RFC 9800 Sec.4.1.2), F3216 SID structure only (32-bit locator block, 16-bit
// uSIDs). The Argument is everything after the matched SID: bytes [6..15]
// for uN (/48) and bytes [8..15] for uA (/64, node + function). While the
// Argument is non-zero the endpoint shifts it toward the block (16 bits
// for uN, 32 bits for uA), zero-fills the tail, and forwards on the
// updated DA without touching the SRH.
//
// The two shift widths come from one rule, not from two special cases.
// RFC 9800 Sec.4.1.1 N05/N06 copy DA.Argument to bits [LBL..LBL+AL-1] and
// zero the rest, where the Argument starts at LBL+LNFL and LNFL is defined
// as "the sum of the LNL and the FL of the SID". Sec.4.1.2 replaces only
// N08 (forward over the adjacency), leaving the shift untouched. So uN,
// whose SID has no Function, consumes LNL = 16 bits, and uA, whose Function
// identifies the adjacency, consumes LNL + FL = 32.
//
// One execution drawn on the DA, in 16-bit cells (byte offsets on top):
//
//   uN at fd00:aaaa:b002::/48       SID = LBL + LNL,      shift 16
//          0-1    2-3    4-5    6-7    8-9   10-11  12-13  14-15
//        +------+------+------+------+------+------+------+------+
//    in  | fd00 | aaaa | b002 | b003 | d004 | 0000 | 0000 | 0000 |
//        +------+------+------+------+------+------+------+------+
//        |<--- LBL --->|<-LNL>|<-------------- Argument -------->|
//        +------+------+------+------+------+------+------+------+
//   out  | fd00 | aaaa | b003 | d004 | 0000 | 0000 | 0000 | 0000 |
//        +------+------+------+------+------+------+------+------+
//                         ^ Argument lands here              ^ zero fill
//
//   uA at fd00:aaaa:b002:a003::/64  SID = LBL + LNL + FL, shift 32
//          0-1    2-3    4-5    6-7    8-9   10-11  12-13  14-15
//        +------+------+------+------+------+------+------+------+
//    in  | fd00 | aaaa | b002 | a003 | b003 | d004 | 0000 | 0000 |
//        +------+------+------+------+------+------+------+------+
//        |<--- LBL --->|<-LNL>|<-FL->|<---------- Argument ----->|
//        +------+------+------+------+------+------+------+------+
//   out  | fd00 | aaaa | b003 | d004 | 0000 | 0000 | 0000 | 0000 |
//        +------+------+------+------+------+------+------+------+
//                         ^ same landing spot         ^ zero fill (2 cells)
//
// The hop limit is decremented once per logical uN/uA execution (RFC 9800
// Sec.4.1.1 pseudocode N02-N08); an exhausted hop limit drops without
// ICMPv6 generation, matching the other End behaviors here. A zero Argument
// means the container ended on this node and processing falls through to
// classic End / End.X.
//
// Deployment constraint: a uN entry is a /48 and a uA entry a /64, so
// every address inside that prefix except the SID itself carries a
// non-zero Argument and is therefore treated as a container and shifted,
// whatever its upper-layer protocol. The prefix has to be dedicated to
// uSID. A loopback or interface address numbered inside it (the classic
// SRv6 habit of putting the node address in the locator) stops being
// reachable the moment the entry is installed, because its traffic is
// rewritten and forwarded instead of delivered locally.
// ========================================================================

#define USID_F3216_BLOCK_BYTES 4
// Argument offsets within the DA for the two supported SID shapes.
#define USID_UN_ARG_OFF 6   // uN: after LBL(4) + LNL(2)
#define USID_UA_ARG_OFF 8   // uA: after LBL(4) + LNL(2) + FL(2)
// An F3216 container carries at most 6 uSIDs, so at most 5 shifts can
// resolve to this same node before the Argument must hit zero.
#define USID_SHIFT_MAX 5
// Sentinel returned by the uN/uT cores instead of an XDP action (0..4)
// when a no-SRH container ends here with the USD flavor: the tailcall
// body owns the decap helpers, so the core only signals the decision.
#define USID_RET_USD_NOSRH 0x7f

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
// LNFL tail (RFC 9800 Sec.4.1.1 / Sec.4.1.2: uN consumes 16 bits, uA
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

// uN shift loop (uA shifts exactly once and forwards over its
// adjacency instead). RFC 9800 Sec.4.1.1 submits the shifted DA to the
// IPv6 FIB; on this node that FIB step can resolve to another local SID,
// which XDP cannot reach by forwarding to itself, so local re-matches are
// handled directly: the SAME entry keeps shifting in place, and a
// DIFFERENT local entry (another uN, or a terminal behavior placed as the
// next CSID) is re-dispatched to its own tail-call slot with its own
// entry/aux context.
// Returns:
//   2  the shifted DA belongs to a local SID that cannot run without an
//      SRH; caller hands the packet to the kernel for local delivery
//   1  shifted; caller forwards on the updated DA
//   0  Argument is zero; caller falls through to classic End
//  -1  drop (hop limit exhausted, or the re-dispatch tail call failed)
// Does not return when the re-dispatch tail call succeeds.
static __always_inline int usid_shift_loop(struct xdp_md *ctx,
                                           struct ipv6hdr *ip6h,
                                           const struct sid_function_entry *entry,
                                           __u8 dispatch_type,
                                           __u8 inner_proto,
                                           __u16 l3_offset)
{
    const int arg_off = USID_UN_ARG_OFF;
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
            next->aux_index != entry->aux_index) {
            // Carry over the no-SRH dispatcher's eligibility rule. Most
            // endpoint slots parse whatever follows the IPv6 header as an
            // SRH, so re-dispatching an SRH-less packet into one of them
            // would read the upper-layer header as a Routing header. Only
            // uN/uA and the decap behaviours are safe there; anything else
            // is a local SID whose packet the kernel should deliver.
            if (dispatch_type == DISPATCH_NOSRH &&
                next->action != SRV6_LOCAL_ACTION_END_UN &&
                next->action != SRV6_LOCAL_ACTION_END_UA &&
                next->action != SRV6_LOCAL_ACTION_END_UT &&
                inner_proto != IPPROTO_IPIP &&
                inner_proto != IPPROTO_IPV6 &&
                inner_proto != IPPROTO_ETHERNET)
                return 2;
            if (tailcall_ctx_write_sid(next, l3_offset, dispatch_type,
                                       inner_proto, next->action) == 0)
                bpf_tail_call(ctx, &sid_endpoint_progs, next->action);
            return -1; // empty slot or ctx write failure: fail closed
        }
        // The same uN entry again: keep shifting.
    }
    // An F3216 container holds up to 6 uSIDs of this same entry: after the
    // 5th shift the Argument must be zero, which is the classic End
    // fall-through, not a drop.
    return usid_arg_is_zero(da, arg_off) ? 0 : -1;
}

// Forward on the shifted DA. dst == NULL looks up the DA itself (uN);
// otherwise dst is the uA nexthop. Fail closed on a routing failure: the
// DA was rewritten, so handing the packet to the kernel would forward a
// half-processed container.
//
// NO_NEIGH is not a routing failure: the route exists and only its
// neighbour is unresolved. XDP cannot emit a Neighbor Solicitation, so
// dropping there black-holes the flow until unrelated traffic happens to
// resolve the neighbour. uN hands those packets to the kernel instead,
// which resolves the neighbour and forwards on the already-shifted DA --
// the same thing classic End does. The hop limit this execution consumed is
// given back first, because ip6_forward decrements again on the way out;
// without that, a packet that arrived with a hop limit of 2 would be
// answered with Time Exceeded after a single logical uN hop.
//
// uA cannot do that: it forwards over a configured adjacency, and the
// kernel would route by the DA instead, which is a different next hop (in
// a lab where the shifted DA has no route at all, an ICMPv6 unreachable
// comes back rather than the packet). So uA stays fail-closed on
// NO_NEIGH; its next hop must be a resolved neighbour, exactly like
// classic End.X.
static __always_inline int usid_forward(struct xdp_md *ctx, void *dst,
                                        __u16 l3_offset, __u32 fib_ifindex)
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
                                    fib_ifindex);
    if (r == FIB_RESULT_REDIRECT)
        return bpf_redirect(out_ifindex, 0);
    // dst == NULL means the lookup key was the DA itself (uN), so the
    // kernel repeats exactly this forwarding decision -- but only when the
    // lookup ran in the ingress context. A uT VRF lookup is one the kernel
    // would not repeat (it routes by the ingress interface's VRF
    // membership), so uT stays fail-closed on NO_NEIGH.
    if (r == FIB_RESULT_NO_NEIGH && dst == NULL &&
        fib_ifindex == ctx->ingress_ifindex) {
        ip6h->hop_limit++;
        return XDP_PASS;
    }
    return XDP_DROP;
}

// uN / uT core, shared by the SRH and no-SRH dispatch paths. uT
// (RFC 9800 Sec.4.1.3) is uN with the FIB lookup bound to a table: same
// SID shape (/48), same shift, same loop; only the forwarding context and
// the classic fall-through differ. is_ut is a literal 0/1 at each call
// site, so the dead branch folds away and neither tailcall program carries
// the other behavior's code.
static __always_inline int process_end_un_core(
    struct xdp_md *ctx,
    struct sid_function_entry *entry,
    struct sid_aux_entry *aux,
    int is_ut,
    __u8 dispatch_type,
    __u8 inner_proto,
    __u16 l3_offset)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ipv6hdr *ip6h = (struct ipv6hdr *)(data + l3_offset);
    if ((void *)(ip6h + 1) > data_end)
        return XDP_DROP;

    int r = usid_shift_loop(ctx, ip6h, entry, dispatch_type, inner_proto, l3_offset);
    if (r < 0)
        return XDP_DROP;
    if (r == 1)
        return usid_forward(ctx, NULL, l3_offset,
                            is_ut ? aux_vrf_or_ingress_ifindex(aux, ctx)
                                  : ctx->ingress_ifindex);
    if (r == 2) {
        // The shifted DA is a local SID that needs an SRH this packet does
        // not have. The kernel owns that address, so let it decide.
        return XDP_PASS;
    }

    // Argument == 0: the container ends here.
    if (dispatch_type == DISPATCH_NOSRH) {
        // USD at the end of a reduced-encaps container (H.Encaps.Red with
        // a single container emits no SRH): decap the outer IPv6 and
        // forward the inner packet, exactly what endpoint_handle_usd does
        // on the SRH path at SL=0. Only tunnelled payloads qualify; for
        // anything else USD has nothing to decap and falls through to the
        // upper-layer delivery below.
        if (entry->flavor == SRV6_LOCAL_FLAVOR_USD &&
            (inner_proto == IPPROTO_IPIP || inner_proto == IPPROTO_IPV6))
            return USID_RET_USD_NOSRH;
        // No SRH and nothing left to consume, so this is classic End with
        // no segment list: RFC 8986 Sec.4.1 hands the packet to the upper
        // layer, i.e. to the kernel. Two shapes reach this point.
        //
        //   1. Zero shifts: the DA is the bare uN SID itself (plain
        //      traffic addressed to the node, e.g. a control-plane
        //      session). The packet is unmodified.
        //   2. One or more shifts: the container listed only this node's
        //      uSIDs, so the DA has been rewritten down to the bare uN
        //      SID and the hop limit is lower.
        //
        // In both shapes the DA that the kernel sees is this node's own uN
        // SID, which is why passing a rewritten packet up is safe here and
        // nowhere else. It does assume the bare uN SID is configured as a
        // local address on this node; without it the kernel routes the
        // packet by the locator prefix instead of delivering it.
        return XDP_PASS;
    }

    void *srh_ptr = (void *)(ip6h + 1);
    if (srh_ptr + 8 > data_end)
        return XDP_DROP;
    struct ipv6_sr_hdr *srh = (struct ipv6_sr_hdr *)srh_ptr;
    if (is_ut)
        return process_end_t(ctx, ip6h, srh, entry, aux, l3_offset);
    return process_end(ctx, ip6h, srh, entry, l3_offset);
}

// uA core: one shift per execution, forwarding over the aux nexthop;
// a zero Argument falls through to classic End.X.
static __always_inline int process_end_ua_core(
    struct xdp_md *ctx,
    struct sid_function_entry *entry,
    struct sid_aux_entry *aux,
    __u8 dispatch_type,
    __u8 inner_proto,
    __u16 l3_offset)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ipv6hdr *ip6h = (struct ipv6hdr *)(data + l3_offset);
    if ((void *)(ip6h + 1) > data_end)
        return XDP_DROP;

    // uA never re-consumes in place: every execution is one shift followed
    // by an End.X forward over the configured adjacency, so a container
    // listing the same uA twice must traverse the adjacency twice
    // (RFC 9800 Sec.4.1.2), unlike uN's FIB-to-self problem.
    __u8 *da = (__u8 *)&ip6h->daddr;
    if (!usid_arg_is_zero(da, USID_UA_ARG_OFF)) {
        if (ip6h->hop_limit <= 1)
            return XDP_DROP;
        ip6h->hop_limit--;
        usid_shift(da, USID_UA_ARG_OFF);
        return usid_forward(ctx, aux->usid.nexthop, l3_offset,
                            ctx->ingress_ifindex);
    }

    // Nothing was shifted on this path (uA returns above whenever it
    // shifts), so the DA is the bare uA SID and the packet is unmodified:
    // classic End.X with no segment list. With the USD flavor and a
    // tunnelled payload the outer header is stripped and the exposed
    // packet forwarded over the adjacency (the tailcall body owns the
    // decap helpers, hence the sentinel); anything else goes to the
    // kernel for local delivery.
    if (dispatch_type == DISPATCH_NOSRH) {
        if (entry->flavor == SRV6_LOCAL_FLAVOR_USD &&
            (inner_proto == IPPROTO_IPIP || inner_proto == IPPROTO_IPV6))
            return USID_RET_USD_NOSRH;
        return XDP_PASS;
    }

    void *srh_ptr = (void *)(ip6h + 1);
    if (srh_ptr + 8 > data_end)
        return XDP_DROP;
    struct ipv6_sr_hdr *srh = (struct ipv6_sr_hdr *)srh_ptr;
    return process_end_x(ctx, ip6h, srh, entry, aux, l3_offset);
}

#endif // SRV6_ENDPOINT_USID_H
