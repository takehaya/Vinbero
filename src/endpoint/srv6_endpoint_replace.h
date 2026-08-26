#ifndef SRV6_ENDPOINT_REPLACE_H
#define SRV6_ENDPOINT_REPLACE_H

#include "endpoint/srv6_endpoint_core.h"
#include "endpoint/srv6_endpoint_usid.h"
#include "headend/srv6_headend_utils.h"

// ========================================================================
// REPLACE-C-SID endpoint behaviors: End and End.X with the REPLACE-CSID
// flavor (RFC 9800 Sec.4.2.1 / 4.2.2).
//
// A REPLACE-C-SID sequence starts with a fully formed 128-bit SID in the
// DA and continues with packed containers in the SRH segment list: each
// 128-bit entry is split into K = 128/LNFL positions of LNFL bits, filled
// from the least significant position (K-1) upward, zero-padded below.
// The DA's Argument carries the index of the current position in its
// least significant ceil(log2(K)) bits, and the endpoint replaces only
// the C-SID part of the DA (bits [LBL..LBL+LNFL-1]) while walking a
// container. Crossing to the next container replaces the C-SID and
// resets the index to K-1; the full 128-bit DA reload happens only when
// a container ends early on a zero C-SID (R06-R10), because the next
// segment list entry is then a fully formed SID rather than a packed
// container.
//
// One execution on the DA for LNFL=32 (K=4), LBL=48:
//
//           0..5          6..9         10..14       15 (low bits)
//        +-----------+------------+--------------+------+
//    in  |   block   |   C-SID a  |   Argument   | Idx  |
//        +-----------+------------+--------------+------+
//    out |   block   |   C-SID b  |   Argument   | Idx' |
//        +-----------+------------+--------------+------+
//                       ^ replaced from SegList[SL][Idx']  (Idx' = Idx-1)
//
// Differences from the RFC pseudocode, shared with the rest of this
// codebase: no ICMPv6 generation (R03/R14 and hop-limit exhaustion are
// silent drops), and the segment list is bounded both by MAX_SEGMENTS
// and by the declared Hdr Ext Len -- data_end alone is not enough,
// because payload bytes follow the SRH and an inflated Last Entry would
// otherwise let them be read as C-SIDs.
//
// LNFL is 32 (mandatory) or 16 (optional) per RFC 9800; csid_bytes is a
// compile-time literal (4 or 2) at every call site so all offsets and
// masks fold. LBL is byte-aligned and carried in the aux
// (block_len_bytes); it is bounded so the C-SID write and the index bits
// in byte 15 never overlap.
// ========================================================================

// Read the C-SID at position `pos` of Segment List entry `sl` into a
// zeroed 4-byte buffer. Position 0 is the most significant LNFL bits
// (IETF bit order), so the byte offset is simply pos * csid_bytes.
static __always_inline int replace_read_csid(
    struct ipv6_sr_hdr *srh, void *data_end,
    __u8 sl, __u8 pos, int csid_bytes, __u32 *out)
{
    if (sl >= MAX_SEGMENTS)
        return -1;
    if (pos >= 16 / csid_bytes)
        return -1;
    // Bound the exact access pointer: the verifier does not connect a
    // range check on (sl+1)*16 to a later access at sl*16 + pos*L.
    void *p = (void *)srh + 8 + (sl * 16) + (pos * csid_bytes);
    if (p + csid_bytes > data_end)
        return -1;
    *out = 0;
    __builtin_memcpy(out, p, csid_bytes);
    return 0;
}

// Write the C-SID into bits [LBL..LBL+LNFL-1] of the DA. The block
// length is re-read and re-bounded here, adjacent to the store: the
// verifier loses the earlier range check once the value is spilled
// across the intervening branches.
static __always_inline int replace_write_csid(
    __u8 *da, void *data_end, struct sid_aux_entry *aux, __u32 c,
    int csid_bytes)
{
    // The & 0xf bounds the value through var_off (clang rewrites the
    // comparison below into a subtract-and-mask form the verifier cannot
    // narrow from), and the derived variable-offset pointer needs its own
    // data_end check regardless of the fixed-offset checks made earlier.
    __u8 bl = aux->usid.block_len_bytes & 0xf;
    if (bl < 1 || bl > 15 - csid_bytes)
        return -1;
    __u8 *p = da + bl;
    if ((void *)(p + csid_bytes) > data_end)
        return -1;
    __builtin_memcpy(p, &c, csid_bytes);
    return 0;
}

// PSP inserted after R20 (RFC 9800 Sec.4.2.8): pop the SRH when the next
// execution would be the container end, i.e. R20.1's condition
// "SL == 0 and (Index == 0 or SegList[0][Index-1] == 0)".
// Returns 1 when the SRH was popped, 0 when PSP does not apply, -1 on
// failure.
static __always_inline int replace_maybe_psp(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6h,
    struct ipv6_sr_hdr *srh,
    struct sid_function_entry *entry,
    int csid_bytes,
    __u16 l3_offset)
{
    if (entry->flavor != SRV6_LOCAL_FLAVOR_PSP)
        return 0;
    if (srh->segments_left != 0)
        return 0;
    void *data_end = (void *)(long)ctx->data_end;
    __u8 idx = ((__u8 *)&ip6h->daddr)[15] & ((16 / csid_bytes) - 1);
    if (idx != 0) {
        __u32 c;
        if (replace_read_csid(srh, data_end, 0, idx - 1, csid_bytes, &c) != 0)
            return -1;
        if (c != 0)
            return 0;
    }
    if (endpoint_strip_srh_at(ctx, ip6h, srh, entry, l3_offset) != 0)
        return -1;
    return 1;
}

// The DA produced by an advance can belong to a local SID -- another
// REPLACE entry on this node (consecutive same-node C-SIDs), the same
// entry again, or a terminal behavior. XDP cannot reach it by forwarding
// to itself, so re-dispatch it to its own tail-call slot with its own
// entry/aux context, exactly like uN's shift loop does. The caller
// applies its own PSP first, so the dispatch shape follows the packet:
// DISPATCH_LOCALSID while the SRH is present, DISPATCH_NOSRH with the
// packet's nexthdr after a pop. Pointers are re-derived here because a
// pop moves the packet.
//
// Each same-node C-SID costs one tail call, so a chain longer than the
// kernel's tail-call limit (33) fails closed partway -- the REPLACE
// analogue of uN's USID_SHIFT_MAX bound. uN can loop in place because
// one /48 entry covers every uSID of the node; REPLACE C-SIDs are
// distinct entries with distinct aux, so the chain has to go through the
// dispatcher. More than 33 consecutive C-SIDs on one node is far outside
// any real container plan.
//
// Returns 0 when no local entry matched (caller forwards by FIB); does
// not return when the tail call succeeds; -1 on failure (fail closed).
static __always_inline int replace_local_redispatch(
    struct xdp_md *ctx, int srh_present, __u16 l3_offset)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ipv6hdr *ip6h = (struct ipv6hdr *)(data + l3_offset);
    if ((void *)(ip6h + 1) > data_end)
        return -1;
    struct lpm_key_v6 key = { .prefixlen = 128 };
    __builtin_memcpy(key.addr, &ip6h->daddr, IPV6_ADDR_LEN);
    struct sid_function_entry *next =
        bpf_map_lookup_elem(&sid_function_map, &key);
    if (!next)
        return 0;
    __u8 dispatch = srh_present ? DISPATCH_LOCALSID : DISPATCH_NOSRH;
    __u8 inner = srh_present ? 0 : ip6h->nexthdr;
    if (tailcall_ctx_write_sid(next, l3_offset, dispatch,
                               inner, next->action) == 0)
        bpf_tail_call(ctx, &sid_endpoint_progs, next->action);
    return -1; // empty slot or ctx write failure: fail closed
}

// End / End.X with REPLACE-CSID, shared core. is_endx and csid_bytes are
// literals at every call site (the dead branches fold away).
static __always_inline int process_end_replace_core(
    struct xdp_md *ctx,
    struct sid_function_entry *entry,
    struct sid_aux_entry *aux,
    int is_endx,
    int csid_bytes,
    __u8 dispatch_type,
    __u8 inner_proto,
    __u16 l3_offset)
{
    const __u8 idx_mask = (16 / csid_bytes) - 1; // K-1; K is a power of 2

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ipv6hdr *ip6h = (struct ipv6hdr *)(data + l3_offset);
    if ((void *)(ip6h + 1) > data_end)
        return XDP_DROP;

    __u8 *da = (__u8 *)&ip6h->daddr;
    __u8 idx = da[15] & idx_mask;
    __u8 bl = aux->usid.block_len_bytes;
    // The C-SID write lands at [bl..bl+csid_bytes) and the index bits live
    // in byte 15; keep them disjoint and the block non-empty.
    if (bl < 1 || bl + csid_bytes > 15)
        return XDP_DROP;

    if (dispatch_type == DISPATCH_NOSRH) {
        // A REPLACE-CSID flavor SID can be the last C-SID of a
        // reduced-encaps packet. RFC 9800 Sec.4.2: with no SRH the index
        // in the Argument is ignored and the upper-layer header is
        // processed. End.X terminal delivery goes to the kernel like uA
        // (no adjacency-keyed decap; see process_end_ua_core).
        if (!is_endx &&
            entry->flavor == SRV6_LOCAL_FLAVOR_USD &&
            (inner_proto == IPPROTO_IPIP || inner_proto == IPPROTO_IPV6))
            return USID_RET_USD_NOSRH;
        return XDP_PASS;
    }

    void *srh_ptr = (void *)(ip6h + 1);
    if (srh_ptr + 8 > data_end)
        return XDP_DROP;
    struct ipv6_sr_hdr *srh = (struct ipv6_sr_hdr *)srh_ptr;
    __u8 sl = srh->segments_left;
    __u8 last = srh->first_segment;

    // R02/R13 sanity beyond the data_end checks: the segment list reads
    // below must stay inside the declared SRH, or payload bytes following
    // a short SRH could be read as C-SIDs through an inflated Last Entry
    // (Hdr Ext Len is in 8-octet units; each entry is 16 bytes).
    if (last >= MAX_SEGMENTS || srh->hdrlen < 2 * (last + 1))
        return XDP_DROP;

    // S02: the C-SID sequence ends here when SL is consumed and the
    // current container has nothing left below the index.
    if (sl == 0) {
        int terminal = (idx == 0);
        if (!terminal) {
            __u32 c;
            if (replace_read_csid(srh, data_end, 0, idx - 1, csid_bytes, &c) != 0)
                return XDP_DROP;
            terminal = (c == 0);
        }
        if (terminal) {
            // USD applies only to tunnelled payloads (RFC 8986 Sec.4.16.3
            // keeps normal upper-layer processing otherwise, so e.g. an
            // ICMPv6 ping to the SID itself still reaches the kernel).
            if (entry->flavor == SRV6_LOCAL_FLAVOR_USD &&
                (srh->nexthdr == IPPROTO_IPIP || srh->nexthdr == IPPROTO_IPV6))
                return endpoint_handle_usd(ctx, ip6h, srh, entry,
                                           ctx->ingress_ifindex, l3_offset);
            if (entry->flavor == SRV6_LOCAL_FLAVOR_USP)
                return endpoint_handle_usp(ctx, ip6h, srh, entry,
                                           ctx->ingress_ifindex, l3_offset);
            return XDP_PASS;
        }
    }

    // The sequence advances: this node is a hop and spends a hop limit
    // (same convention as endpoint_common_processing: exhaustion is a
    // silent drop, no ICMPv6).
    if (ip6h->hop_limit <= 1)
        return XDP_DROP;

    if (idx != 0) {
        // R01-R11: keep walking the current container.
        if (sl > last)
            return XDP_DROP;
        idx--;
        __u32 c;
        if (replace_read_csid(srh, data_end, sl, idx, csid_bytes, &c) != 0)
            return XDP_DROP;
        if (c == 0) {
            // R06-R10: container exhausted early; load the next SID as a
            // full 128-bit DA (its own Argument replaces the index bits).
            if (sl == 0)
                return XDP_DROP; // S02 would have terminated; malformed
            __u8 nsl = sl - 1;
            void *seg_base = (void *)srh + 8;
            if (copy_segment_by_index(da, seg_base, data_end, nsl) != 0)
                return XDP_DROP;
            srh->segments_left = nsl;
            ip6h->hop_limit--;
            // PSP inserted after R09 (RFC 9800 Sec.4.2.8) runs first --
            // it is this entry's own obligation and must not be skipped
            // when the loaded SID happens to live on this node. The
            // re-dispatch then follows the packet's post-PSP shape. End.X
            // forwards over the adjacency instead of by the DA, so only
            // End(REP) can land on itself.
            int stripped = 0;
            if (nsl == 0 && entry->flavor == SRV6_LOCAL_FLAVOR_PSP) {
                if (endpoint_strip_srh_at(ctx, ip6h, srh, entry, l3_offset) != 0)
                    return XDP_DROP;
                stripped = 1;
            }
            if (!is_endx &&
                replace_local_redispatch(ctx, !stripped, l3_offset) != 0)
                return XDP_DROP;
            return usid_forward(ctx, is_endx ? aux->usid.nexthop : NULL,
                                l3_offset, ctx->ingress_ifindex);
        }
        // R19-R21: replace the C-SID part of the DA in place.
        da[15] = (da[15] & ~idx_mask) | idx;
        ip6h->hop_limit--;
        if (replace_write_csid(da, data_end, aux, c, csid_bytes) != 0)
            return XDP_DROP;
    } else {
        // R12-R18: cross into the next packed container.
        if (sl > last + 1)
            return XDP_DROP;
        if (sl == 0)
            return XDP_DROP; // S02 would have terminated; malformed
        __u8 nsl = sl - 1;
        idx = idx_mask; // K-1
        __u32 c;
        if (replace_read_csid(srh, data_end, nsl, idx, csid_bytes, &c) != 0)
            return XDP_DROP;
        // Position K-1 of a packed container is its first C-SID, which a
        // well-formed sequence never leaves zero (the reserved
        // terminator); forwarding on it would write an unroutable C-SID
        // into the DA, so treat it as malformed.
        if (c == 0)
            return XDP_DROP;
        srh->segments_left = nsl;
        da[15] = (da[15] & ~idx_mask) | idx;
        ip6h->hop_limit--;
        if (replace_write_csid(da, data_end, aux, c, csid_bytes) != 0)
            return XDP_DROP;
    }

    // PSP (the R20 insertion point) runs before the local re-dispatch for
    // the same reason as in the R09 branch above: the pop is this entry's
    // own step, whatever node the next C-SID lives on.
    int r = replace_maybe_psp(ctx, ip6h, srh, entry, csid_bytes, l3_offset);
    if (r < 0)
        return XDP_DROP;
    if (!is_endx && replace_local_redispatch(ctx, r == 0, l3_offset) != 0)
        return XDP_DROP;
    return usid_forward(ctx, is_endx ? aux->usid.nexthop : NULL,
                        l3_offset, ctx->ingress_ifindex);
}

#endif // SRV6_ENDPOINT_REPLACE_H
