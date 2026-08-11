#ifndef SRV6_ECMP_H
#define SRV6_ECMP_H

// ECMP flow hashing and path selection for headend path groups.
// Included from xdp_prog.c after xdp_map.h (needs ecmp_* map declarations).

#include <linux/types.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "core/xdp_prog.h"
#include "core/xdp_map.h"

// ========================================================================
// Jenkins hash (jhash), the same construction the kernel flow dissector
// uses. Fixed seed: path selection only needs per-flow stability on this
// node, and a deterministic seed keeps BPF_PROG_TEST_RUN tests reproducible.
// ========================================================================

#define ECMP_JHASH_INITVAL 0xdeadbeef
#define ECMP_JHASH_SEED    0x76696e62  // "vinb"

#define __ecmp_rol32(x, k) (((x) << (k)) | ((x) >> (32 - (k))))

#define __ecmp_jhash_final(a, b, c)            \
    do {                                        \
        c ^= b; c -= __ecmp_rol32(b, 14);       \
        a ^= c; a -= __ecmp_rol32(c, 11);       \
        b ^= a; b -= __ecmp_rol32(a, 25);       \
        c ^= b; c -= __ecmp_rol32(b, 16);       \
        a ^= c; a -= __ecmp_rol32(c, 4);        \
        b ^= a; b -= __ecmp_rol32(a, 14);       \
        c ^= b; c -= __ecmp_rol32(b, 24);       \
    } while (0)

#define __ecmp_jhash_mix(a, b, c)              \
    do {                                        \
        a -= c; a ^= __ecmp_rol32(c, 4);  c += b; \
        b -= a; b ^= __ecmp_rol32(a, 6);  a += c; \
        c -= b; c ^= __ecmp_rol32(b, 8);  b += a; \
        a -= c; a ^= __ecmp_rol32(c, 16); c += b; \
        b -= a; b ^= __ecmp_rol32(a, 19); a += c; \
        c -= b; c ^= __ecmp_rol32(b, 4);  b += a; \
    } while (0)

static __always_inline __u32 ecmp_jhash_3words(__u32 a, __u32 b, __u32 c, __u32 initval)
{
    a += ECMP_JHASH_INITVAL;
    b += ECMP_JHASH_INITVAL;
    c += initval;
    __ecmp_jhash_final(a, b, c);
    return c;
}

// jhash over the 8 words of an IPv6 src+dst pair (32 bytes), unrolled for
// the fixed length: two 3-word mixes plus a 2-word final.
static __always_inline __u32 ecmp_jhash_addrs6(const __u32 *s, const __u32 *d, __u32 initval)
{
    __u32 a = ECMP_JHASH_INITVAL + (8 << 2) + initval;
    __u32 b = a, c = a;

    a += s[0]; b += s[1]; c += s[2];
    __ecmp_jhash_mix(a, b, c);
    a += s[3]; b += d[0]; c += d[1];
    __ecmp_jhash_mix(a, b, c);
    a += d[2]; b += d[3];
    __ecmp_jhash_final(a, b, c);
    return c;
}

// ========================================================================
// Flow hashing
//
// 5-tuple where the L4 ports are reachable, degrading to a 3-tuple
// {src, dst, proto} for fragments, unknown protocols, and IPv6 packets
// with extension headers (the chain is not chased). TCP, UDP, UDP-Lite,
// SCTP and DCCP all carry {sport, dport} in their first 4 bytes.
// ========================================================================

static __always_inline int ecmp_proto_has_ports(__u8 proto)
{
    return proto == IPPROTO_TCP || proto == IPPROTO_UDP ||
           proto == IPPROTO_UDPLITE || proto == IPPROTO_SCTP ||
           proto == IPPROTO_DCCP;
}

// Hash an IPv4 flow. iph must already be bounds-checked by the caller;
// the L4 port load performs its own check against data_end.
static __always_inline __u32 ecmp_flow_hash_v4(
    struct xdp_md *ctx, struct iphdr *iph, __u16 l3_offset)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    __u32 ports = 0;
    // IP_MF | IP_OFFSET: any fragment (even the first) hashes on the
    // 3-tuple so all fragments of one datagram pick the same path.
    if (ecmp_proto_has_ports(iph->protocol) &&
        (iph->frag_off & bpf_htons(0x3FFF)) == 0) {
        __u32 ihl = iph->ihl;
        if (ihl >= 5 && ihl <= 15) {
            void *l4 = data + l3_offset + ihl * 4;
            if (l4 + 4 <= data_end)
                __builtin_memcpy(&ports, l4, 4);
        }
    }
    __u32 hash = ecmp_jhash_3words(iph->saddr, iph->daddr,
                                   ports ^ ((__u32)iph->protocol << 24),
                                   ECMP_JHASH_SEED);
    // 0 is the "no hash computed" sentinel (endpoint/L2 dispatch), but
    // jhash can legitimately produce it; round to 1 so a hashed flow is
    // never mistaken for an unhashed one.
    return hash ? hash : 1;
}

// Hash an IPv6 flow. ip6h must already be bounds-checked by the caller.
static __always_inline __u32 ecmp_flow_hash_v6(
    struct xdp_md *ctx, struct ipv6hdr *ip6h, __u16 l3_offset)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    __u32 ports = 0;
    __u8 nh = ip6h->nexthdr;
    // Only a directly attached L4 header is parsed; any extension header
    // (fragment, routing, ...) falls back to the 3-tuple.
    if (ecmp_proto_has_ports(nh)) {
        void *l4 = data + l3_offset + sizeof(struct ipv6hdr);
        if (l4 + 4 <= data_end)
            __builtin_memcpy(&ports, l4, 4);
    }
    __u32 addrs = ecmp_jhash_addrs6(ip6h->saddr.in6_u.u6_addr32,
                                    ip6h->daddr.in6_u.u6_addr32,
                                    ECMP_JHASH_SEED);
    __u32 hash = ecmp_jhash_3words(addrs, ports, nh, ECMP_JHASH_SEED);
    // Same sentinel rounding as ecmp_flow_hash_v4.
    return hash ? hash : 1;
}

// Fold a 32-bit flow hash into a 20-bit IPv6 flow label (RFC 6437). A
// non-zero hash always yields a non-zero label so transit routers never
// mistake a hashed flow for an unlabeled one; hash 0 means "no hash
// computed" and keeps today's label-0 encap.
static __always_inline __u32 ecmp_flow_label(__u32 hash)
{
    __u32 label = (hash ^ (hash >> 20)) & 0xFFFFF;
    if (hash != 0 && label == 0)
        label = 1;
    return label;
}

// Hash whatever L3 packet sits at `l3_off`, dispatching on the IP version
// nibble. Unlike ecmp_flow_hash_v4/v6 this takes no pre-parsed header, so it
// suits callers that hold only an offset (the service-programming return
// paths, whose payload family is a per-circuit property rather than a
// dispatch-time fact).
//
// Returns 0 — the established "no hash computed" sentinel, which
// ecmp_flow_label folds to an unlabeled 0 — when no L3 header can be hashed:
// `l3_off` is 0 (callers use 0 to mean "no L3 header located", e.g. a payload
// that is a whole Ethernet frame), out of range, or the header is truncated or
// carries a version this node does not hash. Callers that need the packet
// dropped in those cases must check separately; this helper never drops.
//
// The offset is read at its current position, so callers must invoke this
// BEFORE any bpf_xdp_adjust_head. __noinline caps verifier state growth in the
// already-large programs that call it (same reasoning as ecmp_select_path).
static __noinline __u32 ecmp_flow_hash_l3(struct xdp_md *ctx, __u16 l3_off)
{
    if (l3_off == 0 || l3_off > 22)
        return 0;
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    void *l3 = data + l3_off;
    if (l3 + 1 > data_end)
        return 0;
    __u8 ver = (*(__u8 *)l3) >> 4;
    if (ver == 4) {
        struct iphdr *iph = l3;
        if ((void *)(iph + 1) > data_end)
            return 0;
        return ecmp_flow_hash_v4(ctx, iph, l3_off);
    }
    if (ver == 6) {
        struct ipv6hdr *ip6h = l3;
        if ((void *)(ip6h + 1) > data_end)
            return 0;
        return ecmp_flow_hash_v6(ctx, ip6h, l3_off);
    }
    return 0;
}

// Hash an L2 frame for path selection (EVPN aliasing). The inner L3 flow is
// hashed when the payload is IP -- same 5-tuple spread the L3 dispatchers
// get -- and any other payload (ARP, LLDP, ...) falls back to the MAC pair
// plus ethertype, so non-IP frames still spread across the group while each
// station pair keeps one path. Up to two VLAN tags are skipped to find the
// payload, matching the QinQ depth xdp_main parses.
//
// The MAC words and payload offset are captured before the
// ecmp_flow_hash_l3 call: it is __noinline, and packet pointers do not
// survive a BPF-to-BPF call, so nothing derived from data may be reused
// afterwards. Returns a non-zero hash on any parseable frame; 0 only when
// even the Ethernet header is truncated.
static __noinline __u32 ecmp_flow_hash_l2(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 0;

    // dst(6) + src(6) are contiguous at the start of the Ethernet header.
    __u32 macs[3];
    __builtin_memcpy(macs, eth->h_dest, sizeof(macs));

    __u16 proto = eth->h_proto;
    __u16 l3_off = sizeof(*eth);
#pragma unroll
    for (int i = 0; i < 2; i++) {
        if (proto != bpf_htons(ETH_P_8021Q) && proto != bpf_htons(ETH_P_8021AD))
            break;
        struct vlan_hdr *vh = data + l3_off;
        if ((void *)(vh + 1) > data_end)
            break;
        proto = vh->h_vlan_encapsulated_proto;
        l3_off += sizeof(*vh);
    }

    if (proto == bpf_htons(ETH_P_IP) || proto == bpf_htons(ETH_P_IPV6)) {
        __u32 hash = ecmp_flow_hash_l3(ctx, l3_off);
        if (hash)
            return hash;
    }
    __u32 hash = ecmp_jhash_3words(macs[0], macs[1],
                                   macs[2] ^ ((__u32)proto << 16),
                                   ECMP_JHASH_SEED);
    // Same sentinel rounding as ecmp_flow_hash_v4.
    return hash ? hash : 1;
}

// ========================================================================
// Path selection
// ========================================================================

// Pick a path index for the group by weighted hash-modulo over the live
// paths. Returns 0..ECMP_MAX_PATHS-1, or -1 when the group is unresolvable
// (missing info / zero total weight) and the caller should fall back to the
// parent entry. When every live path has been marked dead by the prober the
// selection fails open across the full set: BGP still holds these paths, so
// spreading over possibly-degraded paths beats dropping.
//
// __noinline caps verifier state growth in the already-large main program
// (same reasoning as __do_h_encaps_subprog).
static __noinline int ecmp_select_path(__u32 group_id, __u32 hash)
{
    struct ecmp_group_info *gi = bpf_map_lookup_elem(&ecmp_group_map, &group_id);
    if (!gi)
        return -1;
    __u8 n = gi->num_paths;
    if (n < 1 || n > ECMP_MAX_PATHS)
        return -1;

    __u64 live = ~0ULL; // liveness miss = no prober = all paths live
    __u64 *lv = bpf_map_lookup_elem(&ecmp_live_map, &group_id);
    if (lv)
        live = *lv;

    __u32 total_live = 0, total_all = 0;
#pragma unroll
    for (int i = 0; i < ECMP_MAX_PATHS; i++) {
        if (i < n) {
            total_all += gi->weight[i];
            if ((live >> i) & 1)
                total_live += gi->weight[i];
        }
    }
    __u32 total = total_live;
    if (total == 0) {
        // All paths probed dead (or all live weights zero): fail open.
        live = ~0ULL;
        total = total_all;
    }
    if (total == 0)
        return -1; // guard: the modulus below must be non-zero

    __u32 target = hash % total;
    __u32 acc = 0;
    int sel = -1;
#pragma unroll
    for (int i = 0; i < ECMP_MAX_PATHS; i++) {
        if (i < n && ((live >> i) & 1)) {
            acc += gi->weight[i];
            if (sel < 0 && target < acc)
                sel = i;
        }
    }
    return sel;
}

// Resolve a headend entry's ECMP group reference into the selected path's
// entry (a map-value pointer, valid for the caller's lifetime). Returns the
// entry itself when it carries no group, or as the fallback when the group
// is unresolvable mid-update and the entry has its own segments. Returns
// NULL when the packet must be dropped: a pure group reference (no fallback
// segments) whose group cannot be resolved -- encapping a zero-segment
// entry would emit garbage. Selected paths are terminal (the control plane
// forces their group_id to 0), so resolution never recurses.
static __always_inline struct headend_entry *ecmp_resolve_headend(
    struct headend_entry *entry, __u32 flow_hash)
{
    if (entry->group_id == ECMP_GROUP_NONE)
        return entry;
    int sel = ecmp_select_path(entry->group_id, flow_hash);
    if (sel >= 0) {
        struct ecmp_path_key pk = {
            .group_id = entry->group_id,
            .path_index = (__u32)sel,
        };
        struct headend_entry *path = bpf_map_lookup_elem(&ecmp_path_map, &pk);
        if (path)
            return path;
    }
    if (entry->num_segments < 1)
        return NULL;
    return entry;
}

// Flow label for the current headend encap: the dispatcher's flow hash
// folded per RFC 6437, with an optional extra entropy word mixed in (the
// GTP headends pass the TEID, whose per-session entropy the outer GTP-U
// 5-tuple lacks under fixed ports). Returns 0 (unlabeled) when the
// dispatch did not hash, e.g. endpoint or L2 dispatch.
static __always_inline __u32 headend_ctx_flow_label(__u32 extra)
{
    struct tailcall_ctx *tctx = tailcall_ctx_read();
    __u32 hash = tctx ? tctx->flow_hash : 0;
    if (hash != 0 && extra != 0)
        hash = ecmp_jhash_3words(hash, extra, 0, ECMP_JHASH_SEED);
    return ecmp_flow_label(hash);
}

#endif // SRV6_ECMP_H
