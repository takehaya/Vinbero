#ifndef BUM_XDP_H
#define BUM_XDP_H

// XDP-only BUM replication (settings.l2.bum_mode: xdp).
//
// In tc mode (the default) the XDP program marks a BUM frame with the VNBU
// meta and passes it up: tc_bum.h clones it once per remote PE and the kernel
// bridge floods it to the local ports. In xdp mode the frame never leaves XDP:
// it is broadcast through a per-BD devmap whose members are the local ACs and
// one entry per remote flood slot, the entry's ifindex being the uplink that
// slot's peer is routed through. Every remote entry carries the same devmap
// egress program (bum_egress.c).
//
// The copies of one frame arrive at that program indistinguishable: same
// data, same egress device for every peer behind one uplink. So before the
// broadcast the ingress program writes a plan for the frame into a per-CPU
// ring (bum_plan_ring): per uplink, which slots get a copy, with
// flood_exclude and split horizon already applied. Each copy then takes the
// next slot of its uplink's list and encapsulates for that peer.
//
// Kept out of core/ on purpose: plugins include core/xdp_map.h, and these
// maps hold program references, per-CPU replication state and a ring buffer
// that a plugin must not instantiate on its own.

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>

#include "core/xdp_prog.h"
#include "core/xdp_map.h"
#include "core/xdp_stats.h"
#include "core/esi.h"
#include "core/xdp_redirect.h"
#include "l2vpn/bum_meta.h"

// Per-BD BUM replication mode (bd_config_map). INHERIT takes bum_mode_default.
#define BUM_MODE_INHERIT 0
#define BUM_MODE_TC      1
#define BUM_MODE_XDP     2
// An xdp-mode BD on a host that cannot run xdp mode (the control plane's
// startup check): the tc path, each BUM frame counted as BUM_XDP_FALLBACK.
#define BUM_MODE_TC_FALLBACK 4

struct bd_config {
    __u8 bum_mode;            // BUM_MODE_*
    __u8 _pad[3];
};

_Static_assert(sizeof(struct bd_config) == 4, "bd_config layout");

// Devmap key of remote flood slot i. Local ACs are keyed by their ifindex,
// which never has the top bit set.
#define BUM_SLOT_KEY_BASE 0x80000000u
// Local ACs plus MAX_BUM_NEXTHOPS slots. Small on purpose: a broadcast
// walks every bucket of the DEVMAP_HASH.
#define BUM_DEVMAP_MAX_ENTRIES 32
#define BUM_MAX_BDS 4096

// Loader-set: the BD mode used when bd_config_map has no override, and
// whether any BD can be in xdp mode at all. With bum_xdp_enabled == 0 the
// verifier prunes every xdp-mode branch, so a tc-only deployment runs the
// same instructions as before this mode existed.
const volatile __u8 bum_mode_default = BUM_MODE_TC;
const volatile __u8 bum_xdp_enabled = 0;

// Per-BD override of bum_mode_default. Only read when bum_xdp_enabled.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct bd_config);
    __uint(max_entries, BUM_MAX_BDS);
} bd_config_map SEC(".maps");

struct bum_devmap {
    __uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
    __uint(max_entries, BUM_DEVMAP_MAX_ENTRIES);
    __type(key, __u32);
    __uint(value_size, sizeof(struct bpf_devmap_val));
};

// bd_id -> local ACs + remote flood slots (BUM that entered on an AC)
struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, BUM_MAX_BDS);
    __type(key, __u32);
    __array(values, struct bum_devmap);
} bum_flood_map SEC(".maps");

// bd_id -> local ACs only (End.DT2 / End.DT2M flood after decap)
struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, BUM_MAX_BDS);
    __type(key, __u32);
    __array(values, struct bum_devmap);
} bum_local_map SEC(".maps");

// Local MAC learned (or moved) by the XDP learner in an xdp-mode BD. The
// kernel bridge never sees those frames, so this replaces its FDB netlink
// events as the input of EVPN RT2 auto-advertise.
#define FDB_EVENT_ADD  1
#define FDB_EVENT_MOVE 2

struct fdb_event {
    __u16 bd_id;
    __u8 mac[ETH_ALEN];
    __u32 oif;
    __u8 kind;                // FDB_EVENT_*
    __u8 _pad[3];
} __attribute__((packed));

_Static_assert(sizeof(struct fdb_event) == 16, "fdb_event ABI must remain 16 bytes");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} fdb_event_rb SEC(".maps");

// ===== Per-frame replication plan =====
//
// bum_seq numbers the AC-side BUM frames of each CPU; frame seq's plan is
// bum_plan_ring[seq % BUM_PLAN_RING_SIZE] of the same CPU. How the egress
// program learns the seq of a copy depends on the XDP mode:
//
// - generic: the devmap programs of a broadcast run synchronously, on the
//   CPU and right after the ingress program that issued it
//   (dev_map_redirect_multi -> dev_map_generic_redirect), so the copy is
//   from that CPU's latest seq. Generic XDP does not pass metadata to
//   devmap programs.
// - native (bum_xdp_native): the copies wait in per-CPU bulk queues until
//   the end of the NAPI poll, when later frames may have been planned. The
//   ingress program puts the seq in the frame's metadata (struct
//   bum_xdp_meta), which every copy carries. The flush runs on the same
//   CPU within the same poll, well inside the ring.
#define BUM_PLAN_RING_SIZE 1024
#define BUM_PLAN_MAX_UPLINKS MAX_BUM_NEXTHOPS

_Static_assert((BUM_PLAN_RING_SIZE & (BUM_PLAN_RING_SIZE - 1)) == 0, "ring size must be a power of two");
_Static_assert(MAX_BUM_NEXTHOPS <= 8, "bum_plan_uplink.slots is an 8-bit slot set");

struct bum_plan_uplink {
    __u32 ifindex;            // uplink (devmap entry ifindex)
    __u8 slots;               // flood slots to send through it, bit i = slot i
    __u8 n;                   // number of bits set in slots
    __u8 next_idx;            // copies handed out so far (egress)
    __u8 local;               // also a local AC of the BD: one copy leaves as is
};

struct bum_plan {
    __u64 seq;                // the frame's bum_seq number; checked by egress
    __u64 data;               // ingress ctx->data: detects copies sharing one buffer
    __u32 src_ifindex;        // source AC
    __u16 bd_id;
    __u16 len;                // frame length as broadcast
    __u8 n_uplinks;
    __u8 shared;              // remote copies seen on the ingress buffer
    __u8 _pad[6];
    struct bum_plan_uplink up[BUM_PLAN_MAX_UPLINKS];
};

_Static_assert(sizeof(struct bum_plan) == 96, "bum_plan layout");

// Native XDP: the metadata the ingress program puts in front of a BUM frame
// before the broadcast. The egress program strips it.
#define BUM_XDP_META_MARKER 0x564E4258 // "VNBX"

struct bum_xdp_meta {
    __u32 marker;             // BUM_XDP_META_MARKER
    __u32 src_ifindex;        // source AC
    __u64 seq;                // the frame's bum_seq number
};

_Static_assert(sizeof(struct bum_xdp_meta) % 4 == 0 && sizeof(struct bum_xdp_meta) <= 32,
               "XDP metadata is 4-byte aligned and at most 32 bytes");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} bum_seq SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, BUM_PLAN_RING_SIZE);
    __type(key, __u32);
    __type(value, struct bum_plan);
} bum_plan_ring SEC(".maps");

static __always_inline __u8 bum_bd_mode(__u16 bd_id)
{
    if (!bum_xdp_enabled)
        return BUM_MODE_TC;
    __u32 k = bd_id;
    struct bd_config *c = bpf_map_lookup_elem(&bd_config_map, &k);
    if (!c || c->bum_mode == BUM_MODE_INHERIT)
        return bum_mode_default;
    return c->bum_mode;
}

static __always_inline void bum_fdb_event_emit(__u16 bd_id, const __u8 *mac, __u32 oif, __u8 kind)
{
    if (mac[0] & 0x01)
        return; // only unicast sources are advertised
    struct fdb_event ev = { .bd_id = bd_id, .oif = oif, .kind = kind };
    __builtin_memcpy(ev.mac, mac, ETH_ALEN);
    bpf_ringbuf_output(&fdb_event_rb, &ev, sizeof(ev), 0);
}

// Native XDP: hand the seq that bum_xdp_broadcast just used to the copies.
// vinbero_main has cleared any metadata the frame arrived with.
static __always_inline int bum_xdp_meta_write(struct xdp_md *ctx)
{
    __u32 zero = 0;
    __u64 *next = bpf_map_lookup_elem(&bum_seq, &zero);
    if (!next || *next == 0)
        return -1;
    __u64 seq = *next - 1;
    __u32 src_if = ctx->ingress_ifindex;
    if (bpf_xdp_adjust_meta(ctx, -(int)sizeof(struct bum_xdp_meta)))
        return -1;
    struct bum_xdp_meta *m = (void *)(long)ctx->data_meta;
    if ((void *)(m + 1) > (void *)(long)ctx->data)
        return -1;
    m->marker = BUM_XDP_META_MARKER;
    m->src_ifindex = src_if;
    m->seq = seq;
    return 0;
}

// Return values of bum_xdp_broadcast other than an XDP action.
// NO_DEVMAP: the frame takes the tc path instead. NO_META: native XDP could
// not put the frame's metadata in front of it.
#define BUM_BCAST_NO_DEVMAP (-1)
#define BUM_BCAST_NO_META   (-2)

// Plan the frame's remote copies and broadcast it through the BD's flood
// devmap. Plan and broadcast use the one devmap this function looked up, so
// a concurrent rebuild of the BD cannot give them different member lists.
//
// A slot is planned when the devmap holds its entry -- whose ifindex is the
// slot's uplink -- and it passes the tc path's per-peer checks: a bd_peer
// exists, is not flood_exclude, and is not on the source AC's Ethernet
// Segment. Every uplink of a slot entry gets a plan item, planned slots or
// not, so the egress program can tell a device's surplus copies from the
// copy of a local AC on the same device (item.local).
//
// The broadcast excludes the ingress device, unless a planned slot uses it
// as its uplink (an AC and an uplink on one port): then the ingress AC gets
// a copy too, which the egress program drops (item.local is 0 for it).
//
// Returns the XDP action, BUM_BCAST_NO_DEVMAP when the BD has no devmap, or
// BUM_BCAST_NO_META.
// A global function on purpose: the verifier checks it once, not once per
// path of vinbero_main that reaches the flood.
__noinline int bum_xdp_broadcast(struct xdp_md *ctx, __u32 bd_id, __u32 vlan_id)
{
    if (!ctx)
        return BUM_BCAST_NO_DEVMAP;
    __u32 bd_key = bd_id;
    void *flood = bpf_map_lookup_elem(&bum_flood_map, &bd_key);
    if (!flood)
        return BUM_BCAST_NO_DEVMAP;
    __u32 zero = 0;
    __u64 *seqp = bpf_map_lookup_elem(&bum_seq, &zero);
    if (!seqp)
        return BUM_BCAST_NO_DEVMAP;
    __u64 seq = (*seqp)++;
    __u32 k = seq & (BUM_PLAN_RING_SIZE - 1);
    struct bum_plan *plan = bpf_map_lookup_elem(&bum_plan_ring, &k);
    if (!plan)
        return BUM_BCAST_NO_DEVMAP;

    __u32 src_if = ctx->ingress_ifindex;
    __u64 pkt_len = (__u64)((long)ctx->data_end - (long)ctx->data);
    plan->seq = seq;
    plan->data = (__u64)(long)ctx->data;
    plan->src_ifindex = src_if;
    plan->bd_id = (__u16)bd_id;
    plan->len = (__u16)pkt_len;
    plan->n_uplinks = 0;
    plan->shared = 0;

    struct headend_l2_key src_key = { .ifindex = src_if, .vlan_id = (__u16)vlan_id };
    struct headend_l2_ext_val *src_ext = bpf_map_lookup_elem(&headend_l2_ext_map, &src_key);
    bool src_esi_set = src_ext && !esi_is_zero(src_ext->esi);

    bool hairpin = false;
    __u32 n_up = 0;
    for (__u32 i = 0; i < MAX_BUM_NEXTHOPS; i++) {
        __u32 dk = BUM_SLOT_KEY_BASE | i;
        struct bpf_devmap_val *dv = bpf_map_lookup_elem(flood, &dk);
        if (!dv)
            continue;
        __u32 uplink = dv->ifindex;
        __u32 u;
        for (u = 0; u < BUM_PLAN_MAX_UPLINKS; u++) {
            if (u == n_up) {
                plan->up[u].ifindex = uplink;
                plan->up[u].slots = 0;
                plan->up[u].n = 0;
                plan->up[u].next_idx = 0;
                // Local ACs are keyed by their ifindex.
                plan->up[u].local = uplink != src_if && bpf_map_lookup_elem(flood, &uplink) != NULL;
                n_up++;
                break;
            }
            if (plan->up[u].ifindex == uplink)
                break;
        }
        if (u >= BUM_PLAN_MAX_UPLINKS)
            continue; // unreachable: at most one uplink per slot

        struct bd_peer_key pk = { .bd_id = (__u16)bd_id, .index = (__u16)i };
        struct headend_entry *peer = bpf_map_lookup_elem(&bd_peer_map, &pk);
        if (!peer || peer->flood_exclude)
            continue;
        // RFC 9252 split horizon, same rule as tc_dispatch_bum_clones.
        if (src_esi_set) {
            struct bd_peer_l2_ext_key ek = { .bd_id = (__u16)bd_id, .index = (__u16)i };
            struct bd_peer_l2_ext_val *pe = bpf_map_lookup_elem(&bd_peer_l2_ext_map, &ek);
            if (pe && esi_equal(pe->esi, src_ext->esi)) {
                STATS_INC(STATS_SPLIT_HORIZON_TX, pkt_len);
                continue;
            }
        }
        plan->up[u].slots |= (__u8)(1u << i);
        plan->up[u].n++;
        if (uplink == src_if)
            hairpin = true;
    }
    plan->n_uplinks = (__u8)n_up;

    if (bum_xdp_native && bum_xdp_meta_write(ctx) != 0)
        return BUM_BCAST_NO_META;
    STATS_INC(STATS_BUM_XDP_FLOOD, pkt_len);
    __u64 flags = BPF_F_BROADCAST;
    if (!hairpin)
        flags |= BPF_F_EXCLUDE_INGRESS;
    return bpf_redirect_map(flood, 0, flags);
}

// Whether the control plane serves the BD in xdp mode: it has a devmap. A
// BD it cannot serve (BumDevmapSync) has none and keeps the tc path and the
// bridge for its BUM and its local unicast alike.
static __always_inline bool bum_xdp_served(__u16 bd_id)
{
    __u32 key = bd_id;
    return bpf_map_lookup_elem(&bum_flood_map, &key) != NULL;
}

// BUM that entered on a local AC of a tc-mode BD: mark it for the TC
// clones and the bridge.
static __always_inline int bum_tc_flood_from_ac(struct xdp_md *ctx, __u8 bum_mode, __u16 vlan_id)
{
    if (bum_mode == BUM_MODE_TC_FALLBACK)
        STATS_INC(STATS_BUM_XDP_FALLBACK, (__u64)((long)ctx->data_end - (long)ctx->data));
    xdp_write_bum_meta(ctx, vlan_id);
    return XDP_PASS;
}

// BUM that entered on a local AC of an xdp-mode BD: plan the remote copies,
// then broadcast to the members of the BD's devmap.
// Without a devmap (not built yet, or a BD the control plane cannot serve
// in xdp mode) the frame takes the tc path instead, exactly as a tc-mode BD
// would.
static __always_inline int bum_xdp_flood_from_ac(struct xdp_md *ctx, __u16 bd_id, __u16 vlan_id)
{
    __u64 pkt_len = (__u64)((long)ctx->data_end - (long)ctx->data);
    int act = bum_xdp_broadcast(ctx, bd_id, vlan_id);
    if (act == BUM_BCAST_NO_META) {
        STATS_INC(STATS_BUM_XDP_META_FAIL, pkt_len);
        return XDP_DROP;
    }
    if (act < 0) {
        STATS_INC(STATS_BUM_XDP_FALLBACK, pkt_len);
        xdp_write_bum_meta(ctx, vlan_id);
        return XDP_PASS;
    }
    return act;
}

// Flood after decap in an xdp-mode BD: local ACs only. Returns -1 when the
// BD is not in xdp mode or has no devmap, so the caller keeps its bridge path.
static __always_inline int bum_xdp_flood_from_tunnel(struct xdp_md *ctx, __u16 bd_id)
{
    if (bd_id == 0)
        return -1;
    __u8 mode = bum_bd_mode(bd_id);
    __u64 pkt_len = (__u64)((long)ctx->data_end - (long)ctx->data);
    if (mode == BUM_MODE_TC_FALLBACK)
        STATS_INC(STATS_BUM_XDP_FALLBACK, pkt_len);
    if (mode != BUM_MODE_XDP)
        return -1;
    __u32 key = bd_id;
    void *inner = bpf_map_lookup_elem(&bum_local_map, &key);
    if (!inner) {
        STATS_INC(STATS_BUM_XDP_FALLBACK, pkt_len);
        return -1;
    }
    STATS_INC(STATS_BUM_XDP_LOCAL_FLOOD, pkt_len);
    return bpf_redirect_map(inner, 0, BPF_F_BROADCAST);
}

#endif // BUM_XDP_H
