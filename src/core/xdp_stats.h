#ifndef XDP_STATS_H
#define XDP_STATS_H

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Runtime configurable: set to 1 to enable statistics (default: 0 for max performance)
// Can be controlled via Go config
const volatile __u8 enable_stats = 0;

// Statistics counter indices (global per-action). Per-target invocation
// counts live in slot_stats_* maps below.
enum stats_counter {
    STATS_RX_PACKETS         = 0,   // Total received packets
    STATS_PASS               = 1,   // XDP_PASS count
    STATS_DROP               = 2,   // XDP_DROP count
    STATS_REDIRECT           = 3,   // XDP_REDIRECT count
    STATS_ABORTED            = 4,   // XDP_ABORTED count (BPF program error path)
    STATS_SPLIT_HORIZON_TX   = 5,   // BUM clones skipped by send-side split-horizon
    STATS_SPLIT_HORIZON_RX   = 6,   // DT2M receives dropped by recv-side split-horizon
    STATS_NON_DF_DROP        = 7,   // DT2M BUM dropped on a non-DF PE
    STATS_BUM_XDP_FLOOD      = 8,   // xdp mode: AC-ingress BUM broadcast through the BD devmap
    STATS_BUM_XDP_LOCAL_FLOOD = 9,  // xdp mode: post-decap flood to the local ACs
    STATS_BUM_XDP_FALLBACK   = 10,  // xdp mode BD on the tc/bridge path (no devmap, or xdp mode unavailable)
    STATS_BUM_EGRESS_TX      = 11,  // xdp mode: remote copies encapsulated by the devmap egress program
    STATS_BUM_EGRESS_DROP    = 12,  // xdp mode: remote copy dropped (no AC/peer, encap or FIB failure)
    STATS_BUM_UPLINK_MISMATCH = 13, // xdp mode: FIB egress differs from the slot's devmap uplink
    STATS_BUM_PLAN_STALE     = 14,  // xdp mode: remote copy whose replication plan is not its frame's
    STATS_BUM_PLAN_SURPLUS   = 15,  // xdp mode: remote copy beyond its uplink's planned slots
    STATS_BUM_SHARED_BUFFER  = 16,  // xdp mode: remote copy dropped, its buffer is shared with another
    STATS_BUM_EGRESS_NO_NEIGH = 17, // xdp mode: remote copy dropped, the uplink next hop's neighbour is unresolved
    STATS_BUM_XDP_META_FAIL  = 18,  // native xdp mode: BUM dropped, the driver gave no room for XDP metadata
    STATS_MAX,
};

// Per-CPU statistics entry
struct stats_entry {
    __u64 packets;
    __u64 bytes;
} __attribute__((packed));

// Per-CPU statistics map (always defined, usage is conditional)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct stats_entry);
    __uint(max_entries, STATS_MAX);
} stats_map SEC(".maps");

// Increment statistics counter
// When enable_stats is 0, the verifier optimizes this away
static __always_inline void stats_inc(enum stats_counter counter, __u64 bytes)
{
    if (!enable_stats)
        return;

    __u32 key = counter;
    struct stats_entry *stats = bpf_map_lookup_elem(&stats_map, &key);
    if (stats) {
        stats->packets++;
        stats->bytes += bytes;
    }
}

// Helper macro for cleaner code
#define STATS_INC(counter, bytes) stats_inc(counter, bytes)

// stats_action_inc maps an XDP action to its per-action counter. Shared
// by tailcall_epilogue and vinbero_main's out: label so both paths stay
// in sync when the enum grows.
static __always_inline void stats_action_inc(int action, __u64 pkt_len)
{
    switch (action) {
    case XDP_PASS:     STATS_INC(STATS_PASS, pkt_len); break;
    case XDP_DROP:     STATS_INC(STATS_DROP, pkt_len); break;
    case XDP_REDIRECT: STATS_INC(STATS_REDIRECT, pkt_len); break;
    case XDP_ABORTED:  STATS_INC(STATS_ABORTED, pkt_len); break;
    default: break;
    }
}

// ========== Per-slot invocation counters ==========
// Indexed by tail-call target slot number. One map per PROG_ARRAY so key
// spaces don't collide and each `stats slot reset --type X` resets cleanly.

#define SLOT_STATS_ENDPOINT_MAX 64   // ENDPOINT_PROG_MAX
#define SLOT_STATS_HEADEND_MAX  32   // HEADEND_PROG_MAX
#define SLOT_STATS_SVC_RETURN_MAX 8  // SERVICE_RETURN_PROG_MAX

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct stats_entry);
    __uint(max_entries, SLOT_STATS_ENDPOINT_MAX);
} slot_stats_endpoint SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct stats_entry);
    __uint(max_entries, SLOT_STATS_HEADEND_MAX);
} slot_stats_headend_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct stats_entry);
    __uint(max_entries, SLOT_STATS_HEADEND_MAX);
} slot_stats_headend_v6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct stats_entry);
    __uint(max_entries, SLOT_STATS_HEADEND_MAX);
} slot_stats_headend_l2 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct stats_entry);
    __uint(max_entries, SLOT_STATS_SVC_RETURN_MAX);
} slot_stats_service_return SEC(".maps");

// slot_stats_inc: gated by enable_stats like stats_inc. `map` must be one
// of slot_stats_endpoint / slot_stats_headend_v4 / slot_stats_headend_v6
// / slot_stats_headend_l2 / slot_stats_service_return, and `slot` must be
// already masked to the map's range by the caller.
static __always_inline void slot_stats_inc(void *map, __u32 slot, __u64 bytes)
{
    if (!enable_stats)
        return;

    struct stats_entry *s = bpf_map_lookup_elem(map, &slot);
    if (s) {
        s->packets++;
        s->bytes += bytes;
    }
}

#endif // XDP_STATS_H
