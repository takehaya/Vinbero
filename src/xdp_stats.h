#ifndef XDP_STATS_H
#define XDP_STATS_H

#include <linux/types.h>
#include <bpf/bpf_helpers.h>

// Runtime configurable: set to 1 to enable statistics (default: 0 for max performance)
// Can be controlled via Go config
const volatile __u8 enable_stats = 0;

// Statistics counter indices
enum stats_counter {
    STATS_RX_PACKETS = 0,   // Total received packets
    STATS_SRV6_END = 1,     // SRv6 End operations processed
    STATS_H_ENCAPS_V4 = 2,  // H.Encaps IPv4 packets processed
    STATS_H_ENCAPS_V6 = 3,  // H.Encaps IPv6 packets processed
    STATS_PASS = 4,         // XDP_PASS count
    STATS_DROP = 5,         // XDP_DROP count
    STATS_REDIRECT = 6,     // XDP_REDIRECT count
    STATS_ERROR = 7,        // Error count
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

#endif // XDP_STATS_H
