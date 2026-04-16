#ifndef XDP_TAILCALL_H
#define XDP_TAILCALL_H

#include <linux/types.h>
#include <bpf/bpf_helpers.h>

#include "core/xdp_prog.h"

// ========== Tail Call Constants ==========

// Plugin slot base indices (built-in behaviors use their enum value directly)
#define ENDPOINT_PLUGIN_BASE  32
#define HEADEND_PLUGIN_BASE   16

// PROG_ARRAY sizes: enum max + reserved + plugin slots
#define ENDPOINT_PROG_MAX     64   // enum(23) + reserved(9) + plugin(32)
#define HEADEND_PROG_MAX      32   // enum(8) + reserved(8) + plugin(16)

// Per-CPU context key (single-element array)
#define TAILCALL_CTX_KEY 0

// Dispatch type constants
#define DISPATCH_LOCALSID  0   // SRH present (via process_srv6_localsid)
#define DISPATCH_NOSRH     1   // No SRH (via process_srv6_decap_nosrh)
#define DISPATCH_HEADEND   2   // Headend encapsulation

// ========== Tail Call Context ==========

// Context passed from dispatcher to tail call target via per-CPU map.
// Dispatcher writes before bpf_tail_call; target reads on entry.
struct tailcall_ctx {
    __u16 l3_offset;        // Distance from packet start to L3 header (14/18/22)
    __u8  dispatch_type;    // DISPATCH_LOCALSID / DISPATCH_NOSRH / DISPATCH_HEADEND
    __u8  inner_proto;      // For DISPATCH_NOSRH: nexthdr (IPPROTO_IPIP/IPV6/ETHERNET)
    union {
        // Endpoint (localsid/nosrh): 12 bytes. Aux is re-looked up by target.
        struct sid_function_entry sid_entry;
        // Headend: 200 bytes. Copied because LPM trie re-lookup is expensive.
        struct headend_entry headend;
    };
} __attribute__((packed));

#endif // XDP_TAILCALL_H
