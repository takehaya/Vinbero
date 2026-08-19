// plugin.c -- the data-plane half of the custom-behavior example.
//
// Its control-plane half is sdk/examples/cplane-custom-behavior: a
// WebAssembly plugin that claims an endpoint behavior codepoint no
// standard assigns (0xFE01), asks the daemon for a local SID pointing at
// this program's slot, and advertises that SID over BGP with the codepoint
// in the SID TLV. This is what the SID resolves to when a packet steered
// into it arrives.
//
// What it does is deliberately small: it counts the packets its own SID
// received, and hands them to vinbero's End.DT4 to be decapsulated and
// forwarded. A real behavior would do its own work here -- that is the
// point of owning a slot -- but the example is about the wiring, and the
// wiring is what is hard to get right: an operator-defined codepoint that
// travels in BGP, resolves to an address the daemon allocated, and lands
// in a program the operator wrote.
//
// Handing off rather than forwarding directly is not a shortcut. A plugin
// cannot call bpf_redirect (ForbiddenHelpers): every packet-level redirect
// goes through the epilogue or a vinbero PROG_ARRAY, so tail-calling into
// a validated slot is how a plugin finishes a packet's journey.

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include <vinbero/plugin.h>
#include <vinbero/types.h>
#include <vinbero/maps.h>

// Packets this behavior handled, for the lab to read back. PERCPU_ARRAY
// keeps the increment lock-free in the per-packet path.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} plugin_custom_behavior_seen SEC(".maps");

VINBERO_PLUGIN(plugin_custom_behavior)
{
    __u32 key = 0;
    __u64 *seen = bpf_map_lookup_elem(&plugin_custom_behavior_seen, &key);
    if (seen)
        __sync_fetch_and_add(seen, 1);

    // End.DT4 reads what it needs from the same tail-call context this
    // program was handed -- the SID entry and its aux -- so the handoff
    // needs nothing prepared. With no aux the lookup falls back to the
    // ingress interface's table, which is where the decapsulated customer
    // prefix lives in this example.
    bpf_tail_call(ctx, &sid_endpoint_progs, SRV6_LOCAL_ACTION_END_DT4);

    // Only reached when the slot is empty, which means the daemon is not
    // running End.DT4. Dropping is the honest outcome: the packet is
    // already inside a tunnel this node was meant to terminate.
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
