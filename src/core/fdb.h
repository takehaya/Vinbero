#ifndef VINBERO_FDB_H
#define VINBERO_FDB_H

#include "core/xdp_prog.h"

// The first map-value word is the complete mutable forwarding identity.
// bd_id comes from the lookup key; ESI belongs to the userspace-published node.
union fdb_forward {
    struct {
        __u32 oif;
        __u8 is_remote;
        __u8 is_static;
        __u16 peer_index;
    };
    __u64 word;
};

_Static_assert(sizeof(struct fdb_entry) == 32, "FDB map ABI must remain 32 bytes");
_Static_assert(sizeof(union fdb_forward) == 8, "FDB identity must fit one word");
_Static_assert(__builtin_offsetof(struct fdb_entry, bd_id) == 8,
               "FDB forwarding identity must remain the first word");

static __always_inline union fdb_forward fdb_read_forward(const struct fdb_entry *entry)
{
    // Hash map values are 8-byte aligned, despite the packed wire layout.
    // Volatile prevents separate field loads across a concurrent learner CAS.
    return (union fdb_forward){ .word = *(const volatile __u64 *)(const void *)entry };
}

static __always_inline int fdb_replace_forward(struct fdb_entry *entry,
                                              union fdb_forward old,
                                              union fdb_forward next)
{
    // A userspace HASH replacement publishes a different node. This CAS can
    // only affect the looked-up node, protected by the BPF program's RCU read.
    return __sync_val_compare_and_swap((__u64 *)(void *)entry, old.word, next.word) == old.word;
}

#endif
