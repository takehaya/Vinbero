#ifndef SRV6_HEADEND_H
#define SRV6_HEADEND_H

#include <linux/types.h>
#include <bpf/bpf_helpers.h>

#include "xdp_prog.h"
#include "srv6.h"

// Check if headend entry is valid and mode is H.Encaps
static __always_inline bool headend_should_encaps(struct headend_entry *entry)
{
    if (!entry) {
        return false;
    }
    return entry->mode == SRV6_HEADEND_BEHAVIOR_H_ENCAPS;
}

// Check if headend entry is valid and mode is H.Encaps.L2
static __always_inline bool headend_should_encaps_l2(struct headend_entry *entry)
{
    if (!entry) {
        return false;
    }
    return entry->mode == SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2;
}

#endif // SRV6_HEADEND_H
