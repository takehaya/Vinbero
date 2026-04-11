#ifndef SRV6_HEADEND_H
#define SRV6_HEADEND_H

#include <linux/types.h>
#include <bpf/bpf_helpers.h>

#include "core/xdp_prog.h"
#include "core/srv6.h"

// Check if headend entry is valid and mode is H.Encaps.L2 or H.Encaps.L2.Red
static __always_inline bool headend_should_encaps_l2_any(struct headend_entry *entry)
{
    if (!entry) {
        return false;
    }
    return entry->mode == SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2 ||
           entry->mode == SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2_RED;
}

#endif // SRV6_HEADEND_H
