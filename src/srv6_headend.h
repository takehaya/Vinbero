#ifndef SRV6_HEADEND_H
#define SRV6_HEADEND_H

#include <linux/types.h>
#include <bpf/bpf_helpers.h>

#include "xdp_prog.h"
#include "srv6.h"

// Check if headend entry is valid and mode is supported
// Returns: true if H.Encaps should be performed, false otherwise
static __always_inline bool headend_should_encaps(struct headend_entry *entry)
{
    if (!entry) {
        return false;
    }

    // Only H.Encaps supported for now
    return entry->mode == SRV6_HEADEND_BEHAVIOR_H_ENCAPS;
}

#endif // SRV6_HEADEND_H
