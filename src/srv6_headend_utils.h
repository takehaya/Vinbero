#ifndef SRV6_HEADEND_UTILS_H
#define SRV6_HEADEND_UTILS_H

#include <linux/types.h>
#include <linux/in6.h>
#include "xdp_prog.h"

// Copy segments to SRH in reverse order (RFC 8754)
// Input: [S1, S2, S3] -> SRH storage: [S3, S2, S1]
// Returns 0 on success, -1 on failure
static __always_inline int copy_segments_to_srh(
    void *srh_segments,
    void *data_end,
    __u8 segments[MAX_SEGMENTS][16],
    __u8 num_segments)
{
    // Validate segment count
    if (num_segments < 1 || num_segments > MAX_SEGMENTS)
        return -1;

    // Copy segments in reverse order using unrolled loop
    // Per-iteration bounds check required for BPF verifier
    #pragma unroll
    for (__u8 i = 0; i < MAX_SEGMENTS; i++) {
        if (i < num_segments) {
            void *dst = srh_segments + (i * 16);
            // BPF verifier requires per-iteration boundary check
            if (dst + 16 > data_end)
                return -1;
            __builtin_memcpy(dst, &segments[num_segments - 1 - i], 16);
        }
    }
    return 0;
}

// Copy a specific segment by index from SRH to destination
// Used by process_end to update DA with segments[new_sl]
// Returns 0 on success, -1 on failure
static __always_inline int copy_segment_by_index(
    void *dst,
    void *seg_base,
    void *data_end,
    __u8 index)
{
    // Validate index (0-9 for MAX_SEGMENTS=10)
    if (index >= MAX_SEGMENTS)
        return -1;

    // Boundary check: need to access seg_base + (index+1)*16
    if (seg_base + ((index + 1) * 16) > data_end)
        return -1;

    // Copy the segment at the specified index
    __builtin_memcpy(dst, seg_base + (index * 16), 16);
    return 0;
}

#endif // SRV6_HEADEND_UTILS_H
