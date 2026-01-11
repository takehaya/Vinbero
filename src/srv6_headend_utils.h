#ifndef SRV6_HEADEND_UTILS_H
#define SRV6_HEADEND_UTILS_H

#include <linux/types.h>
#include <linux/in6.h>
#include "xdp_prog.h"

// Copy segments to SRH in reverse order (RFC 8754)
// Returns 0 on success, -1 on failure
static __always_inline int copy_segments_to_srh(
    void *srh_segments,
    void *data_end,
    __u8 segments[MAX_SEGMENTS][16],
    __u8 num_segments)
{
    // Handle each num_segments case explicitly with individual boundary checks
    switch (num_segments) {
    case 1:
        if (srh_segments + 16 > data_end) return -1;
        __builtin_memcpy(srh_segments, &segments[0], 16);
        break;
    case 2:
        if (srh_segments + 32 > data_end) return -1;
        __builtin_memcpy(srh_segments + 0, &segments[1], 16);
        __builtin_memcpy(srh_segments + 16, &segments[0], 16);
        break;
    case 3:
        if (srh_segments + 48 > data_end) return -1;
        __builtin_memcpy(srh_segments + 0, &segments[2], 16);
        __builtin_memcpy(srh_segments + 16, &segments[1], 16);
        __builtin_memcpy(srh_segments + 32, &segments[0], 16);
        break;
    case 4:
        if (srh_segments + 64 > data_end) return -1;
        __builtin_memcpy(srh_segments + 0, &segments[3], 16);
        __builtin_memcpy(srh_segments + 16, &segments[2], 16);
        __builtin_memcpy(srh_segments + 32, &segments[1], 16);
        __builtin_memcpy(srh_segments + 48, &segments[0], 16);
        break;
    case 5:
        if (srh_segments + 80 > data_end) return -1;
        __builtin_memcpy(srh_segments + 0, &segments[4], 16);
        __builtin_memcpy(srh_segments + 16, &segments[3], 16);
        __builtin_memcpy(srh_segments + 32, &segments[2], 16);
        __builtin_memcpy(srh_segments + 48, &segments[1], 16);
        __builtin_memcpy(srh_segments + 64, &segments[0], 16);
        break;
    case 6:
        if (srh_segments + 96 > data_end) return -1;
        __builtin_memcpy(srh_segments + 0, &segments[5], 16);
        __builtin_memcpy(srh_segments + 16, &segments[4], 16);
        __builtin_memcpy(srh_segments + 32, &segments[3], 16);
        __builtin_memcpy(srh_segments + 48, &segments[2], 16);
        __builtin_memcpy(srh_segments + 64, &segments[1], 16);
        __builtin_memcpy(srh_segments + 80, &segments[0], 16);
        break;
    case 7:
        if (srh_segments + 112 > data_end) return -1;
        __builtin_memcpy(srh_segments + 0, &segments[6], 16);
        __builtin_memcpy(srh_segments + 16, &segments[5], 16);
        __builtin_memcpy(srh_segments + 32, &segments[4], 16);
        __builtin_memcpy(srh_segments + 48, &segments[3], 16);
        __builtin_memcpy(srh_segments + 64, &segments[2], 16);
        __builtin_memcpy(srh_segments + 80, &segments[1], 16);
        __builtin_memcpy(srh_segments + 96, &segments[0], 16);
        break;
    case 8:
        if (srh_segments + 128 > data_end) return -1;
        __builtin_memcpy(srh_segments + 0, &segments[7], 16);
        __builtin_memcpy(srh_segments + 16, &segments[6], 16);
        __builtin_memcpy(srh_segments + 32, &segments[5], 16);
        __builtin_memcpy(srh_segments + 48, &segments[4], 16);
        __builtin_memcpy(srh_segments + 64, &segments[3], 16);
        __builtin_memcpy(srh_segments + 80, &segments[2], 16);
        __builtin_memcpy(srh_segments + 96, &segments[1], 16);
        __builtin_memcpy(srh_segments + 112, &segments[0], 16);
        break;
    case 9:
        if (srh_segments + 144 > data_end) return -1;
        __builtin_memcpy(srh_segments + 0, &segments[8], 16);
        __builtin_memcpy(srh_segments + 16, &segments[7], 16);
        __builtin_memcpy(srh_segments + 32, &segments[6], 16);
        __builtin_memcpy(srh_segments + 48, &segments[5], 16);
        __builtin_memcpy(srh_segments + 64, &segments[4], 16);
        __builtin_memcpy(srh_segments + 80, &segments[3], 16);
        __builtin_memcpy(srh_segments + 96, &segments[2], 16);
        __builtin_memcpy(srh_segments + 112, &segments[1], 16);
        __builtin_memcpy(srh_segments + 128, &segments[0], 16);
        break;
    case 10:
        if (srh_segments + 160 > data_end) return -1;
        __builtin_memcpy(srh_segments + 0, &segments[9], 16);
        __builtin_memcpy(srh_segments + 16, &segments[8], 16);
        __builtin_memcpy(srh_segments + 32, &segments[7], 16);
        __builtin_memcpy(srh_segments + 48, &segments[6], 16);
        __builtin_memcpy(srh_segments + 64, &segments[5], 16);
        __builtin_memcpy(srh_segments + 80, &segments[4], 16);
        __builtin_memcpy(srh_segments + 96, &segments[3], 16);
        __builtin_memcpy(srh_segments + 112, &segments[2], 16);
        __builtin_memcpy(srh_segments + 128, &segments[1], 16);
        __builtin_memcpy(srh_segments + 144, &segments[0], 16);
        break;
    default:
        return -1;
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
    // Limit index to reasonable value
    if (index > 9) {
        return -1;
    }

    // Use switch-case to explicitly handle each segment index
    switch (index) {
    case 0:
        if (seg_base + 16 > data_end) return -1;
        __builtin_memcpy(dst, seg_base, 16);
        break;
    case 1:
        if (seg_base + 32 > data_end) return -1;
        __builtin_memcpy(dst, seg_base + 16, 16);
        break;
    case 2:
        if (seg_base + 48 > data_end) return -1;
        __builtin_memcpy(dst, seg_base + 32, 16);
        break;
    case 3:
        if (seg_base + 64 > data_end) return -1;
        __builtin_memcpy(dst, seg_base + 48, 16);
        break;
    case 4:
        if (seg_base + 80 > data_end) return -1;
        __builtin_memcpy(dst, seg_base + 64, 16);
        break;
    case 5:
        if (seg_base + 96 > data_end) return -1;
        __builtin_memcpy(dst, seg_base + 80, 16);
        break;
    case 6:
        if (seg_base + 112 > data_end) return -1;
        __builtin_memcpy(dst, seg_base + 96, 16);
        break;
    case 7:
        if (seg_base + 128 > data_end) return -1;
        __builtin_memcpy(dst, seg_base + 112, 16);
        break;
    case 8:
        if (seg_base + 144 > data_end) return -1;
        __builtin_memcpy(dst, seg_base + 128, 16);
        break;
    case 9:
        if (seg_base + 160 > data_end) return -1;
        __builtin_memcpy(dst, seg_base + 144, 16);
        break;
    default:
        return -1;
    }
    return 0;
}

#endif // SRV6_HEADEND_UTILS_H
