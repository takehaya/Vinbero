#ifndef VINBERO_ESI_H
#define VINBERO_ESI_H

#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <stdbool.h>

#include "core/xdp_prog.h" // ESI_LEN, struct esi_key / esi_entry
#include "core/xdp_map.h"  // esi_map

// RFC 7432 ESI byte-level helpers.

static __always_inline bool esi_is_zero(const __u8 esi[ESI_LEN])
{
    // 8 + 2 split: verifier-friendly for the 10-byte shape where
    // __builtin_memcmp with non-power-of-two isn't reliably lowered.
    __u64 hi = *(const __u64 *)esi;
    __u16 lo = *(const __u16 *)(esi + 8);
    return (hi | (__u64)lo) == 0;
}

static __always_inline bool esi_equal(const __u8 a[ESI_LEN], const __u8 b[ESI_LEN])
{
    __u64 a_hi = *(const __u64 *)a;
    __u64 b_hi = *(const __u64 *)b;
    __u16 a_lo = *(const __u16 *)(a + 8);
    __u16 b_lo = *(const __u16 *)(b + 8);
    return (a_hi == b_hi) && (a_lo == b_lo);
}

// True if `esi` is registered in esi_map with local_attached=1.
static __always_inline bool esi_is_local_attached(const __u8 esi[ESI_LEN])
{
    struct esi_key k = {};
    __builtin_memcpy(k.esi, esi, ESI_LEN);
    struct esi_entry *e = bpf_map_lookup_elem(&esi_map, &k);
    return e && e->local_attached;
}

// IPv6 byte-level helpers. Verifier-friendly 8+8 split; DF check on
// df_pe_src_addr / local_pe_src_addr uses these.

static __always_inline bool ipv6_is_zero(const __u8 addr[IPV6_ADDR_LEN])
{
    __u64 hi = *(const __u64 *)addr;
    __u64 lo = *(const __u64 *)(addr + 8);
    return (hi | lo) == 0;
}

static __always_inline bool ipv6_equal(const __u8 a[IPV6_ADDR_LEN], const __u8 b[IPV6_ADDR_LEN])
{
    __u64 a_hi = *(const __u64 *)a;
    __u64 b_hi = *(const __u64 *)b;
    __u64 a_lo = *(const __u64 *)(a + 8);
    __u64 b_lo = *(const __u64 *)(b + 8);
    return (a_hi == b_hi) && (a_lo == b_lo);
}

#endif // VINBERO_ESI_H
