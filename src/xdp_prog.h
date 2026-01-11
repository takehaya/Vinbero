#ifndef XDP_PROG_H
#define XDP_PROG_H
#include <linux/types.h>

#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/in.h>

#ifdef VINBERO_DEBUG
#define DEBUG_PRINT(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define DEBUG_PRINT(fmt, ...) (void)0
#endif

// AF_INET/AF_INET6 are not available in BPF programs, define it manually
#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10
#endif

// Protocol numbers for encapsulation
#ifndef IPPROTO_IPIP
#define IPPROTO_IPIP 4   // IPv4 in IPv6
#endif

#ifndef IPPROTO_IPV6
#define IPPROTO_IPV6 41  // IPv6 in IPv6
#endif

// Boundary check macro
#define CHECK_BOUND(ptr, end, size) \
    if ((void *)(ptr) + (size) > (void *)(end)) return XDP_PASS

// Advance pointer with boundary check
#define ADVANCE_PTR(ptr, end, size, ret) \
    do { \
        if ((void *)(ptr) + (size) > (void *)(end)) return ret; \
        ptr = (void *)(ptr) + (size); \
    } while (0)

#define MAX_SEGMENTS 10
#define IPV4_ADDR_LEN 4
#define IPV6_ADDR_LEN 16

// LPM key for IPv4 prefix matching
struct lpm_key_v4 {
    __u32 prefixlen;              // Prefix length (0-32)
    __u8 addr[IPV4_ADDR_LEN];     // IPv4 address (4 bytes)
} __attribute__((packed));

// LPM key for IPv6 prefix matching
struct lpm_key_v6 {
    __u32 prefixlen;              // Prefix length (0-128)
    __u8 addr[IPV6_ADDR_LEN];     // IPv6 address (16 bytes)
} __attribute__((packed));


// SID Function entry (for SRv6 Endpoint functions)
struct sid_function_entry {
    __u8 action;                  // srv6_local_action enum
    __u8 flavor;                  // srv6_local_flavor enum
    __u8 src_addr[IPV6_ADDR_LEN]; // actionSrcAddr
    __u8 dst_addr[IPV6_ADDR_LEN]; // actionDstAddr
    __u8 nexthop[IPV6_ADDR_LEN];  // Next hop address
    __u8 arg_src_offset;          // Bit offset for source in SID Args
    __u8 arg_dst_offset;          // Bit offset for destination in SID Args
    __u8 _pad[2];                 // Padding for alignment
} __attribute__((packed));

// Headend entry (for H.Encaps, H.Insert, etc.)
struct headend_entry {
    __u8 mode;                              // srv6_headend_behavior enum
    __u8 num_segments;                      // Number of segments (1-10)
    __u8 _pad[2];                           // Padding for alignment
    __u8 src_addr[IPV6_ADDR_LEN];           // Outer IPv6 source address
    __u8 dst_addr[IPV6_ADDR_LEN];           // Unused for H.Encaps (reserved)
    __u8 segments[MAX_SEGMENTS][IPV6_ADDR_LEN]; // SID list (up to 10 segments)
} __attribute__((packed));

#endif // XDP_PROG_H
