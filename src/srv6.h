#ifndef SRV6_H
#define SRV6_H
#include <linux/types.h>

#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/in.h>

// ========== SRv6 Local Action (Endpoint functions) ==========
// Maps to Srv6LocalAction enum in protobuf
enum srv6_local_action {
    SRV6_LOCAL_ACTION_UNSPECIFIED = 0,
    SRV6_LOCAL_ACTION_END = 1,
    SRV6_LOCAL_ACTION_END_X = 2,
    SRV6_LOCAL_ACTION_END_T = 3,
    SRV6_LOCAL_ACTION_END_DX2 = 4,
    SRV6_LOCAL_ACTION_END_DX6 = 5,
    SRV6_LOCAL_ACTION_END_DX4 = 6,
    SRV6_LOCAL_ACTION_END_DT6 = 7,
    SRV6_LOCAL_ACTION_END_DT4 = 8,
    SRV6_LOCAL_ACTION_END_DT46 = 9,
    SRV6_LOCAL_ACTION_END_B6 = 10,
    SRV6_LOCAL_ACTION_END_B6_ENCAPS = 11,
    SRV6_LOCAL_ACTION_END_BM = 12,
    SRV6_LOCAL_ACTION_END_S = 13,
    SRV6_LOCAL_ACTION_END_AS = 14,
    SRV6_LOCAL_ACTION_END_AM = 15,
    SRV6_LOCAL_ACTION_END_BPF = 16,  // BPF-defined local action
};

// ========== SRv6 Local Flavor ==========
// Maps to Srv6LocalFlavor enum in protobuf
enum srv6_local_flavor {
    SRV6_LOCAL_FLAVOR_UNSPECIFIED = 0,
    SRV6_LOCAL_FLAVOR_NONE = 1,
    SRV6_LOCAL_FLAVOR_PSP = 2,
    SRV6_LOCAL_FLAVOR_USP = 3,
    SRV6_LOCAL_FLAVOR_USD = 4,
};

// ========== SRv6 Headend Behavior ==========
// Maps to Srv6HeadendBehavior enum in protobuf
enum srv6_headend_behavior {
    SRV6_HEADEND_BEHAVIOR_UNSPECIFIED = 0,
    SRV6_HEADEND_BEHAVIOR_H_INSERT = 1,     // H.Insert (Insert SRH after IPv6 header)
    SRV6_HEADEND_BEHAVIOR_H_ENCAPS = 2,     // H.Encaps (Encapsulate with outer IPv6+SRH)
    SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2 = 3,  // H.Encaps.L2 (L2 frame encapsulation)
    SRV6_HEADEND_BEHAVIOR_H_M_GTP4_D = 4,   // H.M.GTP4.D (GTP-U encapsulation)
};

// Protocol numbers
#define IPPROTO_ROUTING 43

// Routing header types
#define IPV6_SRCRT_TYPE_4 4  // Segment Routing

// IPv6 Segment Routing Header (SRH)
// RFC 8754 Section 2
struct ipv6_sr_hdr {
    __u8 nexthdr;         // Next Header
    __u8 hdrlen;          // Header Extension Length (in 8-octet units, not including first 8)
    __u8 type;            // Routing Type = 4 (Segment Routing)
    __u8 segments_left;   // Segments Left
    __u8 first_segment;   // First Segment (index of the first segment)
    __u8 flags;           // Flags
    __be16 tag;           // Tag
    struct in6_addr segments[0]; // Segment list (variable length)
} __attribute__((packed));

// SRH Flags (RFC 8754)
#define SR6_FLAG1_PROTECTED (1 << 6)
#define SR6_FLAG1_OAM       (1 << 5)
#define SR6_FLAG1_ALERT     (1 << 4)
#define SR6_FLAG1_HMAC      (1 << 3)

#endif // SRV6_H
