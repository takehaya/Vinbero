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
    SRV6_LOCAL_ACTION_END_BPF = 16,
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

// ========== SRv6 Encap Mode (Transit behavior) ==========
// Maps to Srv6EncapMode enum in protobuf
enum srv6_encap_mode {
    SRV6_ENCAP_MODE_UNSPECIFIED = 0,
    SRV6_ENCAP_MODE_INLINE = 1,              // T.Insert
    SRV6_ENCAP_MODE_ENCAP = 2,               // T.Encaps
    SRV6_ENCAP_MODE_L2ENCAP = 3,             // T.Encaps.L2
    SRV6_ENCAP_MODE_ENCAP_T_M_GTP6_D = 4,    // T.M.GTP6.D
    SRV6_ENCAP_MODE_ENCAP_T_M_GTP6_D_DI = 5, // T.M.GTP6.D.Di
    SRV6_ENCAP_MODE_ENCAP_H_M_GTP4_D = 6,    // H.M.GTP4.D
};

#endif // SRV6_H
