#ifndef XDP_UTIL_H
#define XDP_UTIL_H
#include <linux/types.h>
#include <linux/if_ether.h>

// VLAN header structure (802.1Q)
struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

#endif // XDP_UTIL_H
