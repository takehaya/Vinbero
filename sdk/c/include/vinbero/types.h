#ifndef VINBERO_SDK_TYPES_H
#define VINBERO_SDK_TYPES_H

/*
 * Public data structures exchanged between vinbero and plugins.
 *
 *   - struct sid_function_entry: lookup result in sid_function_map
 *   - struct sid_aux_entry     : auxiliary data (union of per-behavior variants)
 *   - struct headend_entry     : lookup result in headend_v4_map / headend_v6_map
 *   - struct tailcall_ctx      : per-CPU context passed across bpf_tail_call
 *
 * These definitions live in src/core/xdp_prog.h and src/core/xdp_tailcall.h.
 * Re-exported here so plugin authors don't need to know the internal layout.
 */

#include "core/xdp_prog.h"
#include "core/xdp_tailcall.h"

/*
 * VINBERO_PLUGIN_AUX_CAST: interpret sid_aux_entry.plugin_raw as a plugin-
 * defined struct. The caller is responsible for ensuring
 *   sizeof(type) <= sizeof(((struct sid_aux_entry *)0)->plugin_raw)
 * typically via _Static_assert at the plugin's translation-unit scope.
 */
#define VINBERO_PLUGIN_AUX_CAST(type, aux_ptr) \
    ((type *)((aux_ptr)->plugin_raw))

/*
 * Well-known typedefs and structs for the BTF-driven CLI encoder.
 *
 * Plugin authors use these when they want their aux JSON to accept
 * human-friendly formats instead of raw byte arrays. The server encoder
 * detects these type names in the plugin's BTF and parses the JSON string
 * value accordingly:
 *
 *   vinbero_mac_t          "aa:bb:cc:dd:ee:ff"
 *   vinbero_ipv4_t         "10.0.0.1"              (network byte order)
 *   vinbero_ipv6_t         "fc00::1"               (network byte order)
 *   vinbero_ipv4_prefix_t  "10.0.0.0/24"
 *   vinbero_ipv6_prefix_t  "fc00::/48"
 *
 * Plugins that stick with plain arrays (e.g. __u8 mac[6]) still work via
 * hex string or JSON number array; special formats are opt-in.
 */
typedef __u8 vinbero_mac_t[6];
typedef __u8 vinbero_ipv4_t[4];
typedef __u8 vinbero_ipv6_t[16];

struct vinbero_ipv4_prefix_t {
    __u8 prefix_len;
    __u8 _pad[3];
    vinbero_ipv4_t addr;
} __attribute__((packed));

struct vinbero_ipv6_prefix_t {
    __u8 prefix_len;
    __u8 _pad[7];
    vinbero_ipv6_t addr;
} __attribute__((packed));

#endif /* VINBERO_SDK_TYPES_H */
