// Vinbero BPF program orchestrator.
// All code is in a single compilation unit (required by bpf2go).
// Implementation is split into separate .c files included below.

#include <linux/types.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <stdbool.h>
#include <stddef.h>

#include "core/xdp_prog.h"
#include "core/xdp_map.h"
#include "core/srv6.h"
#include "headend/srv6_headend_utils.h"
#include "headend/srv6_headend.h"
#include "headend/srv6_encaps.h"
#include "headend/srv6_insert.h"
#include "core/xdp_stats.h"
#include "endpoint/srv6_endpoint.h"
#include "endpoint/srv6_end_b6.h"
#include "l2vpn/bum_meta.h"
#include "core/srv6_gtp.h"
#include "endpoint/srv6_gtp_endpoint.h"
#include "endpoint/srv6_gtp_encap.h"
#include "headend/srv6_gtp_headend.h"

char _license[] SEC("license") = "GPL";

// ========== BPF programs & pipeline ==========
// Include order reflects dependency chain.

#include "core/xdp_tailcall_macros.h"
#include "endpoint/tailcall_endpoint.c"
#include "headend/tailcall_headend.c"
#include "dispatch/srv6_dispatch.c"
#include "headend/srv6_encaps_l2.h"
#include "dispatch/l2_headend.c"
#include "xdp_main.c"
#include "l2vpn/tc_bum.h"
#include "l2vpn/tc_prog.c"
