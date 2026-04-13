// Headend tail call targets (7 SEC("xdp") programs).
// Included from xdp_prog.c — not compiled standalone.

// ========== Headend v4 Tail Call Targets (3 programs) ==========

SEC("xdp")
int tailcall_headend_v4_h_encaps(struct xdp_md *ctx) { HEADEND_BODY(do_h_encaps_v4, struct iphdr); }

SEC("xdp")
int tailcall_headend_v4_h_encaps_red(struct xdp_md *ctx) { HEADEND_BODY(do_h_encaps_red_v4, struct iphdr); }

SEC("xdp")
int tailcall_headend_v4_h_m_gtp4_d(struct xdp_md *ctx) { HEADEND_BODY(do_h_m_gtp4_d, struct iphdr); }

// ========== Headend v6 Tail Call Targets (4 programs) ==========

SEC("xdp")
int tailcall_headend_v6_h_encaps(struct xdp_md *ctx) { HEADEND_BODY(do_h_encaps_v6, struct ipv6hdr); }

SEC("xdp")
int tailcall_headend_v6_h_encaps_red(struct xdp_md *ctx) { HEADEND_BODY(do_h_encaps_red_v6, struct ipv6hdr); }

SEC("xdp")
int tailcall_headend_v6_h_insert(struct xdp_md *ctx) { HEADEND_BODY(do_h_insert_v6, struct ipv6hdr); }

SEC("xdp")
int tailcall_headend_v6_h_insert_red(struct xdp_md *ctx) { HEADEND_BODY(do_h_insert_red_v6, struct ipv6hdr); }
