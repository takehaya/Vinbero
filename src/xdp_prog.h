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


// https://github.com/cloudflare/xdpcap
// struct bpf_map_def SEC("maps") xdpcap_hook = XDPCAP_HOOK();
struct xdpcap_hook {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 5);
} xdpcap_hook SEC(".maps");

#endif // XDP_PROG_H
