#!/usr/bin/env bash
# Two PE nodes joined by an IPv6 underlay, and empty pod namespaces the CNI
# plugin wires up in test.sh.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
source "$EXAMPLE_DIR/../common/netns.sh"
source "$EXAMPLE_DIR/../common/veth.sh"
check_root

for ns in "${NAMESPACES[@]}"; do
    if ip netns list | awk '{print $1}' | grep -Fxq "$ns"; then
        print_error "$ns already exists; run teardown.sh first"
        exit 1
    fi
done
if ip link show cnil3-u1 >/dev/null 2>&1; then
    print_error "cnil3-u1 already exists"
    exit 1
fi

created=()
cleanup_partial() {
    for ns in "${created[@]}"; do delete_netns "$ns"; done
    ip link delete cnil3-u1 2>/dev/null || true
}
trap cleanup_partial EXIT
for ns in "${NAMESPACES[@]}"; do
    ip netns add "$ns"
    created+=("$ns")
    ip -n "$ns" link set lo up
done

ip link add cnil3-u1 type veth peer name cnil3-u2
ip link set cnil3-u1 netns "$PE1"
ip link set cnil3-u2 netns "$PE2"
ip -n "$PE1" link set cnil3-u1 name eth1
ip -n "$PE2" link set cnil3-u2 name eth1
ip -n "$PE1" link set eth1 up
ip -n "$PE2" link set eth1 up

configure_veth "$PE1" eth1 2001:db8:12::1/64
configure_veth "$PE2" eth1 2001:db8:12::2/64
configure_veth "$PE1" lo 2001:db8:ff::1/128
configure_veth "$PE2" lo 2001:db8:ff::2/128
ip -n "$PE1" -6 route add 2001:db8:ff::2/128 via 2001:db8:12::2 src 2001:db8:ff::1
ip -n "$PE2" -6 route add 2001:db8:ff::1/128 via 2001:db8:12::1 src 2001:db8:ff::2
ip -n "$PE1" -6 route add fd00:2::/48 via 2001:db8:12::2
ip -n "$PE2" -6 route add fd00:1::/48 via 2001:db8:12::1
for ns in "$PE1" "$PE2"; do
    ns_sysctl "$ns" net.ipv4.ip_forward 1
    ns_sysctl "$ns" net.ipv6.conf.all.forwarding 1
    ns_sysctl "$ns" net.ipv6.conf.all.seg6_enabled 1
    ns_sysctl "$ns" net.ipv4.conf.all.rp_filter 0
    ns_sysctl "$ns" net.ipv4.conf.default.rp_filter 0
done
trap - EXIT
print_success "PE1 -- PE2 underlay and pod namespaces ready"
