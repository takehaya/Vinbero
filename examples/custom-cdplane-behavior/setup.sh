#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
source "$EXAMPLE_DIR/../common/netns.sh"
source "$EXAMPLE_DIR/../common/veth.sh"
check_root

# Refuse existing names; creation also uses non-replacing ip commands.
for ns in "${NAMESPACES[@]}"; do
    if ip netns list | awk '{print $1}' | grep -Fxq "$ns"; then
        print_error "$ns already exists; run teardown.sh first"
        exit 1
    fi
done
for link in cpdp-h1 cpdp-p1c cpdp-p1 cpdp-p2 cpdp-p2c cpdp-h2; do
    if ip link show "$link" >/dev/null 2>&1; then
        print_error "$link already exists"
        exit 1
    fi
done

created=()
created_links=()
cleanup_partial() {
    for ns in "${created[@]}"; do delete_netns "$ns"; done
    for link in "${created_links[@]}"; do ip link delete "$link" 2>/dev/null || true; done
}
trap cleanup_partial EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
for ns in "${NAMESPACES[@]}"; do
    ip netns add "$ns"
    created+=("$ns")
    ip -n "$ns" link set lo up
done
create_pair() {
    ip link add "$1" type veth peer name "$3"
    created_links+=("$1")
    ip link set "$1" netns "$2"
    ip link set "$3" netns "$4"
    ip -n "$2" link set "$1" up
    ip -n "$4" link set "$3" up
}
create_pair cpdp-h1 "$HOST1" cpdp-p1c "$PE1"
create_pair cpdp-p1 "$PE1" cpdp-p2 "$PE2"
create_pair cpdp-p2c "$PE2" cpdp-h2 "$HOST2"
ip -n "$HOST1" link set cpdp-h1 name eth0
ip -n "$PE1" link set cpdp-p1c name eth2
ip -n "$PE1" link set cpdp-p1 name eth1
ip -n "$PE2" link set cpdp-p2 name eth1
ip -n "$PE2" link set cpdp-p2c name eth2
ip -n "$HOST2" link set cpdp-h2 name eth0

configure_veth "$HOST1" eth0 10.1.0.10/24
configure_veth "$PE1" eth2 10.1.0.1/24
configure_veth "$PE2" eth2 10.2.0.1/24
configure_veth "$HOST2" eth0 10.2.0.10/24
configure_veth "$PE1" eth1 2001:db8:12::1/64
configure_veth "$PE2" eth1 2001:db8:12::2/64
configure_veth "$PE1" lo 2001:db8:ff::1/128
configure_veth "$PE2" lo 2001:db8:ff::2/128
ip -n "$HOST1" route add 10.2.0.0/24 via 10.1.0.1
ip -n "$HOST2" route add 10.1.0.0/24 via 10.2.0.1
ip -n "$PE1" -6 route add 2001:db8:ff::2/128 via 2001:db8:12::2 src 2001:db8:ff::1
ip -n "$PE2" -6 route add 2001:db8:ff::1/128 via 2001:db8:12::1 src 2001:db8:ff::2
ip -n "$PE1" -6 route add fd00:200::/48 via 2001:db8:12::2
ip -n "$PE2" -6 route add fd00:100::/48 via 2001:db8:12::1
for ns in "$PE1" "$PE2"; do
    ns_sysctl "$ns" net.ipv4.ip_forward 1
    ns_sysctl "$ns" net.ipv6.conf.all.forwarding 1
    ns_sysctl "$ns" net.ipv4.conf.all.rp_filter 0
    ns_sysctl "$ns" net.ipv4.conf.default.rp_filter 0
    for dev in eth1 eth2; do
        ns_sysctl "$ns" "net.ipv4.conf.$dev.rp_filter" 0
    done
done
trap - EXIT
print_success "host1 -- PE1 (Cplane) -- PE2 (Cplane + Dplane) -- host2 ready"
