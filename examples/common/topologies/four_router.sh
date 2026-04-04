#!/bin/bash
# examples/common/topologies/four_router.sh
# 4ルーター + 4ホストのP2MPトポロジー
#
# Topology:
#                                  ┌── router3 ──┬── host2
#   host1 ── router1 ── router2 ──┤              └── host3
#                                  └── router4 ──── host4
#

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../netns.sh"
source "${SCRIPT_DIR}/../veth.sh"
source "${SCRIPT_DIR}/../test_utils.sh"

check_root

: ${TOPO_NS_PREFIX:=}

setup_four_router_topology() {
    print_info "Setting up 4-router P2MP topology..."

    local ns_host1="${TOPO_NS_PREFIX}host1"
    local ns_host2="${TOPO_NS_PREFIX}host2"
    local ns_host3="${TOPO_NS_PREFIX}host3"
    local ns_host4="${TOPO_NS_PREFIX}host4"
    local ns_router1="${TOPO_NS_PREFIX}router1"
    local ns_router2="${TOPO_NS_PREFIX}router2"
    local ns_router3="${TOPO_NS_PREFIX}router3"
    local ns_router4="${TOPO_NS_PREFIX}router4"

    # Veth names (max 15 chars)
    local veth_h1_rt1="${TOPO_NS_PREFIX}h1rt1"
    local veth_rt1_h1="${TOPO_NS_PREFIX}rt1h1"
    local veth_h2_rt3="${TOPO_NS_PREFIX}h2rt3"
    local veth_rt3_h2="${TOPO_NS_PREFIX}rt3h2"
    local veth_h3_rt3="${TOPO_NS_PREFIX}h3rt3"
    local veth_rt3_h3="${TOPO_NS_PREFIX}rt3h3"
    local veth_h4_rt4="${TOPO_NS_PREFIX}h4rt4"
    local veth_rt4_h4="${TOPO_NS_PREFIX}rt4h4"
    local veth_rt1_rt2="${TOPO_NS_PREFIX}rt1rt2"
    local veth_rt2_rt1="${TOPO_NS_PREFIX}rt2rt1"
    local veth_rt2_rt3="${TOPO_NS_PREFIX}rt2rt3"
    local veth_rt3_rt2="${TOPO_NS_PREFIX}rt3rt2"
    local veth_rt2_rt4="${TOPO_NS_PREFIX}rt2rt4"
    local veth_rt4_rt2="${TOPO_NS_PREFIX}rt4rt2"

    # Create namespaces
    print_info "Creating namespaces..."
    for ns in "$ns_host1" "$ns_host2" "$ns_host3" "$ns_host4" \
              "$ns_router1" "$ns_router2" "$ns_router3" "$ns_router4"; do
        create_netns "$ns"
    done

    # === host1 <-> router1 ===
    create_veth_pair "$veth_h1_rt1" "$ns_host1" "$veth_rt1_h1" "$ns_router1"

    # === host2 <-> router3 ===
    create_veth_pair "$veth_h2_rt3" "$ns_host2" "$veth_rt3_h2" "$ns_router3"

    # === host3 <-> router3 (second port) ===
    create_veth_pair "$veth_h3_rt3" "$ns_host3" "$veth_rt3_h3" "$ns_router3"

    # === host4 <-> router4 ===
    create_veth_pair "$veth_h4_rt4" "$ns_host4" "$veth_rt4_h4" "$ns_router4"

    # === router1 <-> router2 ===
    create_veth_pair "$veth_rt1_rt2" "$ns_router1" "$veth_rt2_rt1" "$ns_router2"

    # === router2 <-> router3 ===
    create_veth_pair "$veth_rt2_rt3" "$ns_router2" "$veth_rt3_rt2" "$ns_router3"

    # === router2 <-> router4 ===
    create_veth_pair "$veth_rt2_rt4" "$ns_router2" "$veth_rt4_rt2" "$ns_router4"

    # --- Router loopbacks ---
    run ip netns exec "$ns_router1" ip -6 addr add fc00:1::1/128 dev lo
    run ip netns exec "$ns_router2" ip -6 addr add fc00:2::2/128 dev lo
    run ip netns exec "$ns_router3" ip -6 addr add fc00:3::3/128 dev lo
    run ip netns exec "$ns_router4" ip -6 addr add fc00:4::4/128 dev lo

    # --- Enable forwarding on all routers ---
    for ns in "$ns_router1" "$ns_router2" "$ns_router3" "$ns_router4"; do
        ns_sysctl "$ns" net.ipv4.conf.all.forwarding 1
        ns_sysctl "$ns" net.ipv6.conf.all.forwarding 1
        ns_sysctl "$ns" net.ipv4.conf.all.rp_filter 0
    done

    # --- Router1 <-> Router2 link (fc00:12::/64) ---
    run ip netns exec "$ns_router1" ip addr add fc00:12::1/64 dev "$veth_rt1_rt2"
    run ip netns exec "$ns_router2" ip addr add fc00:12::2/64 dev "$veth_rt2_rt1"

    # --- Router2 <-> Router3 link (fc00:23::/64) ---
    run ip netns exec "$ns_router2" ip addr add fc00:23::2/64 dev "$veth_rt2_rt3"
    run ip netns exec "$ns_router3" ip addr add fc00:23::1/64 dev "$veth_rt3_rt2"

    # --- Router2 <-> Router4 link (fc00:24::/64) ---
    run ip netns exec "$ns_router2" ip addr add fc00:24::2/64 dev "$veth_rt2_rt4"
    run ip netns exec "$ns_router4" ip addr add fc00:24::1/64 dev "$veth_rt4_rt2"

    # --- IPv6 routes ---
    # Router1: reach router2,3,4 via router2
    run ip netns exec "$ns_router1" ip -6 route add fc00:2::/64 via fc00:12::2
    run ip netns exec "$ns_router1" ip -6 route add fc00:3::/64 via fc00:12::2
    run ip netns exec "$ns_router1" ip -6 route add fc00:4::/64 via fc00:12::2
    run ip netns exec "$ns_router1" ip -6 route add fc00:23::/64 via fc00:12::2
    run ip netns exec "$ns_router1" ip -6 route add fc00:24::/64 via fc00:12::2

    # Router2: reach router1 via rt1, router3 via rt3, router4 via rt4
    run ip netns exec "$ns_router2" ip -6 route add fc00:1::/64 via fc00:12::1
    run ip netns exec "$ns_router2" ip -6 route add fc00:3::/64 via fc00:23::1
    run ip netns exec "$ns_router2" ip -6 route add fc00:4::/64 via fc00:24::1

    # Router3: reach everything via router2
    run ip netns exec "$ns_router3" ip -6 route add fc00:1::/64 via fc00:23::2
    run ip netns exec "$ns_router3" ip -6 route add fc00:2::/64 via fc00:23::2
    run ip netns exec "$ns_router3" ip -6 route add fc00:4::/64 via fc00:23::2
    run ip netns exec "$ns_router3" ip -6 route add fc00:12::/64 via fc00:23::2
    run ip netns exec "$ns_router3" ip -6 route add fc00:24::/64 via fc00:23::2

    # Router4: reach everything via router2
    run ip netns exec "$ns_router4" ip -6 route add fc00:1::/64 via fc00:24::2
    run ip netns exec "$ns_router4" ip -6 route add fc00:2::/64 via fc00:24::2
    run ip netns exec "$ns_router4" ip -6 route add fc00:3::/64 via fc00:24::2
    run ip netns exec "$ns_router4" ip -6 route add fc00:12::/64 via fc00:24::2
    run ip netns exec "$ns_router4" ip -6 route add fc00:23::/64 via fc00:24::2

    # Enable SRv6
    for ns in "$ns_router1" "$ns_router2" "$ns_router3" "$ns_router4"; do
        ns_enable_srv6 "$ns"
    done

    print_success "4-router P2MP topology created!"
}

teardown_four_router_topology() {
    print_info "Tearing down 4-router P2MP topology..."
    for ns in host1 host2 host3 host4 router1 router2 router3 router4; do
        delete_netns "${TOPO_NS_PREFIX}${ns}"
    done
    print_success "Topology removed!"
}

export -f setup_four_router_topology
export -f teardown_four_router_topology
