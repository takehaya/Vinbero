#!/bin/bash
# examples/common/topologies/three_router.sh
# 3ルーター + 2ホストの基本トポロジー
#
# Topology:
#   host1 --- router1 --- router2 --- router3 --- host2
#

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../netns.sh"
source "${SCRIPT_DIR}/../veth.sh"
source "${SCRIPT_DIR}/../test_utils.sh"

# Check root
check_root

# Configuration variables (can be overridden before sourcing this script)
# Namespace prefix for parallel execution (e.g., "end-", "enddx4-", "test1-")
: ${TOPO_NS_PREFIX:=}

# Host1 configuration
: ${TOPO_HOST1_LO_ADDR:=10.0.1.1/32}
: ${TOPO_HOST1_IPV4_ADDR:=172.0.1.1/24}
: ${TOPO_HOST1_IPV4_GW:=172.0.1.2}

# Host2 configuration
: ${TOPO_HOST2_LO_ADDR:=10.0.1.2/32}
: ${TOPO_HOST2_IPV4_ADDR:=172.0.2.1/24}
: ${TOPO_HOST2_IPV4_GW:=172.0.2.2}

# Router1 configuration
: ${TOPO_ROUTER1_IPV6_LO:=fc00:1::1/128}
: ${TOPO_ROUTER1_IPV4_ADDR:=172.0.1.2/24}
: ${TOPO_ROUTER1_RT2_IPV6:=fc00:12::1/64}

# Router2 configuration
: ${TOPO_ROUTER2_IPV6_LO:=fc00:2::2/128}
: ${TOPO_ROUTER2_RT1_IPV6:=fc00:12::2/64}
: ${TOPO_ROUTER2_RT3_IPV6:=fc00:23::2/64}

# Router3 configuration
: ${TOPO_ROUTER3_IPV6_LO:=fc00:3::3/128}
: ${TOPO_ROUTER3_IPV4_ADDR:=172.0.2.2/24}
: ${TOPO_ROUTER3_RT2_IPV6:=fc00:23::1/64}

# Network prefixes for routing
: ${TOPO_HOST1_NET:=172.0.1.0/24}
: ${TOPO_HOST2_NET:=172.0.2.0/24}
: ${TOPO_HOST1_LO_NET:=10.0.1.0/24}
: ${TOPO_HOST2_LO_NET:=10.0.2.0/24}
: ${TOPO_IPV6_PREFIX_RT1:=fc00:1::/64}
: ${TOPO_IPV6_PREFIX_RT2:=fc00:2::/64}
: ${TOPO_IPV6_PREFIX_RT3:=fc00:3::/64}
: ${TOPO_IPV6_PREFIX_RT1_RT2:=fc00:12::/64}
: ${TOPO_IPV6_PREFIX_RT2_RT3:=fc00:23::/64}

setup_three_router_topology() {
    print_info "Setting up 3-router topology..."

    # Define namespace and interface names with prefix
    local ns_host1="${TOPO_NS_PREFIX}host1"
    local ns_router1="${TOPO_NS_PREFIX}router1"
    local ns_router2="${TOPO_NS_PREFIX}router2"
    local ns_router3="${TOPO_NS_PREFIX}router3"
    local ns_host2="${TOPO_NS_PREFIX}host2"

    # Veth interface names (max 15 chars - Linux limit)
    local veth_h1_rt1="${TOPO_NS_PREFIX}h1rt1"
    local veth_rt1_h1="${TOPO_NS_PREFIX}rt1h1"
    local veth_h2_rt3="${TOPO_NS_PREFIX}h2rt3"
    local veth_rt3_h2="${TOPO_NS_PREFIX}rt3h2"
    local veth_rt1_rt2="${TOPO_NS_PREFIX}rt1rt2"
    local veth_rt2_rt1="${TOPO_NS_PREFIX}rt2rt1"
    local veth_rt2_rt3="${TOPO_NS_PREFIX}rt2rt3"
    local veth_rt3_rt2="${TOPO_NS_PREFIX}rt3rt2"

    # Create namespaces
    print_info "Creating namespaces..."
    create_netns "$ns_host1"
    create_netns "$ns_router1"
    create_netns "$ns_router2"
    create_netns "$ns_router3"
    create_netns "$ns_host2"

    # Create veth pairs: host1 <-> router1
    print_info "Creating veth pairs..."
    create_veth_pair "$veth_h1_rt1" "$ns_host1" "$veth_rt1_h1" "$ns_router1"

    # Configure host1
    run ip netns exec "$ns_host1" ip addr add ${TOPO_HOST1_LO_ADDR} dev lo
    run ip netns exec "$ns_host1" ip addr add ${TOPO_HOST1_IPV4_ADDR} dev "$veth_h1_rt1"
    run ip netns exec "$ns_host1" ip route add ${TOPO_HOST2_LO_NET} via ${TOPO_HOST1_IPV4_GW}
    run ip netns exec "$ns_host1" ip route add ${TOPO_HOST2_NET} via ${TOPO_HOST1_IPV4_GW}

    # Configure router1
    run ip netns exec "$ns_router1" ip -6 addr add ${TOPO_ROUTER1_IPV6_LO} dev lo
    run ip netns exec "$ns_router1" ip addr add ${TOPO_ROUTER1_IPV4_ADDR} dev "$veth_rt1_h1"
    ns_sysctl "$ns_router1" net.ipv4.conf.all.forwarding 1
    ns_sysctl "$ns_router1" net.ipv6.conf.all.forwarding 1
    ns_sysctl "$ns_router1" net.ipv4.conf.all.rp_filter 0

    # Create router2
    run ip netns exec "$ns_router2" ip -6 addr add ${TOPO_ROUTER2_IPV6_LO} dev lo
    ns_sysctl "$ns_router2" net.ipv4.conf.all.forwarding 1
    ns_sysctl "$ns_router2" net.ipv6.conf.all.forwarding 1
    ns_sysctl "$ns_router2" net.ipv4.conf.all.rp_filter 0

    # Create veth pairs: router3 <-> host2
    create_veth_pair "$veth_h2_rt3" "$ns_host2" "$veth_rt3_h2" "$ns_router3"

    # Configure host2
    run ip netns exec "$ns_host2" ip addr add ${TOPO_HOST2_LO_ADDR} dev lo
    run ip netns exec "$ns_host2" ip addr add ${TOPO_HOST2_IPV4_ADDR} dev "$veth_h2_rt3"
    run ip netns exec "$ns_host2" ip route add ${TOPO_HOST1_LO_NET} via ${TOPO_HOST2_IPV4_GW}
    run ip netns exec "$ns_host2" ip route add ${TOPO_HOST1_NET} via ${TOPO_HOST2_IPV4_GW}

    # Configure router3
    run ip netns exec "$ns_router3" ip -6 addr add ${TOPO_ROUTER3_IPV6_LO} dev lo
    run ip netns exec "$ns_router3" ip addr add ${TOPO_ROUTER3_IPV4_ADDR} dev "$veth_rt3_h2"
    ns_sysctl "$ns_router3" net.ipv4.conf.all.forwarding 1
    ns_sysctl "$ns_router3" net.ipv6.conf.all.forwarding 1
    ns_sysctl "$ns_router3" net.ipv4.conf.all.rp_filter 0

    # Connect router1 and router2
    create_veth_pair "$veth_rt1_rt2" "$ns_router1" "$veth_rt2_rt1" "$ns_router2"
    run ip netns exec "$ns_router1" ip addr add ${TOPO_ROUTER1_RT2_IPV6} dev "$veth_rt1_rt2"
    run ip netns exec "$ns_router1" ip -6 route add ${TOPO_IPV6_PREFIX_RT2_RT3} via ${TOPO_ROUTER2_RT1_IPV6%/*}
    run ip netns exec "$ns_router1" ip -6 route add ${TOPO_IPV6_PREFIX_RT2} via ${TOPO_ROUTER2_RT1_IPV6%/*}
    run ip netns exec "$ns_router1" ip -6 route add ${TOPO_IPV6_PREFIX_RT3} via ${TOPO_ROUTER2_RT1_IPV6%/*}

    run ip netns exec "$ns_router2" ip addr add ${TOPO_ROUTER2_RT1_IPV6} dev "$veth_rt2_rt1"
    run ip netns exec "$ns_router2" ip -6 route add ${TOPO_IPV6_PREFIX_RT1} via ${TOPO_ROUTER1_RT2_IPV6%/*}
    run ip netns exec "$ns_router2" ip -6 route add ${TOPO_IPV6_PREFIX_RT1_RT2} via ${TOPO_ROUTER1_RT2_IPV6%/*}

    # Connect router2 and router3
    create_veth_pair "$veth_rt2_rt3" "$ns_router2" "$veth_rt3_rt2" "$ns_router3"
    run ip netns exec "$ns_router2" ip addr add ${TOPO_ROUTER2_RT3_IPV6} dev "$veth_rt2_rt3"
    run ip netns exec "$ns_router2" ip -6 route add ${TOPO_IPV6_PREFIX_RT3} via ${TOPO_ROUTER3_RT2_IPV6%/*}
    run ip netns exec "$ns_router2" ip -6 route add ${TOPO_IPV6_PREFIX_RT2_RT3} via ${TOPO_ROUTER3_RT2_IPV6%/*}

    run ip netns exec "$ns_router3" ip addr add ${TOPO_ROUTER3_RT2_IPV6} dev "$veth_rt3_rt2"
    run ip netns exec "$ns_router3" ip -6 route add ${TOPO_IPV6_PREFIX_RT1} via ${TOPO_ROUTER2_RT3_IPV6%/*}
    run ip netns exec "$ns_router3" ip -6 route add ${TOPO_IPV6_PREFIX_RT2} via ${TOPO_ROUTER2_RT3_IPV6%/*}
    run ip netns exec "$ns_router3" ip -6 route add ${TOPO_IPV6_PREFIX_RT1_RT2} via ${TOPO_ROUTER2_RT3_IPV6%/*}

    # Enable SRv6 on all routers
    for ns in "$ns_router1" "$ns_router2" "$ns_router3"; do
        ns_enable_srv6 "$ns"
    done

    print_success "3-router topology created!"
}

teardown_three_router_topology() {
    print_info "Tearing down 3-router topology..."

    # Define namespace names with prefix
    local ns_host1="${TOPO_NS_PREFIX}host1"
    local ns_router1="${TOPO_NS_PREFIX}router1"
    local ns_router2="${TOPO_NS_PREFIX}router2"
    local ns_router3="${TOPO_NS_PREFIX}router3"
    local ns_host2="${TOPO_NS_PREFIX}host2"

    delete_netns "$ns_host1"
    delete_netns "$ns_router1"
    delete_netns "$ns_router2"
    delete_netns "$ns_router3"
    delete_netns "$ns_host2"

    print_success "Topology removed!"
}

# Export functions
export -f setup_three_router_topology
export -f teardown_three_router_topology
