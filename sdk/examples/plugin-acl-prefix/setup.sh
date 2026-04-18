#!/bin/bash
# sdk/examples/plugin-acl-prefix/setup.sh
# Setup three-router topology for the prefix-ACL plugin demo.

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMMON_DIR="${SCRIPT_DIR}/../../../examples/common"

# Short prefix to stay within 15-char Linux interface name limit
export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-plgacl-}"

source "${COMMON_DIR}/topologies/three_router.sh"

ns_router1="${TOPO_NS_PREFIX}router1"
ns_router2="${TOPO_NS_PREFIX}router2"
ns_router3="${TOPO_NS_PREFIX}router3"

setup_three_router_topology

# Add SRv6 baseline routes. Replace existing routes if they exist.
ip netns exec "$ns_router1" ip -6 route replace fc00:3::/64 encap seg6 mode encap segs fc00:2::1,fc00:3::3 dev "${TOPO_NS_PREFIX}rt1rt2"
ip netns exec "$ns_router3" ip -6 route replace fc00:1::/64 encap seg6 mode encap segs fc00:2::2,fc00:1::1 dev "${TOPO_NS_PREFIX}rt3rt2"

# host1 needs an IPv6 address + default route through router1 so that
# `ping6 fc00:3::3` from host1 actually leaves the netns and triggers
# router1's seg6 encap rule.
ip netns exec "$ns_router1" ip addr add fc00:101::2/64 dev "${TOPO_NS_PREFIX}rt1h1"
ip netns exec "${TOPO_NS_PREFIX}host1" ip addr add fc00:101::1/64 dev "${TOPO_NS_PREFIX}h1rt1"
ip netns exec "${TOPO_NS_PREFIX}host1" ip -6 route add default via fc00:101::2

echo ""
echo "Prefix-ACL plugin demo topology ready."
echo "router2 will run Vinbero with the plugin at SIDs fc00:2::33/128 (drop) and fc00:2::34/128 (pass)"
