#!/bin/bash
# examples/plugin-counter/setup.sh
# Setup plugin counter demonstration environment

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Short prefix to stay within 15-char Linux interface name limit
export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-plgcnt-}"

source "${SCRIPT_DIR}/../common/topologies/three_router.sh"

ns_router1="${TOPO_NS_PREFIX}router1"
ns_router2="${TOPO_NS_PREFIX}router2"
ns_router3="${TOPO_NS_PREFIX}router3"

setup_three_router_topology

# Add SRv6 routes using Linux native (baseline)
# Replace existing routes if they exist (three_router topology may add plain routes)
ip netns exec "$ns_router1" ip -6 route replace fc00:3::/64 encap seg6 mode encap segs fc00:2::1,fc00:3::3 dev "${TOPO_NS_PREFIX}rt1rt2"
ip netns exec "$ns_router3" ip -6 route replace fc00:1::/64 encap seg6 mode encap segs fc00:2::2,fc00:1::1 dev "${TOPO_NS_PREFIX}rt3rt2"

echo ""
echo "Plugin demo topology ready."
echo "router2 will run Vinbero with the plugin at SID fc00:2::32/128"
