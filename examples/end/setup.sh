#!/bin/bash
# examples/end/setup.sh
# Setup End operation demonstration environment

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Set namespace prefix for this example (allows parallel execution)
# Default: use directory name (e.g., "end" -> "end-")
# Override with TOPO_NS_PREFIX environment variable if needed
EXAMPLE_NAME="$(basename "$SCRIPT_DIR")"
export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-${EXAMPLE_NAME}-}"

source "${SCRIPT_DIR}/../common/topologies/three_router.sh"

# Define namespace and veth names with prefix
ns_router1="${TOPO_NS_PREFIX}router1"
ns_router2="${TOPO_NS_PREFIX}router2"
ns_router3="${TOPO_NS_PREFIX}router3"
veth_rt1_h1="${TOPO_NS_PREFIX}rt1h1"
veth_rt1_rt2="${TOPO_NS_PREFIX}rt1rt2"
veth_rt2_rt1="${TOPO_NS_PREFIX}rt2rt1"
veth_rt2_rt3="${TOPO_NS_PREFIX}rt2rt3"
veth_rt3_h2="${TOPO_NS_PREFIX}rt3h2"
veth_rt3_rt2="${TOPO_NS_PREFIX}rt3rt2"

# Setup base topology
setup_three_router_topology

# Configure SRv6-specific settings for End operation demo
print_info "Configuring SRv6 End operation settings..."

# Configure router1 (End.DX4)
ns_sysctl "$ns_router1" net.ipv6.conf.${veth_rt1_h1}.seg6_enabled 1
ns_sysctl "$ns_router1" net.ipv6.conf.${veth_rt1_rt2}.seg6_enabled 1
ns_sysctl "$ns_router1" net.ipv4.conf.${veth_rt1_rt2}.rp_filter 0
ns_sysctl "$ns_router1" net.ipv4.conf.${veth_rt1_h1}.rp_filter 0

run ip netns exec "$ns_router1" ip route add 172.0.2.0/24 encap seg6 mode encap segs fc00:2::1,fc00:3::3 dev "$veth_rt1_rt2"
run ip netns exec "$ns_router1" ip -6 route del local fc00:1::1
run ip netns exec "$ns_router1" ip -6 route add local fc00:1::1/128 encap seg6local action End.DX4 nh4 172.0.1.1 dev "$veth_rt1_h1"

# Configure router2 (End) - Linux native for testing
ns_sysctl "$ns_router2" net.ipv6.conf.${veth_rt2_rt1}.seg6_enabled 1
ns_sysctl "$ns_router2" net.ipv6.conf.${veth_rt2_rt3}.seg6_enabled 1

run ip netns exec "$ns_router2" ip -6 route del local fc00:2::2
run ip netns exec "$ns_router2" ip -6 route add local fc00:2::1/128 encap seg6local action End dev lo
run ip netns exec "$ns_router2" ip -6 route add local fc00:2::2/128 encap seg6local action End dev lo

# Configure router3 (End.DX4)
ns_sysctl "$ns_router3" net.ipv6.conf.${veth_rt3_h2}.seg6_enabled 1
ns_sysctl "$ns_router3" net.ipv6.conf.${veth_rt3_rt2}.seg6_enabled 1
ns_sysctl "$ns_router3" net.ipv4.conf.${veth_rt3_rt2}.rp_filter 0
ns_sysctl "$ns_router3" net.ipv4.conf.${veth_rt3_h2}.rp_filter 0

run ip netns exec "$ns_router3" ip route add 172.0.1.0/24 encap seg6 mode encap segs fc00:2::2,fc00:1::1 dev "$veth_rt3_rt2"
run ip netns exec "$ns_router3" ip -6 route del local fc00:3::3
run ip netns exec "$ns_router3" ip -6 route add local fc00:3::3/128 encap seg6local action End.DX4 nh4 172.0.2.1 dev "$veth_rt3_h2"

echo ""
echo "=========================================="
echo "SRv6 End Setup Complete!"
echo "=========================================="
echo "Topology:"
echo "  host1 (172.0.1.1) <---> router1 (fc00:1::1, End.DX4)"
echo "  router1 (fc00:12::1) <---> router2 (fc00:2::1, fc00:2::2, End)"
echo "  router2 (fc00:23::2) <---> router3 (fc00:3::3, End.DX4)"
echo "  router3 <---> host2 (172.0.2.1)"
echo ""
echo "SRv6 Segment List:"
echo "  host1 -> host2: fc00:2::1, fc00:3::3"
echo "  host2 -> host1: fc00:2::2, fc00:1::1"
echo ""
print_success "Ready for testing!"
