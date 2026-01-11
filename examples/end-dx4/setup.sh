#!/bin/bash
# examples/end-dx4/setup.sh
# Setup End.DX4 demonstration environment

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Set namespace prefix for this example (allows parallel execution)
# Note: Linux interface names are limited to 15 chars, so use short prefix "dx4-"
export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-dx4-}"

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

# Configure SRv6-specific settings for End.DX4 demo
print_info "Configuring SRv6 End.DX4 settings..."

# Configure router1 (Headend - H.Encaps using Linux native)
ns_sysctl "$ns_router1" net.ipv6.conf.${veth_rt1_h1}.seg6_enabled 1
ns_sysctl "$ns_router1" net.ipv6.conf.${veth_rt1_rt2}.seg6_enabled 1
ns_sysctl "$ns_router1" net.ipv4.conf.${veth_rt1_rt2}.rp_filter 0
ns_sysctl "$ns_router1" net.ipv4.conf.${veth_rt1_h1}.rp_filter 0

# Add Linux native T.Encaps for forward path (host1 -> host2)
run ip netns exec "$ns_router1" ip route add 172.0.2.0/24 encap seg6 mode encap segs fc00:2::1,fc00:3::3 dev "$veth_rt1_rt2"

# Configure End.DX4 for return path (host2 -> host1)
run ip netns exec "$ns_router1" ip -6 route del local fc00:1::1 2>/dev/null || true
run ip netns exec "$ns_router1" ip -6 route add local fc00:1::1/128 encap seg6local action End.DX4 nh4 172.0.1.1 dev "$veth_rt1_h1"

# Configure router2 (End)
ns_sysctl "$ns_router2" net.ipv6.conf.${veth_rt2_rt1}.seg6_enabled 1
ns_sysctl "$ns_router2" net.ipv6.conf.${veth_rt2_rt3}.seg6_enabled 1

run ip netns exec "$ns_router2" ip -6 route del local fc00:2::2 2>/dev/null || true
run ip netns exec "$ns_router2" ip -6 route add local fc00:2::1/128 encap seg6local action End dev lo
run ip netns exec "$ns_router2" ip -6 route add local fc00:2::2/128 encap seg6local action End dev lo

# Configure router3 (End.DX4 - Vinbero will handle this)
ns_sysctl "$ns_router3" net.ipv6.conf.${veth_rt3_h2}.seg6_enabled 1
ns_sysctl "$ns_router3" net.ipv6.conf.${veth_rt3_rt2}.seg6_enabled 1
ns_sysctl "$ns_router3" net.ipv4.conf.${veth_rt3_rt2}.rp_filter 0
ns_sysctl "$ns_router3" net.ipv4.conf.${veth_rt3_h2}.rp_filter 0

# Return path: host2 -> host1 (Linux native on router3)
run ip netns exec "$ns_router3" ip route add 172.0.1.0/24 encap seg6 mode encap segs fc00:2::2,fc00:1::1 dev "$veth_rt3_rt2"

# Add Linux native End.DX4 for baseline testing (will be replaced by Vinbero)
run ip netns exec "$ns_router3" ip -6 route del local fc00:3::3 2>/dev/null || true
run ip netns exec "$ns_router3" ip -6 route add local fc00:3::3/128 encap seg6local action End.DX4 nh4 172.0.2.1 dev "$veth_rt3_h2"

echo ""
echo "=========================================="
echo "SRv6 End.DX4 Setup Complete!"
echo "=========================================="
echo "Topology:"
echo "  host1 (172.0.1.1) <---> router1 (fc00:1::1, H.Encaps/End.DX4)"
echo "  router1 (fc00:12::1) <---> router2 (fc00:2::1, fc00:2::2, End)"
echo "  router2 (fc00:23::2) <---> router3 (fc00:3::3, End.DX4) <- Vinbero"
echo "  router3 <---> host2 (172.0.2.1)"
echo ""
echo "SRv6 Segment List (forward: host1 -> host2):"
echo "  Trigger: 172.0.2.0/24"
echo "  Segments: fc00:2::1, fc00:3::3"
echo "  End.DX4 at fc00:3::3 will be handled by Vinbero XDP"
echo ""
echo "SRv6 Segment List (return: host2 -> host1):"
echo "  Segments: fc00:2::2, fc00:1::1"
echo ""
print_success "Ready for testing!"
