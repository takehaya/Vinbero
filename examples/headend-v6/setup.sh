#!/bin/bash
# examples/headend-v6/setup.sh
# Setup H.Encaps (Headend IPv6) demonstration environment

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Set namespace prefix for this example (allows parallel execution)
# Note: Linux interface names are limited to 15 chars, so use short prefix "hv6-"
export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-hv6-}"

source "${SCRIPT_DIR}/../common/topologies/three_router.sh"

# Define namespace and veth names with prefix
ns_host1="${TOPO_NS_PREFIX}host1"
ns_host2="${TOPO_NS_PREFIX}host2"
ns_router1="${TOPO_NS_PREFIX}router1"
ns_router2="${TOPO_NS_PREFIX}router2"
ns_router3="${TOPO_NS_PREFIX}router3"
veth_h1_rt1="${TOPO_NS_PREFIX}h1rt1"
veth_rt1_h1="${TOPO_NS_PREFIX}rt1h1"
veth_h2_rt3="${TOPO_NS_PREFIX}h2rt3"
veth_rt3_h2="${TOPO_NS_PREFIX}rt3h2"
veth_rt1_rt2="${TOPO_NS_PREFIX}rt1rt2"
veth_rt2_rt1="${TOPO_NS_PREFIX}rt2rt1"
veth_rt2_rt3="${TOPO_NS_PREFIX}rt2rt3"
veth_rt3_rt2="${TOPO_NS_PREFIX}rt3rt2"

# Setup base topology
setup_three_router_topology

# Configure IPv6 addresses for hosts (for H.Encaps IPv6 demo)
print_info "Configuring IPv6 addresses for H.Encaps IPv6 demo..."

# Add IPv6 addresses to hosts
run ip netns exec "$ns_host1" ip -6 addr add 2001:1::1/64 dev "$veth_h1_rt1"
run ip netns exec "$ns_host2" ip -6 addr add 2001:2::1/64 dev "$veth_h2_rt3"

# Add IPv6 addresses to routers (host-facing interfaces)
run ip netns exec "$ns_router1" ip -6 addr add 2001:1::2/64 dev "$veth_rt1_h1"
run ip netns exec "$ns_router3" ip -6 addr add 2001:2::2/64 dev "$veth_rt3_h2"

# Add default routes for hosts
run ip netns exec "$ns_host1" ip -6 route add 2001:2::/64 via 2001:1::2
run ip netns exec "$ns_host2" ip -6 route add 2001:1::/64 via 2001:2::2

# Configure SRv6-specific settings for H.Encaps demo
print_info "Configuring SRv6 H.Encaps settings..."

# Configure router1 (Headend - H.Encaps)
ns_sysctl "$ns_router1" net.ipv6.conf.${veth_rt1_h1}.seg6_enabled 1
ns_sysctl "$ns_router1" net.ipv6.conf.${veth_rt1_rt2}.seg6_enabled 1

# Add Linux native T.Encaps for baseline testing (will be replaced by Vinbero)
run ip netns exec "$ns_router1" ip -6 route add 2001:2::/64 encap seg6 mode encap segs fc00:2::1,fc00:3::3 dev "$veth_rt1_rt2"

# Configure End.DX6 for return path (host2 -> host1)
run ip netns exec "$ns_router1" ip -6 route del local fc00:1::1 2>/dev/null || true
run ip netns exec "$ns_router1" ip -6 route add local fc00:1::1/128 encap seg6local action End.DX6 nh6 2001:1::1 dev "$veth_rt1_h1"

# Configure router2 (End)
ns_sysctl "$ns_router2" net.ipv6.conf.${veth_rt2_rt1}.seg6_enabled 1
ns_sysctl "$ns_router2" net.ipv6.conf.${veth_rt2_rt3}.seg6_enabled 1

run ip netns exec "$ns_router2" ip -6 route del local fc00:2::2 2>/dev/null || true
run ip netns exec "$ns_router2" ip -6 route add local fc00:2::1/128 encap seg6local action End dev lo
run ip netns exec "$ns_router2" ip -6 route add local fc00:2::2/128 encap seg6local action End dev lo

# Configure router3 (End.DX6)
ns_sysctl "$ns_router3" net.ipv6.conf.${veth_rt3_h2}.seg6_enabled 1
ns_sysctl "$ns_router3" net.ipv6.conf.${veth_rt3_rt2}.seg6_enabled 1

# Return path: host2 -> host1
run ip netns exec "$ns_router3" ip -6 route add 2001:1::/64 encap seg6 mode encap segs fc00:2::2,fc00:1::1 dev "$veth_rt3_rt2"

# End.DX6 for forward path
run ip netns exec "$ns_router3" ip -6 route del local fc00:3::3 2>/dev/null || true
run ip netns exec "$ns_router3" ip -6 route add local fc00:3::3/128 encap seg6local action End.DX6 nh6 2001:2::1 dev "$veth_rt3_h2"

echo ""
echo "=========================================="
echo "SRv6 H.Encaps (Headend IPv6) Setup Complete!"
echo "=========================================="
echo "Topology:"
echo "  host1 (2001:1::1) <---> router1 (fc00:1::1, H.Encaps/End.DX6)"
echo "  router1 (fc00:12::1) <---> router2 (fc00:2::1, fc00:2::2, End)"
echo "  router2 (fc00:23::2) <---> router3 (fc00:3::3, End.DX6)"
echo "  router3 <---> host2 (2001:2::1)"
echo ""
echo "SRv6 Segment List (forward: host1 -> host2):"
echo "  Trigger: 2001:2::/64"
echo "  Segments: fc00:2::1, fc00:3::3"
echo ""
echo "SRv6 Segment List (return: host2 -> host1):"
echo "  Segments: fc00:2::2, fc00:1::1"
echo ""
print_success "Ready for testing!"
