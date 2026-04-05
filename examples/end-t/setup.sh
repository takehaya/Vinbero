#!/bin/bash
# examples/end-t/setup.sh
# Setup End.T demonstration environment (endpoint with VRF table lookup)
#
# End.T is like End but performs FIB lookup in a specific VRF routing table
# instead of the default table. It does NOT decapsulate - it just does SRH
# processing (update DA, decrement SL) and forwards using VRF FIB lookup.

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Set namespace prefix for this example
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

print_info "Configuring SRv6 End.T settings..."

# Load VRF kernel module
modprobe vrf 2>/dev/null || true

# Configure router1 (End.DX4 + H.Encaps)
ns_sysctl "$ns_router1" net.ipv6.conf.${veth_rt1_h1}.seg6_enabled 1
ns_sysctl "$ns_router1" net.ipv6.conf.${veth_rt1_rt2}.seg6_enabled 1
ns_sysctl "$ns_router1" net.ipv4.conf.${veth_rt1_rt2}.rp_filter 0
ns_sysctl "$ns_router1" net.ipv4.conf.${veth_rt1_h1}.rp_filter 0

# Forward path: host1 -> host2 (encap with SID list)
run ip netns exec "$ns_router1" ip route add 172.0.2.0/24 encap seg6 mode encap segs fc00:2::1,fc00:3::3 dev "$veth_rt1_rt2"

# Return path: End.DX4 for host2 -> host1
run ip netns exec "$ns_router1" ip -6 route del local fc00:1::1
run ip netns exec "$ns_router1" ip -6 route add local fc00:1::1/128 encap seg6local action End.DX4 nh4 172.0.1.1 dev "$veth_rt1_h1"

# Configure router2 (End.T with VRF)
ns_sysctl "$ns_router2" net.ipv6.conf.${veth_rt2_rt1}.seg6_enabled 1
ns_sysctl "$ns_router2" net.ipv6.conf.${veth_rt2_rt3}.seg6_enabled 1

# Create VRF device on router2
run ip netns exec "$ns_router2" ip link add vrf100 type vrf table 100
run ip netns exec "$ns_router2" ip link set vrf100 up
ip netns exec "$ns_router2" ip rule add l3mdev protocol kernel prio 1000 2>/dev/null || true
ns_sysctl "$ns_router2" net.vrf.strict_mode 1

# Enslave both router-facing interfaces to VRF
run ip netns exec "$ns_router2" ip link set "$veth_rt2_rt1" master vrf100
run ip netns exec "$ns_router2" ip link set "$veth_rt2_rt3" master vrf100

# VRF enslave may drop global-scope IPv6 addresses. Re-add them.
ip netns exec "$ns_router2" ip -6 addr add ${TOPO_ROUTER2_RT1_IPV6} dev "$veth_rt2_rt1" 2>/dev/null || true
ip netns exec "$ns_router2" ip -6 addr add ${TOPO_ROUTER2_RT3_IPV6} dev "$veth_rt2_rt3" 2>/dev/null || true

# Re-add inter-router routes in VRF table 100
ip netns exec "$ns_router2" ip -6 route replace ${TOPO_IPV6_PREFIX_RT1} via ${TOPO_ROUTER1_RT2_IPV6%/*} dev "$veth_rt2_rt1" table 100
ip netns exec "$ns_router2" ip -6 route replace ${TOPO_IPV6_PREFIX_RT3} via ${TOPO_ROUTER3_RT2_IPV6%/*} dev "$veth_rt2_rt3" table 100

# Linux native End.T: process SRH then lookup updated DA in VRF table 100
# Forward path SID
run ip netns exec "$ns_router2" ip -6 route del local fc00:2::2 2>/dev/null || true
run ip netns exec "$ns_router2" ip -6 route add local fc00:2::1/128 encap seg6local action End.T table 100 dev lo
# Return path SID
run ip netns exec "$ns_router2" ip -6 route add local fc00:2::2/128 encap seg6local action End.T table 100 dev lo

# Configure router3 (End.DX4)
ns_sysctl "$ns_router3" net.ipv6.conf.${veth_rt3_h2}.seg6_enabled 1
ns_sysctl "$ns_router3" net.ipv6.conf.${veth_rt3_rt2}.seg6_enabled 1
ns_sysctl "$ns_router3" net.ipv4.conf.${veth_rt3_rt2}.rp_filter 0
ns_sysctl "$ns_router3" net.ipv4.conf.${veth_rt3_h2}.rp_filter 0

# Return path: host2 -> host1 (encap with SID list)
run ip netns exec "$ns_router3" ip route add 172.0.1.0/24 encap seg6 mode encap segs fc00:2::2,fc00:1::1 dev "$veth_rt3_rt2"

# Forward path: End.DX4 for host1 -> host2
run ip netns exec "$ns_router3" ip -6 route del local fc00:3::3
run ip netns exec "$ns_router3" ip -6 route add local fc00:3::3/128 encap seg6local action End.DX4 nh4 172.0.2.1 dev "$veth_rt3_h2"

# Pre-resolve NDP between routers
print_info "Pre-resolving NDP..."
ip netns exec "$ns_router1" ping6 -c 1 -W 2 fc00:12::2 > /dev/null 2>&1 || true
ip netns exec "$ns_router2" ping6 -c 1 -W 2 fc00:12::1 > /dev/null 2>&1 || true
ip netns exec "$ns_router2" ip vrf exec vrf100 ping6 -c 1 -W 2 fc00:23::1 > /dev/null 2>&1 || true
ip netns exec "$ns_router2" ip vrf exec vrf100 ping6 -c 1 -W 2 fc00:12::1 > /dev/null 2>&1 || true
ip netns exec "$ns_router3" ping6 -c 1 -W 2 fc00:23::2 > /dev/null 2>&1 || true

echo ""
echo "=========================================="
echo "SRv6 End.T (VRF) Setup Complete!"
echo "=========================================="
echo "Topology:"
echo "  host1 (172.0.1.1) <---> router1 (fc00:1::1, H.Encaps/End.DX4)"
echo "  router1 <---> router2 (fc00:2::1/2, End.T vrftable 100) <- Vinbero"
echo "  router2 <---> router3 (fc00:3::3, End.DX4)"
echo "  router3 <---> host2 (172.0.2.1)"
echo ""
echo "SRv6 Segment List (forward: host1 -> host2):"
echo "  Trigger: 172.0.2.0/24"
echo "  Segments: fc00:2::1, fc00:3::3"
echo "  End.T at fc00:2::1 updates DA to fc00:3::3, then VRF FIB lookup"
echo ""
echo "SRv6 Segment List (return: host2 -> host1):"
echo "  Trigger: 172.0.1.0/24"
echo "  Segments: fc00:2::2, fc00:1::1"
echo "  End.T at fc00:2::2 updates DA to fc00:1::1, then VRF FIB lookup"
echo ""
print_success "Ready for testing!"
