#!/bin/bash
# examples/end-dt6/setup.sh
# Setup End.DT6 demonstration environment (with VRF)

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-dt6-}"

source "${SCRIPT_DIR}/../common/topologies/three_router.sh"

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

setup_three_router_topology

# Configure IPv6 addresses for hosts
print_info "Configuring IPv6 addresses for End.DT6 demo..."

run ip netns exec "$ns_host1" ip -6 addr add 2001:1::1/64 dev "$veth_h1_rt1"
run ip netns exec "$ns_host2" ip -6 addr add 2001:2::1/64 dev "$veth_h2_rt3"

run ip netns exec "$ns_router1" ip -6 addr add 2001:1::2/64 dev "$veth_rt1_h1"
run ip netns exec "$ns_router3" ip -6 addr add 2001:2::2/64 dev "$veth_rt3_h2"

run ip netns exec "$ns_host1" ip -6 route add 2001:2::/64 via 2001:1::2
run ip netns exec "$ns_host2" ip -6 route add 2001:1::/64 via 2001:2::2

print_info "Configuring SRv6 End.DT6 settings..."

# Configure router1 (Headend)
ns_sysctl "$ns_router1" net.ipv6.conf.${veth_rt1_h1}.seg6_enabled 1
ns_sysctl "$ns_router1" net.ipv6.conf.${veth_rt1_rt2}.seg6_enabled 1

run ip netns exec "$ns_router1" ip -6 route add 2001:2::/64 encap seg6 mode encap segs fc00:2::1,fc00:3::3 dev "$veth_rt1_rt2"

# Return path: End.DX6 on router1
run ip netns exec "$ns_router1" ip -6 route del local fc00:1::1 2>/dev/null || true
run ip netns exec "$ns_router1" ip -6 route add local fc00:1::1/128 encap seg6local action End.DX6 nh6 2001:1::1 dev "$veth_rt1_h1"

# Configure router2 (End)
ns_sysctl "$ns_router2" net.ipv6.conf.${veth_rt2_rt1}.seg6_enabled 1
ns_sysctl "$ns_router2" net.ipv6.conf.${veth_rt2_rt3}.seg6_enabled 1

run ip netns exec "$ns_router2" ip -6 route del local fc00:2::2 2>/dev/null || true
run ip netns exec "$ns_router2" ip -6 route add local fc00:2::1/128 encap seg6local action End dev lo
run ip netns exec "$ns_router2" ip -6 route add local fc00:2::2/128 encap seg6local action End dev lo

# Configure router3 (End.DT6 with VRF)
ns_sysctl "$ns_router3" net.ipv6.conf.${veth_rt3_h2}.seg6_enabled 1
ns_sysctl "$ns_router3" net.ipv6.conf.${veth_rt3_rt2}.seg6_enabled 1

# Create VRF device on router3
run ip netns exec "$ns_router3" ip link add vrf100 type vrf table 100
run ip netns exec "$ns_router3" ip link set vrf100 up
ip netns exec "$ns_router3" ip rule add l3mdev protocol kernel prio 1000 2>/dev/null || true
ns_sysctl "$ns_router3" net.vrf.strict_mode 1

# Enslave host-facing interface to VRF
run ip netns exec "$ns_router3" ip link set "$veth_rt3_h2" master vrf100

# Re-add IPv6 address in VRF context (enslaving may drop it)
run ip netns exec "$ns_router3" ip -6 addr add 2001:2::2/64 dev "$veth_rt3_h2" 2>/dev/null || true

# Return path: host2 -> host1
run ip netns exec "$ns_router3" ip -6 route add 2001:1::/64 encap seg6 mode encap segs fc00:2::2,fc00:1::1 dev "$veth_rt3_rt2"

# Linux native End.DT6 for baseline
run ip netns exec "$ns_router3" ip -6 route del local fc00:3::3 2>/dev/null || true
run ip netns exec "$ns_router3" ip -6 route add local fc00:3::3/128 encap seg6local action End.DT6 vrftable 100 dev lo

# Pre-resolve NDP (required for bpf_fib_lookup and Linux native)
print_info "Pre-resolving NDP between routers..."
ip netns exec "$ns_router1" ping6 -c 1 -W 2 fc00:12::2 > /dev/null 2>&1 || true
ip netns exec "$ns_router2" ping6 -c 1 -W 2 fc00:23::1 > /dev/null 2>&1 || true
ip netns exec "$ns_router3" ping6 -c 1 -W 2 fc00:23::2 > /dev/null 2>&1 || true
# NDP for host-facing links (VRF context)
ip netns exec "$ns_router3" ip vrf exec vrf100 ping6 -c 1 -W 2 2001:2::1 > /dev/null 2>&1 || true

echo ""
echo "=========================================="
echo "SRv6 End.DT6 (VRF) Setup Complete!"
echo "=========================================="
echo "Topology:"
echo "  host1 (2001:1::1) <---> router1 (fc00:1::1, H.Encaps/End.DX6)"
echo "  router1 <---> router2 (fc00:2::1/2, End)"
echo "  router2 <---> router3 (fc00:3::3, End.DT6 vrftable 100) <- Vinbero"
echo "  router3 (vrf100) <---> host2 (2001:2::1)"
echo ""
print_success "Ready for testing!"
