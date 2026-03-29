#!/bin/bash
# examples/end-dt2/setup.sh
# Setup End.DT2 L2VPN demonstration environment
# Router1: H.Encaps.L2 (Vinbero) for forward path
# Router3: End.DT2 (Vinbero) for forward path + H.Encaps.L2 (Vinbero) for return path

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-dt2-}"

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

# Configure VLAN interfaces for L2VPN
print_info "Configuring VLAN interfaces for L2VPN..."
run modprobe 8021q 2>/dev/null || true

run ip netns exec "$ns_host1" ip link add link "${veth_h1_rt1}" name "${veth_h1_rt1}.100" type vlan id 100
run ip netns exec "$ns_host1" ip addr add 172.16.100.1/24 dev "${veth_h1_rt1}.100"
run ip netns exec "$ns_host1" ip link set "${veth_h1_rt1}.100" up

run ip netns exec "$ns_host2" ip link add link "${veth_h2_rt3}" name "${veth_h2_rt3}.100" type vlan id 100
run ip netns exec "$ns_host2" ip addr add 172.16.100.2/24 dev "${veth_h2_rt3}.100"
run ip netns exec "$ns_host2" ip link set "${veth_h2_rt3}.100" up

# Disable VLAN TX offload for XDP compatibility
print_info "Disabling VLAN TX offload for XDP compatibility..."
run ip netns exec "$ns_host1" ethtool -K "${veth_h1_rt1}" txvlan off 2>/dev/null || true
run ip netns exec "$ns_host2" ethtool -K "${veth_h2_rt3}" txvlan off 2>/dev/null || true

print_info "Configuring SRv6 End.DT2 settings..."

# Configure router1
ns_sysctl "$ns_router1" net.ipv6.conf.${veth_rt1_h1}.seg6_enabled 1
ns_sysctl "$ns_router1" net.ipv6.conf.${veth_rt1_rt2}.seg6_enabled 1

# End.DX2 on router1 for return path (Linux native baseline)
run ip netns exec "$ns_router1" ip -6 route del local fc00:1::1 2>/dev/null || true
run ip netns exec "$ns_router1" ip -6 route add local fc00:1::2/128 encap seg6local action End.DX2 oif "$veth_rt1_h1" dev lo

# Configure router2 (End - transit)
ns_sysctl "$ns_router2" net.ipv6.conf.${veth_rt2_rt1}.seg6_enabled 1
ns_sysctl "$ns_router2" net.ipv6.conf.${veth_rt2_rt3}.seg6_enabled 1

run ip netns exec "$ns_router2" ip -6 route del local fc00:2::2 2>/dev/null || true
run ip netns exec "$ns_router2" ip -6 route add local fc00:2::1/128 encap seg6local action End dev lo
run ip netns exec "$ns_router2" ip -6 route add local fc00:2::2/128 encap seg6local action End dev lo

# Configure router3 (End.DT2 via Vinbero)
ns_sysctl "$ns_router3" net.ipv6.conf.${veth_rt3_h2}.seg6_enabled 1
ns_sysctl "$ns_router3" net.ipv6.conf.${veth_rt3_rt2}.seg6_enabled 1

# Create bridge on router3 for End.DT2 FDB learning
run ip netns exec "$ns_router3" ip link add br100 type bridge
run ip netns exec "$ns_router3" ip link set br100 up
run ip netns exec "$ns_router3" ip link set "$veth_rt3_h2" master br100

# Linux native End.DX2 for baseline testing (will be replaced by Vinbero End.DT2)
run ip netns exec "$ns_router3" ip -6 route del local fc00:3::3 2>/dev/null || true
run ip netns exec "$ns_router3" ip -6 route add local fc00:3::3/128 encap seg6local action End.DX2 oif "$veth_rt3_h2" dev lo

# Pre-resolve NDP
print_info "Pre-resolving NDP between routers..."
ip netns exec "$ns_router1" ping6 -c 1 -W 1 fc00:12::2 > /dev/null 2>&1 || true
ip netns exec "$ns_router2" ping6 -c 1 -W 1 fc00:12::1 > /dev/null 2>&1 || true
ip netns exec "$ns_router2" ping6 -c 1 -W 1 fc00:23::1 > /dev/null 2>&1 || true
ip netns exec "$ns_router3" ping6 -c 1 -W 1 fc00:23::2 > /dev/null 2>&1 || true

echo ""
echo "=========================================="
echo "SRv6 End.DT2 L2VPN Setup Complete!"
echo "=========================================="
echo "Topology:"
echo "  host1 (VLAN 100: 172.16.100.1) <---> router1 (H.Encaps.L2 via Vinbero)"
echo "  router1 <---> router2 (End)"
echo "  router2 <---> router3 (End.DT2 via Vinbero, bridge br100)"
echo "  router3 (br100) <---> host2 (VLAN 100: 172.16.100.2)"
echo ""
print_success "Ready for testing!"
