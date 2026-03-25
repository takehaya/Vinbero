#!/bin/bash
# examples/headend-l2/setup.sh
# Setup H.Encaps.L2 (Headend L2VPN) demonstration environment

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Set namespace prefix for this example (allows parallel execution)
# Note: Linux interface names are limited to 15 chars, so use short prefix "hl2-"
export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-hl2-}"

source "${SCRIPT_DIR}/../common/topologies/three_router.sh"

# Define namespace and veth names with prefix
ns_host1="${TOPO_NS_PREFIX}host1"
ns_router1="${TOPO_NS_PREFIX}router1"
ns_router2="${TOPO_NS_PREFIX}router2"
ns_router3="${TOPO_NS_PREFIX}router3"
ns_host2="${TOPO_NS_PREFIX}host2"
veth_h1_rt1="${TOPO_NS_PREFIX}h1rt1"
veth_rt1_h1="${TOPO_NS_PREFIX}rt1h1"
veth_rt1_rt2="${TOPO_NS_PREFIX}rt1rt2"
veth_rt2_rt1="${TOPO_NS_PREFIX}rt2rt1"
veth_rt2_rt3="${TOPO_NS_PREFIX}rt2rt3"
veth_rt3_rt2="${TOPO_NS_PREFIX}rt3rt2"
veth_rt3_h2="${TOPO_NS_PREFIX}rt3h2"
veth_h2_rt3="${TOPO_NS_PREFIX}h2rt3"

# Setup base topology
setup_three_router_topology

# Configure VLAN interfaces for L2VPN demo
print_info "Configuring VLAN interfaces for L2VPN..."

# Enable 8021q module for VLAN processing
run modprobe 8021q 2>/dev/null || true

# Create VLAN 100 interface on host1's veth
run ip netns exec "$ns_host1" ip link add link "${veth_h1_rt1}" name "${veth_h1_rt1}.100" type vlan id 100
run ip netns exec "$ns_host1" ip addr add 172.16.100.1/24 dev "${veth_h1_rt1}.100"
run ip netns exec "$ns_host1" ip link set "${veth_h1_rt1}.100" up

# Create VLAN 100 interface on host2's veth (for L2VPN endpoint)
run ip netns exec "$ns_host2" ip link add link "${veth_h2_rt3}" name "${veth_h2_rt3}.100" type vlan id 100
run ip netns exec "$ns_host2" ip addr add 172.16.100.2/24 dev "${veth_h2_rt3}.100"
run ip netns exec "$ns_host2" ip link set "${veth_h2_rt3}.100" up

# Disable VLAN TX offload on host interfaces
# Without this, VLAN tags are stored in skb->vlan_tci (hardware accelerated)
# rather than in the packet data, making them invisible to XDP programs.
print_info "Disabling VLAN TX offload for XDP compatibility..."
run ip netns exec "$ns_host1" ethtool -K "${veth_h1_rt1}" txvlan off 2>/dev/null || true
run ip netns exec "$ns_host2" ethtool -K "${veth_h2_rt3}" txvlan off 2>/dev/null || true

# Configure SRv6-specific settings for H.Encaps.L2 demo
print_info "Configuring SRv6 H.Encaps.L2 settings..."

# Configure router1 (Headend - H.Encaps.L2 via Vinbero XDP)
ns_sysctl "$ns_router1" net.ipv6.conf.${veth_rt1_h1}.seg6_enabled 1
ns_sysctl "$ns_router1" net.ipv6.conf.${veth_rt1_rt2}.seg6_enabled 1

# Configure router2 (End - transit)
ns_sysctl "$ns_router2" net.ipv6.conf.${veth_rt2_rt1}.seg6_enabled 1
ns_sysctl "$ns_router2" net.ipv6.conf.${veth_rt2_rt3}.seg6_enabled 1

run ip netns exec "$ns_router2" ip -6 route del local fc00:2::2 2>/dev/null || true
run ip netns exec "$ns_router2" ip -6 route add local fc00:2::1/128 encap seg6local action End dev lo
run ip netns exec "$ns_router2" ip -6 route add local fc00:2::2/128 encap seg6local action End dev lo

# Configure router3 (End.DX2 for forward path + H.Encaps.L2 for return via Vinbero)
ns_sysctl "$ns_router3" net.ipv6.conf.${veth_rt3_h2}.seg6_enabled 1
ns_sysctl "$ns_router3" net.ipv6.conf.${veth_rt3_rt2}.seg6_enabled 1

# End.DX2: Decapsulate SRv6 and forward L2 frame to host2
run ip netns exec "$ns_router3" ip -6 route del local fc00:3::3 2>/dev/null || true
run ip netns exec "$ns_router3" ip -6 route add local fc00:3::3/128 encap seg6local action End.DX2 oif "$veth_rt3_h2" dev lo

# End.DX2 on router1 for return path (decapsulate SRv6 and forward L2 to host1)
run ip netns exec "$ns_router1" ip -6 route del local fc00:1::1 2>/dev/null || true
run ip netns exec "$ns_router1" ip -6 route add local fc00:1::2/128 encap seg6local action End.DX2 oif "$veth_rt1_h1" dev lo

# Pre-resolve NDP between routers (required for bpf_fib_lookup)
print_info "Pre-resolving NDP between routers..."
ip netns exec "$ns_router1" ping6 -c 1 -W 1 fc00:12::2 > /dev/null 2>&1 || true
ip netns exec "$ns_router2" ping6 -c 1 -W 1 fc00:12::1 > /dev/null 2>&1 || true
ip netns exec "$ns_router2" ping6 -c 1 -W 1 fc00:23::1 > /dev/null 2>&1 || true
ip netns exec "$ns_router3" ping6 -c 1 -W 1 fc00:23::2 > /dev/null 2>&1 || true

echo ""
echo "=========================================="
echo "SRv6 H.Encaps.L2 (Headend L2VPN) Setup Complete!"
echo "=========================================="
echo "Topology:"
echo "  host1 (VLAN 100: 172.16.100.1) <---> router1 (fc00:1::1, H.Encaps.L2 via Vinbero)"
echo "  router1 (fc00:12::1) <---> router2 (fc00:2::1, fc00:2::2, End)"
echo "  router2 (fc00:23::2) <---> router3 (fc00:3::3, End.DX2 + H.Encaps.L2 via Vinbero)"
echo "  router3 <---> host2 (VLAN 100: 172.16.100.2)"
echo ""
echo "L2VPN Configuration (forward: host1 -> host2):"
echo "  Vinbero on router1: VLAN 100 -> SRv6 [fc00:2::1, fc00:3::3]"
echo "  End.DX2 on router3: fc00:3::3 -> $veth_rt3_h2"
echo ""
echo "L2VPN Configuration (return: host2 -> host1):"
echo "  Vinbero on router3: VLAN 100 -> SRv6 [fc00:2::2, fc00:1::2]"
echo "  End.DX2 on router1: fc00:1::2 -> $veth_rt1_h1"
echo ""
print_success "Ready for testing!"
