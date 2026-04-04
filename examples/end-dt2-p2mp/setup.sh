#!/bin/bash
# examples/end-dt2-p2mp/setup.sh
# Setup End.DT2 P2MP L2VPN demonstration environment
#
# PE1 (router1): H.Encaps.L2 + TC BUM flood to PE2 and PE3
# PE2 (router3): End.DT2 + bridge br100 (host2, host3)
# PE3 (router4): End.DT2 + bridge br100 (host4)
# P   (router2): SRv6 transit (End)

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-p2m-}"

source "${SCRIPT_DIR}/../common/topologies/four_router.sh"

ns_host1="${TOPO_NS_PREFIX}host1"
ns_host2="${TOPO_NS_PREFIX}host2"
ns_host3="${TOPO_NS_PREFIX}host3"
ns_host4="${TOPO_NS_PREFIX}host4"
ns_router1="${TOPO_NS_PREFIX}router1"
ns_router2="${TOPO_NS_PREFIX}router2"
ns_router3="${TOPO_NS_PREFIX}router3"
ns_router4="${TOPO_NS_PREFIX}router4"
veth_h1_rt1="${TOPO_NS_PREFIX}h1rt1"
veth_rt1_h1="${TOPO_NS_PREFIX}rt1h1"
veth_h2_rt3="${TOPO_NS_PREFIX}h2rt3"
veth_rt3_h2="${TOPO_NS_PREFIX}rt3h2"
veth_h3_rt3="${TOPO_NS_PREFIX}h3rt3"
veth_rt3_h3="${TOPO_NS_PREFIX}rt3h3"
veth_h4_rt4="${TOPO_NS_PREFIX}h4rt4"
veth_rt4_h4="${TOPO_NS_PREFIX}rt4h4"
veth_rt1_rt2="${TOPO_NS_PREFIX}rt1rt2"
veth_rt3_rt2="${TOPO_NS_PREFIX}rt3rt2"
veth_rt4_rt2="${TOPO_NS_PREFIX}rt4rt2"

setup_four_router_topology

# === VLAN 100 interfaces on all hosts ===
print_info "Configuring VLAN interfaces..."
run modprobe 8021q 2>/dev/null || true

for entry in \
    "$ns_host1:$veth_h1_rt1:172.16.100.1/24" \
    "$ns_host2:$veth_h2_rt3:172.16.100.2/24" \
    "$ns_host3:$veth_h3_rt3:172.16.100.3/24" \
    "$ns_host4:$veth_h4_rt4:172.16.100.4/24"; do
    IFS=: read -r ns_host veth_if ip_addr <<< "$entry"
    run ip netns exec "$ns_host" ip link add link "$veth_if" name "${veth_if}.100" type vlan id 100
    run ip netns exec "$ns_host" ip addr add "$ip_addr" dev "${veth_if}.100"
    run ip netns exec "$ns_host" ip link set "${veth_if}.100" up
done

# === Disable VLAN offload for XDP compatibility ===
print_info "Disabling VLAN offload..."
run ip netns exec "$ns_host1" ethtool -K "$veth_h1_rt1" txvlan off 2>/dev/null || true
run ip netns exec "$ns_host2" ethtool -K "$veth_h2_rt3" txvlan off 2>/dev/null || true
run ip netns exec "$ns_host3" ethtool -K "$veth_h3_rt3" txvlan off 2>/dev/null || true
run ip netns exec "$ns_host4" ethtool -K "$veth_h4_rt4" txvlan off 2>/dev/null || true
run ip netns exec "$ns_router1" ethtool -K "$veth_rt1_h1" rxvlan off 2>/dev/null || true
run ip netns exec "$ns_router3" ethtool -K "$veth_rt3_h2" rxvlan off 2>/dev/null || true
run ip netns exec "$ns_router3" ethtool -K "$veth_rt3_h3" rxvlan off 2>/dev/null || true
run ip netns exec "$ns_router4" ethtool -K "$veth_rt4_h4" rxvlan off 2>/dev/null || true

# === SRv6 seg6_enabled on customer-facing interfaces ===
for entry in \
    "$ns_router1:$veth_rt1_h1" \
    "$ns_router1:$veth_rt1_rt2" \
    "$ns_router2:${TOPO_NS_PREFIX}rt2rt1" \
    "$ns_router2:${TOPO_NS_PREFIX}rt2rt3" \
    "$ns_router2:${TOPO_NS_PREFIX}rt2rt4" \
    "$ns_router3:$veth_rt3_h2" \
    "$ns_router3:$veth_rt3_h3" \
    "$ns_router3:$veth_rt3_rt2" \
    "$ns_router4:$veth_rt4_h4" \
    "$ns_router4:$veth_rt4_rt2"; do
    IFS=: read -r ns iface <<< "$entry"
    ns_sysctl "$ns" "net.ipv6.conf.${iface}.seg6_enabled" 1
done

# === Router2: SRv6 End transit (Linux native) ===
run ip netns exec "$ns_router2" ip -6 route del local fc00:2::2 2>/dev/null || true
run ip netns exec "$ns_router2" ip -6 route add local fc00:2::1/128 encap seg6local action End dev lo
run ip netns exec "$ns_router2" ip -6 route add local fc00:2::2/128 encap seg6local action End dev lo

# === Router1: Linux native End.DX2 for return path baseline ===
run ip netns exec "$ns_router1" ip -6 route del local fc00:1::1 2>/dev/null || true
run ip netns exec "$ns_router1" ip -6 route add local fc00:1::2/128 encap seg6local action End.DX2 oif "$veth_rt1_h1" dev lo

# === Bridge on router3 (two members: host2 + host3) ===
print_info "Creating bridge br100 on router3 with two members..."
run ip netns exec "$ns_router3" ip link add br100 type bridge
run ip netns exec "$ns_router3" ip link set br100 up
run ip netns exec "$ns_router3" ip link set "$veth_rt3_h2" master br100
run ip netns exec "$ns_router3" ip link set "$veth_rt3_h3" master br100

# === Bridge on router4 (one member: host4) ===
print_info "Creating bridge br100 on router4..."
run ip netns exec "$ns_router4" ip link add br100 type bridge
run ip netns exec "$ns_router4" ip link set br100 up
run ip netns exec "$ns_router4" ip link set "$veth_rt4_h4" master br100

# === Pre-resolve NDP ===
print_info "Pre-resolving NDP..."
ip netns exec "$ns_router1" ping6 -c 1 -W 1 fc00:12::2 > /dev/null 2>&1 || true
ip netns exec "$ns_router2" ping6 -c 1 -W 1 fc00:12::1 > /dev/null 2>&1 || true
ip netns exec "$ns_router2" ping6 -c 1 -W 1 fc00:23::1 > /dev/null 2>&1 || true
ip netns exec "$ns_router2" ping6 -c 1 -W 1 fc00:24::1 > /dev/null 2>&1 || true
ip netns exec "$ns_router3" ping6 -c 1 -W 1 fc00:23::2 > /dev/null 2>&1 || true
ip netns exec "$ns_router4" ping6 -c 1 -W 1 fc00:24::2 > /dev/null 2>&1 || true

echo ""
echo "=========================================="
echo "SRv6 End.DT2 P2MP L2VPN Setup Complete!"
echo "=========================================="
echo "Topology:"
echo "  host1 (VLAN 100: .1) <---> PE1 (router1)"
echo "  PE1 <---> P (router2)"
echo "  P <---> PE2 (router3, br100) <---> host2 (.2), host3 (.3)"
echo "  P <---> PE3 (router4, br100) <---> host4 (.4)"
echo ""
print_success "Ready for testing!"
