#!/bin/bash
# examples/end-an/setup.sh
# Setup End.AN (SR-aware native service, draft-ietf-spring-srv6-service-programming)
# demonstration environment.
#
# Topology (plain three_router):
#
#   host1 --- router1 --- router2 --- router3 --- host2
#
# Forward direction: router1 H.Encaps [fc00:2::200, fc00:3::3]. The End.AN
# SID fc00:2::200 on router2 forwards exactly like End — the SR-aware
# service is conceptually co-located with the SID — and registers the
# service in the NF catalog via its metadata.

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Linux interface names are limited to 15 chars, so use short prefix "an-"
export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-an-}"

source "${SCRIPT_DIR}/../common/topologies/three_router.sh"

ns_router1="${TOPO_NS_PREFIX}router1"
ns_router2="${TOPO_NS_PREFIX}router2"
ns_router3="${TOPO_NS_PREFIX}router3"
veth_rt1_rt2="${TOPO_NS_PREFIX}rt1rt2"
veth_rt2_rt1="${TOPO_NS_PREFIX}rt2rt1"
veth_rt2_rt3="${TOPO_NS_PREFIX}rt2rt3"
veth_rt3_h2="${TOPO_NS_PREFIX}rt3h2"
veth_rt3_rt2="${TOPO_NS_PREFIX}rt3rt2"

setup_three_router_topology

print_info "Configuring SRv6 End.AN settings..."

# router1: H.Encaps steering host1 -> host2 through the proxy SID.
ns_sysctl "$ns_router1" net.ipv6.conf.${veth_rt1_rt2}.seg6_enabled 1
ns_sysctl "$ns_router1" net.ipv4.conf.${veth_rt1_rt2}.rp_filter 0
run ip netns exec "$ns_router1" ip route add 172.0.2.0/24 encap seg6 mode encap segs fc00:2::200,fc00:3::3 dev "$veth_rt1_rt2"

# router2: Linux native End as the Phase 1 baseline (Linux cannot do
# End.AN; the baseline just proves the underlay path and resolves NDP).
ns_sysctl "$ns_router2" net.ipv6.conf.${veth_rt2_rt1}.seg6_enabled 1
ns_sysctl "$ns_router2" net.ipv6.conf.${veth_rt2_rt3}.seg6_enabled 1
run ip netns exec "$ns_router2" ip -6 route add local fc00:2::200/128 encap seg6local action End dev lo

# router3: End.DX4 towards host2, and the native return path host2 -> host1.
ns_sysctl "$ns_router3" net.ipv6.conf.${veth_rt3_rt2}.seg6_enabled 1
ns_sysctl "$ns_router3" net.ipv4.conf.${veth_rt3_rt2}.rp_filter 0
ns_sysctl "$ns_router3" net.ipv4.conf.${veth_rt3_h2}.rp_filter 0
run ip netns exec "$ns_router3" ip -6 route del local fc00:3::3 2>/dev/null || true
run ip netns exec "$ns_router3" ip -6 route add local fc00:3::3/128 encap seg6local action End.DX4 nh4 172.0.2.1 dev "$veth_rt3_h2"
run ip netns exec "$ns_router3" ip route add 172.0.1.0/24 encap seg6 mode encap segs fc00:1::1 dev "$veth_rt3_rt2"

# router1: plain End.DX4 for the return path terminus.
run ip netns exec "$ns_router1" ip -6 route del local fc00:1::1 2>/dev/null || true
run ip netns exec "$ns_router1" ip -6 route add local fc00:1::1/128 encap seg6local action End.DX4 nh4 172.0.1.1 dev "${TOPO_NS_PREFIX}rt1h1"

echo ""
echo "=========================================="
echo "SRv6 End.AN Setup Complete!"
echo "=========================================="
echo "Forward: host1 -> [fc00:2::200 (End.AN), fc00:3::3 (End.DX4)] -> host2"
echo "Return:  host2 -> [fc00:1::1 (End.DX4)] -> host1"
echo ""
print_success "Ready for testing!"
