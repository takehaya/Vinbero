#!/bin/bash
# examples/end-as/setup.sh
# Setup End.AS (static proxy, draft-ietf-spring-srv6-service-programming)
# demonstration environment.
#
# Topology (three_router + a service namespace hanging off router2):
#
#   host1 --- router1 --- router2 --- router3 --- host2
#                            |
#                           svc   (SR-unaware service: plain IPv4 forwarder)
#
# Forward direction: router1 H.Encaps [fc00:2::100, fc00:3::3]. The End.AS
# SID fc00:2::100 on router2 strips the SR encapsulation and hands the bare
# IPv4 packet to svc; svc routes it straight back, and the return circuit
# re-encapsulates towards fc00:3::3 from the static CACHE.

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Linux interface names are limited to 15 chars, so use short prefix "as-"
export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-as-}"

source "${SCRIPT_DIR}/../common/topologies/three_router.sh"

ns_router1="${TOPO_NS_PREFIX}router1"
ns_router2="${TOPO_NS_PREFIX}router2"
ns_router3="${TOPO_NS_PREFIX}router3"
ns_svc="${TOPO_NS_PREFIX}svc"
veth_rt1_rt2="${TOPO_NS_PREFIX}rt1rt2"
veth_rt2_rt1="${TOPO_NS_PREFIX}rt2rt1"
veth_rt2_rt3="${TOPO_NS_PREFIX}rt2rt3"
veth_rt2_svc="${TOPO_NS_PREFIX}rt2svc"
veth_svc_rt2="${TOPO_NS_PREFIX}svcrt2"
veth_rt3_h2="${TOPO_NS_PREFIX}rt3h2"
veth_rt3_rt2="${TOPO_NS_PREFIX}rt3rt2"

setup_three_router_topology

print_info "Attaching the service namespace to router2..."
create_netns "$ns_svc"
create_veth_pair "$veth_rt2_svc" "$ns_router2" "$veth_svc_rt2" "$ns_svc"
run ip netns exec "$ns_router2" ip addr add 10.99.0.1/24 dev "$veth_rt2_svc"
run ip netns exec "$ns_svc" ip addr add 10.99.0.2/24 dev "$veth_svc_rt2"

# The SR-unaware service: a plain IPv4 forwarder that sends everything
# straight back over the same wire (bump-in-the-wire shape).
ns_sysctl "$ns_svc" net.ipv4.ip_forward 1
ns_sysctl "$ns_svc" net.ipv4.conf.${veth_svc_rt2}.rp_filter 0
ns_sysctl "$ns_svc" net.ipv4.conf.all.rp_filter 0
run ip netns exec "$ns_svc" ip route add 172.0.1.0/24 via 10.99.0.1
run ip netns exec "$ns_svc" ip route add 172.0.2.0/24 via 10.99.0.1

# router2 must not rp-filter the decapped packets it emits towards svc.
ns_sysctl "$ns_router2" net.ipv4.conf.${veth_rt2_svc}.rp_filter 0
ns_sysctl "$ns_router2" net.ipv4.conf.all.rp_filter 0

print_info "Configuring SRv6 End.AS settings..."

# router1: H.Encaps steering host1 -> host2 through the proxy SID.
ns_sysctl "$ns_router1" net.ipv6.conf.${veth_rt1_rt2}.seg6_enabled 1
ns_sysctl "$ns_router1" net.ipv4.conf.${veth_rt1_rt2}.rp_filter 0
run ip netns exec "$ns_router1" ip route add 172.0.2.0/24 encap seg6 mode encap segs fc00:2::100,fc00:3::3 dev "$veth_rt1_rt2"

# router2: Linux native End as the Phase 1 baseline (Linux cannot do
# End.AS; the baseline just proves the underlay path and resolves NDP).
ns_sysctl "$ns_router2" net.ipv6.conf.${veth_rt2_rt1}.seg6_enabled 1
ns_sysctl "$ns_router2" net.ipv6.conf.${veth_rt2_rt3}.seg6_enabled 1
run ip netns exec "$ns_router2" ip -6 route add local fc00:2::100/128 encap seg6local action End dev lo

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
echo "SRv6 End.AS Setup Complete!"
echo "=========================================="
echo "Forward: host1 -> [fc00:2::100 (End.AS via svc), fc00:3::3 (End.DX4)] -> host2"
echo "Return:  host2 -> [fc00:1::1 (End.DX4)] -> host1"
echo "Service namespace: $ns_svc (plain IPv4 forwarder on 10.99.0.0/24)"
echo ""
print_success "Ready for testing!"
