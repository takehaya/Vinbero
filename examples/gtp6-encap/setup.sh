#!/bin/bash
# examples/gtp6-encap/setup.sh
# Setup End.M.GTP6.D + End.M.GTP6.E demonstration environment
#
# Topology:
#   gNB (GTP-U/IPv6) ---> router1 (End.M.GTP6.D) ---> router2 (End) ---> router3 (End.M.GTP6.E) ---> UPF

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-gtp6-}"

source "${SCRIPT_DIR}/../common/topologies/three_router.sh"

ns_host1="${TOPO_NS_PREFIX}host1"
ns_router1="${TOPO_NS_PREFIX}router1"
ns_router2="${TOPO_NS_PREFIX}router2"
ns_router3="${TOPO_NS_PREFIX}router3"
veth_h1_rt1="${TOPO_NS_PREFIX}h1rt1"
veth_rt1_h1="${TOPO_NS_PREFIX}rt1h1"
veth_rt1_rt2="${TOPO_NS_PREFIX}rt1rt2"
veth_rt2_rt1="${TOPO_NS_PREFIX}rt2rt1"
veth_rt2_rt3="${TOPO_NS_PREFIX}rt2rt3"
veth_rt3_h2="${TOPO_NS_PREFIX}rt3h2"
veth_rt3_rt2="${TOPO_NS_PREFIX}rt3rt2"

setup_three_router_topology

print_info "Configuring SRv6 GTP-U/IPv6 settings..."

for ns in "$ns_router1" "$ns_router2" "$ns_router3"; do
    for dev in $(ip netns exec "$ns" ip -o link show | awk -F': ' '{print $2}'); do
        ns_sysctl "$ns" net.ipv6.conf.${dev}.seg6_enabled 1 2>/dev/null || true
    done
done

# router2 is a pure IPv6 transit: End.M.GTP6.D forwards the inner straight to the
# End.M.GTP6.E SID (no transit localsid), so router2 only forwards the /56 route.

# host1 plays the upstream node that SRv6-encapsulates GTP-U and sends it to
# router1's End.M.GTP6.D SID. Give the host1<->router1 link a global IPv6 so
# host1 can route to fc00:1::/56 (the SID); router1 processes the frame in XDP.
run ip netns exec "$ns_host1" ip -6 addr add fc00:10::1/64 dev "$veth_h1_rt1"
run ip netns exec "$ns_router1" ip -6 addr add fc00:10::2/64 dev "$veth_rt1_h1"
run ip netns exec "$ns_host1" ip -6 route add fc00:1::/56 via fc00:10::2 dev "$veth_h1_rt1"
# Pre-resolve NDP so the first SRv6 frame is not dropped waiting on it.
ip netns exec "$ns_host1" ping6 -c 1 -W 1 fc00:10::2 > /dev/null 2>&1 || true

echo ""
echo "=========================================="
echo "SRv6 GTP-U/IPv6 (End.M.GTP6.D + End.M.GTP6.E) Setup Complete!"
echo "=========================================="
echo "Forward: GTP-U/IPv6 -> End.M.GTP6.D (router1) -> End (router2) -> End.M.GTP6.E (router3) -> GTP-U/IPv6"
echo ""
print_success "Ready for testing!"
