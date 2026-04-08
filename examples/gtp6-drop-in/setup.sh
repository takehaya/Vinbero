#!/bin/bash
# examples/gtp6-drop-in/setup.sh
# Setup End.M.GTP6.D.Di (Drop-In) demonstration environment
#
# Drop-In mode: existing GTP-U infrastructure with minimal SRv6 integration.
# The SRv6 node strips GTP-U and passes to kernel for further processing.

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-gtdi-}"

source "${SCRIPT_DIR}/../common/topologies/three_router.sh"

ns_router1="${TOPO_NS_PREFIX}router1"
ns_router2="${TOPO_NS_PREFIX}router2"
ns_router3="${TOPO_NS_PREFIX}router3"
veth_rt1_h1="${TOPO_NS_PREFIX}rt1h1"
veth_rt1_rt2="${TOPO_NS_PREFIX}rt1rt2"
veth_rt2_rt1="${TOPO_NS_PREFIX}rt2rt1"
veth_rt2_rt3="${TOPO_NS_PREFIX}rt2rt3"
veth_rt3_h2="${TOPO_NS_PREFIX}rt3h2"
veth_rt3_rt2="${TOPO_NS_PREFIX}rt3rt2"

setup_three_router_topology

print_info "Configuring SRv6 GTP-U/IPv6 Drop-In settings..."

for ns in "$ns_router1" "$ns_router2" "$ns_router3"; do
    for dev in $(ip netns exec "$ns" ip -o link show | awk -F': ' '{print $2}'); do
        ns_sysctl "$ns" net.ipv6.conf.${dev}.seg6_enabled 1 2>/dev/null || true
    done
done

# router2: End (transit)
run ip netns exec "$ns_router2" ip -6 route del local fc00:2::2 2>/dev/null || true
run ip netns exec "$ns_router2" ip -6 route add local fc00:2::1/128 encap seg6local action End dev lo

echo ""
echo "=========================================="
echo "SRv6 GTP-U/IPv6 Drop-In (End.M.GTP6.D.Di) Setup Complete!"
echo "=========================================="
echo "Drop-In: Vinbero updates SRH metadata and passes to kernel SRv6 stack."
echo ""
print_success "Ready for testing!"
