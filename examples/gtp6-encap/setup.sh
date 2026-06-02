#!/bin/bash
# examples/gtp6-encap/setup.sh
# Setup H.M.GTP6.D + End.M.GTP6.E demonstration environment (IPv6 counterpart of
# gtp4-encap): router1 is the headend that intercepts a raw GTP-U/IPv6 tunnel by
# its outer IPv6 destination and converts it to SRv6.
#
# Topology:
#   gNB (GTP-U/IPv6) --> router1 (H.M.GTP6.D) --> router2 (transit) --> router3 (End.M.GTP6.E) --> UPF

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

# host1 is the gNB. Give the host1<->router1 link a global IPv6 and route the
# GTP-U outer-dst prefix (the N3/UPF tunnel endpoint, 2001:db8:caf::/64) toward
# router1, where H.M.GTP6.D intercepts it. router1 keeps the default /64 routes
# to the End.M.GTP6.E locator (fc00:3::) -- with args-offset 8 the Args.Mob.Session
# stays past the /64, so the SID is still routable.
run ip netns exec "$ns_host1" ip -6 addr add fc00:10::1/64 dev "$veth_h1_rt1"
run ip netns exec "$ns_router1" ip -6 addr add fc00:10::2/64 dev "$veth_rt1_h1"
run ip netns exec "$ns_host1" ip -6 route add 2001:db8:caf::/64 via fc00:10::2 dev "$veth_h1_rt1"
ip netns exec "$ns_host1" ping6 -c 1 -W 1 fc00:10::2 > /dev/null 2>&1 || true

# router2 is a pure IPv6 transit: H.M.GTP6.D encapsulates straight to the
# End.M.GTP6.E SID, so router2 only forwards the /64 SID route -- no localsid.

echo ""
echo "=========================================="
echo "SRv6 GTP-U/IPv6 (H.M.GTP6.D + End.M.GTP6.E) Setup Complete!"
echo "=========================================="
echo "Forward: GTP-U/IPv6 -> H.M.GTP6.D (router1) -> transit (router2) -> End.M.GTP6.E (router3) -> GTP-U/IPv6"
echo ""
print_success "Ready for testing!"
