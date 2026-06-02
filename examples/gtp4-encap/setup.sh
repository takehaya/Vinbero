#!/bin/bash
# examples/gtp4-encap/setup.sh
# Setup H.M.GTP4.D + End.M.GTP4.E demonstration environment
#
# Topology:
#   gNB (GTP-U/IPv4) ---> router1 (H.M.GTP4.D) ---> router2 (End) ---> router3 (End.M.GTP4.E) ---> UPF
#   gNB <--- router1 (End.M.GTP4.E) <--- router2 (End) <--- router3 (H.M.GTP4.D) <--- UPF

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-gtp4-}"

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

# H.M.GTP4.D writes Args.Mob.Session into the outer DA at args_offset=7 (byte 7
# onward), so the End.M.GTP4.E SID locator must be <= 56 bits and the underlay
# must route that /56 (the default /64 would not cover an address whose byte 7
# carries the IPv4 destination). End.M.GTP4.E lives on fc00:1:: (return) and
# fc00:3:: (forward); route both as /56 so the args-bearing DA is forwardable.
export TOPO_IPV6_PREFIX_RT1=fc00:1::/56
export TOPO_IPV6_PREFIX_RT3=fc00:3::/56

setup_three_router_topology

print_info "Configuring SRv6 GTP-U/IPv4 settings..."

# router1: H.M.GTP4.D (forward) / End.M.GTP4.E (return)
ns_sysctl "$ns_router1" net.ipv6.conf.${veth_rt1_h1}.seg6_enabled 1
ns_sysctl "$ns_router1" net.ipv6.conf.${veth_rt1_rt2}.seg6_enabled 1
ns_sysctl "$ns_router1" net.ipv4.conf.${veth_rt1_rt2}.rp_filter 0
ns_sysctl "$ns_router1" net.ipv4.conf.${veth_rt1_h1}.rp_filter 0

# router2: pure IPv6 transit. The H.M.GTP4.D headend encapsulates straight to
# the End.M.GTP4.E SID (single segment), so router2 only forwards the /56 SID
# routes set up above -- no SRv6 localsid here.
ns_sysctl "$ns_router2" net.ipv6.conf.${veth_rt2_rt1}.seg6_enabled 1
ns_sysctl "$ns_router2" net.ipv6.conf.${veth_rt2_rt3}.seg6_enabled 1

# router3: End.M.GTP4.E (forward) / H.M.GTP4.D (return)
ns_sysctl "$ns_router3" net.ipv6.conf.${veth_rt3_h2}.seg6_enabled 1
ns_sysctl "$ns_router3" net.ipv6.conf.${veth_rt3_rt2}.seg6_enabled 1
ns_sysctl "$ns_router3" net.ipv4.conf.${veth_rt3_rt2}.rp_filter 0
ns_sysctl "$ns_router3" net.ipv4.conf.${veth_rt3_h2}.rp_filter 0

echo ""
echo "=========================================="
echo "SRv6 GTP-U/IPv4 (H.M.GTP4.D + End.M.GTP4.E) Setup Complete!"
echo "=========================================="
echo "Topology:"
echo "  gNB/host1 (172.0.1.1) <---> router1 (fc00:1::/56, H.M.GTP4.D / End.M.GTP4.E)"
echo "  router1 (fc00:12::1) <---> router2 (IPv6 transit)"
echo "  router2 (fc00:23::2) <---> router3 (fc00:3::/56, End.M.GTP4.E / H.M.GTP4.D)"
echo "  router3 <---> UPF/host2 (172.0.2.1)"
echo ""
echo "Forward: GTP-U/IPv4 -> H.M.GTP4.D (router1) -> transit (router2) -> End.M.GTP4.E (router3) -> GTP-U/IPv4"
echo "Return:  GTP-U/IPv4 -> H.M.GTP4.D (router3) -> transit (router2) -> End.M.GTP4.E (router1) -> GTP-U/IPv4"
echo ""
print_success "Ready for testing!"
