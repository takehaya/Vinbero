#!/bin/bash
# examples/headend-ecmp/setup.sh
# Setup for the headend ECMP path-group demonstration: a diamond topology
# with two parallel SRv6 paths between the Vinbero headend and the egress.

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Set namespace prefix for this example (allows parallel execution)
# Note: Linux interface names are limited to 15 chars, so use short prefix "hec-"
export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-hec-}"

source "${SCRIPT_DIR}/../common/netns.sh"
source "${SCRIPT_DIR}/../common/veth.sh"
source "${SCRIPT_DIR}/../common/test_utils.sh"

ns_host1="${TOPO_NS_PREFIX}host1"
ns_host2="${TOPO_NS_PREFIX}host2"
ns_router1="${TOPO_NS_PREFIX}router1"   # Vinbero headend (H.Encaps + ECMP group)
ns_router2a="${TOPO_NS_PREFIX}router2a" # transit path A (End)
ns_router2b="${TOPO_NS_PREFIX}router2b" # transit path B (End)
ns_router3="${TOPO_NS_PREFIX}router3"   # egress (End.DX4)

veth_h1_rt1="${TOPO_NS_PREFIX}h1rt1"
veth_rt1_h1="${TOPO_NS_PREFIX}rt1h1"
veth_rt1_r2a="${TOPO_NS_PREFIX}rt1r2a"
veth_r2a_rt1="${TOPO_NS_PREFIX}r2art1"
veth_rt1_r2b="${TOPO_NS_PREFIX}rt1r2b"
veth_r2b_rt1="${TOPO_NS_PREFIX}r2brt1"
veth_r2a_rt3="${TOPO_NS_PREFIX}r2art3"
veth_rt3_r2a="${TOPO_NS_PREFIX}rt3r2a"
veth_r2b_rt3="${TOPO_NS_PREFIX}r2brt3"
veth_rt3_r2b="${TOPO_NS_PREFIX}rt3r2b"
veth_rt3_h2="${TOPO_NS_PREFIX}rt3h2"
veth_h2_rt3="${TOPO_NS_PREFIX}h2rt3"

check_root

run() { echo "+ $*"; "$@"; }

print_info "Creating namespaces..."
for ns in "$ns_host1" "$ns_host2" "$ns_router1" "$ns_router2a" "$ns_router2b" "$ns_router3"; do
    create_netns "$ns"
done

print_info "Wiring the diamond topology..."
create_veth_pair "$veth_h1_rt1" "$ns_host1" "$veth_rt1_h1" "$ns_router1"
create_veth_pair "$veth_rt1_r2a" "$ns_router1" "$veth_r2a_rt1" "$ns_router2a"
create_veth_pair "$veth_rt1_r2b" "$ns_router1" "$veth_r2b_rt1" "$ns_router2b"
create_veth_pair "$veth_r2a_rt3" "$ns_router2a" "$veth_rt3_r2a" "$ns_router3"
create_veth_pair "$veth_r2b_rt3" "$ns_router2b" "$veth_rt3_r2b" "$ns_router3"
create_veth_pair "$veth_rt3_h2" "$ns_router3" "$veth_h2_rt3" "$ns_host2"

print_info "Assigning addresses..."
configure_veth "$ns_host1" "$veth_h1_rt1" 172.0.1.1/24
configure_veth "$ns_router1" "$veth_rt1_h1" 172.0.1.254/24
configure_veth "$ns_router1" "$veth_rt1_r2a" fc00:12a::1/64
configure_veth "$ns_router2a" "$veth_r2a_rt1" fc00:12a::2/64
configure_veth "$ns_router1" "$veth_rt1_r2b" fc00:12b::1/64
configure_veth "$ns_router2b" "$veth_r2b_rt1" fc00:12b::2/64
configure_veth "$ns_router2a" "$veth_r2a_rt3" fc00:2a3::2/64
configure_veth "$ns_router3" "$veth_rt3_r2a" fc00:2a3::3/64
configure_veth "$ns_router2b" "$veth_r2b_rt3" fc00:2b3::2/64
configure_veth "$ns_router3" "$veth_rt3_r2b" fc00:2b3::3/64
configure_veth "$ns_router3" "$veth_rt3_h2" 172.0.2.254/24
configure_veth "$ns_host2" "$veth_h2_rt3" 172.0.2.1/24

print_info "Enabling forwarding and SRv6..."
for ns in "$ns_router1" "$ns_router2a" "$ns_router2b" "$ns_router3"; do
    ns_sysctl "$ns" net.ipv4.ip_forward 1
    ns_sysctl "$ns" net.ipv6.conf.all.forwarding 1
    ns_sysctl "$ns" net.ipv6.conf.all.seg6_enabled 1
    ns_sysctl "$ns" net.ipv6.conf.default.seg6_enabled 1
done
for dev in "$veth_rt1_h1" "$veth_rt1_r2a" "$veth_rt1_r2b"; do
    ns_sysctl "$ns_router1" net.ipv6.conf.${dev}.seg6_enabled 1
    ns_sysctl "$ns_router1" net.ipv4.conf.${dev}.rp_filter 0
done
# The effective rp_filter is max(all, device), and a new netns inherits the
# host's conf.all value on some systems. The decapped return traffic has no
# matching IPv4 route on the decap routers, so force it off entirely.
ns_sysctl "$ns_router1" net.ipv4.conf.all.rp_filter 0
ns_sysctl "$ns_router3" net.ipv4.conf.all.rp_filter 0
ns_sysctl "$ns_router2a" net.ipv6.conf.${veth_r2a_rt1}.seg6_enabled 1
ns_sysctl "$ns_router2b" net.ipv6.conf.${veth_r2b_rt1}.seg6_enabled 1
ns_sysctl "$ns_router3" net.ipv6.conf.${veth_rt3_r2a}.seg6_enabled 1
ns_sysctl "$ns_router3" net.ipv6.conf.${veth_rt3_r2b}.seg6_enabled 1
ns_sysctl "$ns_router3" net.ipv4.conf.${veth_rt3_h2}.rp_filter 0
ns_sysctl "$ns_router3" net.ipv4.conf.${veth_rt3_r2a}.rp_filter 0
ns_sysctl "$ns_router3" net.ipv4.conf.${veth_rt3_r2b}.rp_filter 0

print_info "Configuring hosts..."
run ip netns exec "$ns_host1" ip route add default via 172.0.1.254
run ip netns exec "$ns_host2" ip route add default via 172.0.2.254

print_info "Configuring router1 (Vinbero headend)..."
# Underlay routes towards each path's first SID (used by the XDP FIB lookup)
run ip netns exec "$ns_router1" ip -6 route add fc00:a::/64 via fc00:12a::2 dev "$veth_rt1_r2a"
run ip netns exec "$ns_router1" ip -6 route add fc00:b::/64 via fc00:12b::2 dev "$veth_rt1_r2b"
# Baseline Linux native encap over path A (replaced by Vinbero in test.sh)
run ip netns exec "$ns_router1" ip route add 172.0.2.0/24 encap seg6 mode encap segs fc00:a::2,fc00:3::3 dev "$veth_rt1_r2a"
# Return path terminator: host2 -> host1
run ip netns exec "$ns_router1" ip -6 route add local fc00:1::1/128 encap seg6local action End.DX4 nh4 172.0.1.1 dev "$veth_rt1_h1"

print_info "Configuring router2a (transit, path A)..."
run ip netns exec "$ns_router2a" ip -6 route add local fc00:a::2/128 encap seg6local action End dev lo
run ip netns exec "$ns_router2a" ip -6 route add fc00:3::/64 via fc00:2a3::3 dev "$veth_r2a_rt3"
run ip netns exec "$ns_router2a" ip -6 route add fc00:1::/64 via fc00:12a::1 dev "$veth_r2a_rt1"

print_info "Configuring router2b (transit, path B)..."
run ip netns exec "$ns_router2b" ip -6 route add local fc00:b::2/128 encap seg6local action End dev lo
run ip netns exec "$ns_router2b" ip -6 route add fc00:3::/64 via fc00:2b3::3 dev "$veth_r2b_rt3"
run ip netns exec "$ns_router2b" ip -6 route add fc00:1::/64 via fc00:12b::1 dev "$veth_r2b_rt1"

print_info "Configuring router3 (egress End.DX4)..."
run ip netns exec "$ns_router3" ip -6 route add local fc00:3::3/128 encap seg6local action End.DX4 nh4 172.0.2.1 dev "$veth_rt3_h2"
# Return path: host2 -> host1 rides a single-SID encap through path A
run ip netns exec "$ns_router3" ip route add 172.0.1.0/24 encap seg6 mode encap segs fc00:1::1 dev "$veth_rt3_r2a"
run ip netns exec "$ns_router3" ip -6 route add fc00:1::/64 via fc00:2a3::2 dev "$veth_rt3_r2a"

echo ""
echo "=========================================="
echo "SRv6 Headend ECMP Setup Complete!"
echo "=========================================="
echo "Topology (diamond):"
echo "                    router2a (fc00:a::2, End)"
echo "                   /                          \\"
echo "  host1 -- router1 (Vinbero H.Encaps + group)  router3 (fc00:3::3, End.DX4) -- host2"
echo "                   \\                          /"
echo "                    router2b (fc00:b::2, End)"
echo ""
echo "ECMP path group (installed in test.sh):"
echo "  path 0: fc00:a::2, fc00:3::3  (via router2a)"
echo "  path 1: fc00:b::2, fc00:3::3  (via router2b)"
echo ""
print_success "Ready for testing!"
