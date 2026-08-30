#!/bin/bash
# examples/end-udt4/setup.sh
# Setup uDT4 (End.DT4 as the last uSID of a NEXT-C-SID container) environment

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Note: Linux interface names are limited to 15 chars, so use short prefix
export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-udt4-}"

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

# Setup base topology
setup_three_router_topology

# uSID plan (F3216: 32-bit block fd00:aaaa, 16-bit uSIDs):
#   r3 node b003: uN    fd00:aaaa:b003::/48
#                 uDT4  fd00:aaaa:b003:d004::/128 (vrf100, zero-padded)
# Forward container: fd00:aaaa:b003:d004::
#   With both routes installed, the zero-padded /128 must win the LPM over
#   the uN /48 and decap into vrf100 -- the property this example proves.
#   test.sh phase 2 additionally switches the headend to the two-uSID
#   container fd00:aaaa:b003:b003:d004:: (shift at r3, then its own uDT4):
#   Vinbero consumes that hand-off inside the XDP loop, while Linux
#   seg6local cannot forward a shifted DA back into its own local SID, so
#   the oracle phase never sees that container.
print_info "Configuring uDT4 (NEXT-C-SID terminal) settings..."

# router1: headend towards host2 + terminal End.DX4 for the return direction
ns_sysctl "$ns_router1" net.ipv6.conf.${veth_rt1_h1}.seg6_enabled 1
ns_sysctl "$ns_router1" net.ipv6.conf.${veth_rt1_rt2}.seg6_enabled 1
ns_sysctl "$ns_router1" net.ipv4.conf.${veth_rt1_rt2}.rp_filter 0
ns_sysctl "$ns_router1" net.ipv4.conf.${veth_rt1_h1}.rp_filter 0

run ip netns exec "$ns_router1" ip route add 172.0.2.0/24 encap seg6 mode encap segs fd00:aaaa:b003:d004:: dev "$veth_rt1_rt2"
run ip netns exec "$ns_router1" ip -6 route add fd00:aaaa:b003::/48 via fc00:12::2 dev "$veth_rt1_rt2"
run ip netns exec "$ns_router1" ip -6 route del local fc00:1::1 2>/dev/null || true
run ip netns exec "$ns_router1" ip -6 route add local fc00:1::1/128 encap seg6local action End.DX4 nh4 172.0.1.1 dev "$veth_rt1_h1"

# router2: plain IPv6 transit towards the uSID block
run ip netns exec "$ns_router2" ip -6 route add fd00:aaaa:b003::/48 via fc00:23::1 dev "$veth_rt2_rt3"

# router3: uN + uDT4 (vrf100). Phase 1 of test.sh uses the Linux-native
# routes below as the oracle; phase 2 removes them and reinstalls the same
# SIDs via Vinbero.
ns_sysctl "$ns_router3" net.ipv6.conf.${veth_rt3_h2}.seg6_enabled 1
ns_sysctl "$ns_router3" net.ipv6.conf.${veth_rt3_rt2}.seg6_enabled 1
ns_sysctl "$ns_router3" net.ipv4.conf.all.rp_filter 0
ns_sysctl "$ns_router3" net.ipv4.conf.default.rp_filter 0
ns_sysctl "$ns_router3" net.ipv4.conf.${veth_rt3_rt2}.rp_filter 0
ns_sysctl "$ns_router3" net.ipv4.conf.${veth_rt3_h2}.rp_filter 0

# VRF for the uDT4 target table
run ip netns exec "$ns_router3" ip link add vrf100 type vrf table 100
run ip netns exec "$ns_router3" ip link set vrf100 up
ip netns exec "$ns_router3" ip rule add l3mdev protocol kernel prio 1000 2>/dev/null || true
ns_sysctl "$ns_router3" net.vrf.strict_mode 1
run ip netns exec "$ns_router3" ip link set "$veth_rt3_h2" master vrf100

# The bare uN SID is a local address on the node: a container that ends on
# the plain uN (not the uDT4) is handed up for local delivery.
run ip netns exec "$ns_router3" ip -6 addr add fd00:aaaa:b003::/128 dev lo nodad

# Return path: host2 -> host1 (in table 100, since rt3h2 is enslaved)
run ip netns exec "$ns_router3" ip route add 172.0.1.0/24 encap seg6 mode encap segs fc00:1::1 dev "$veth_rt3_rt2" table 100

# Linux-native oracle: uN (next-csid) + End.DT4 at the zero-padded /128
run ip netns exec "$ns_router3" ip -6 route add local fd00:aaaa:b003::/48 encap seg6local action End flavors next-csid lblen 32 nflen 16 dev "$veth_rt3_rt2"
run ip netns exec "$ns_router3" ip -6 route add local fd00:aaaa:b003:d004::/128 encap seg6local action End.DT4 vrftable 100 dev lo

# Pre-resolve NDP/ARP (bpf_fib_lookup needs resolved neighbours)
print_info "Pre-resolving NDP/ARP..."
ip netns exec "$ns_router1" ping6 -c 1 -W 2 fc00:12::2 > /dev/null 2>&1 || true
ip netns exec "$ns_router2" ping6 -c 1 -W 2 fc00:23::1 > /dev/null 2>&1 || true
ip netns exec "$ns_router3" ping6 -c 1 -W 2 fc00:23::2 > /dev/null 2>&1 || true
ip netns exec "$ns_router3" ip vrf exec vrf100 ping -c 1 -W 2 172.0.2.1 > /dev/null 2>&1 || true

echo ""
echo "=========================================="
echo "SRv6 uDT4 (NEXT-C-SID terminal) Setup Complete!"
echo "=========================================="
echo "uSID plan (block fd00:aaaa/32, 16-bit uSIDs):"
echo "  r3: uN    fd00:aaaa:b003::/48"
echo "  r3: uDT4  fd00:aaaa:b003:d004::/128 (End.DT4, vrf100)"
echo "Forward container: fd00:aaaa:b003:d004:: (direct uDT4; test.sh phase 2"
echo "  also exercises fd00:aaaa:b003:b003:d004:: -- shift, then own uDT4)"
echo "Return path: fc00:1::1 (End.DX4 on r1)"
echo ""
print_success "Ready for testing!"
