#!/bin/bash
# examples/end-ua/setup.sh
# Setup uA (NEXT-C-SID, RFC 9800) operation demonstration environment

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Set namespace prefix for this example (allows parallel execution).
# Note: vinbero_*.yaml hardcodes device names with this prefix.
EXAMPLE_NAME="$(basename "$SCRIPT_DIR")"
export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-${EXAMPLE_NAME}-}"

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
#   r1 node b001, terminal uDX4  fd00:aaaa:b001:d001::/128
#   r2 node b002, uA a003 -> r3  fd00:aaaa:b002:a003::/64
#              , uA a001 -> r1  fd00:aaaa:b002:a001::/64
#   r3 node b003, terminal uDX4  fd00:aaaa:b003:d004::/128
# Forward container: fd00:aaaa:b002:a003:b003:d004::
# Return  container: fd00:aaaa:b002:a001:b001:d001::
# uA consumes node + function (32 bits) per execution and forwards over the
# configured adjacency instead of the FIB, so the DA that leaves r2 is
# already the terminal SID.
print_info "Configuring NEXT-C-SID (uA) settings..."

# router1: headend towards host2 + terminal uDX4 for the return direction
ns_sysctl "$ns_router1" net.ipv6.conf.${veth_rt1_h1}.seg6_enabled 1
ns_sysctl "$ns_router1" net.ipv6.conf.${veth_rt1_rt2}.seg6_enabled 1
ns_sysctl "$ns_router1" net.ipv4.conf.${veth_rt1_rt2}.rp_filter 0
ns_sysctl "$ns_router1" net.ipv4.conf.${veth_rt1_h1}.rp_filter 0

run ip netns exec "$ns_router1" ip route add 172.0.2.0/24 encap seg6 mode encap segs fd00:aaaa:b002:a003:b003:d004:: dev "$veth_rt1_rt2"
run ip netns exec "$ns_router1" ip -6 route add fd00:aaaa:b002::/48 via fc00:12::2 dev "$veth_rt1_rt2"
run ip netns exec "$ns_router1" ip -6 route add local fd00:aaaa:b001:d001::/128 encap seg6local action End.DX4 nh4 172.0.1.1 dev "$veth_rt1_h1"

# router2: uA towards each neighbour. Phase 1 of test.sh uses these
# Linux-native next-csid routes as the oracle; phase 2 removes them and
# reinstalls the same SIDs via Vinbero.
#
# lblen 32 nflen 32 is the uA shape. Linux consumes nflen bits per
# execution and keeps lblen, so node (16) + function (16) go together and
# the SID prefix is lblen + nflen = /64. nflen 16 would leave the function
# CSID in place -- that is the uN shape.
ns_sysctl "$ns_router2" net.ipv6.conf.${veth_rt2_rt1}.seg6_enabled 1
ns_sysctl "$ns_router2" net.ipv6.conf.${veth_rt2_rt3}.seg6_enabled 1

# Both uA SIDs are local addresses on the node, as an operator would
# configure them: a container that ends on one of them arrives with the
# Argument zeroed out and is handed up for local delivery.
run ip netns exec "$ns_router2" ip -6 addr add fd00:aaaa:b002:a003::/128 dev lo nodad
run ip netns exec "$ns_router2" ip -6 addr add fd00:aaaa:b002:a001::/128 dev lo nodad

run ip netns exec "$ns_router2" ip -6 route add local fd00:aaaa:b002:a003::/64 encap seg6local action End.X nh6 fc00:23::1 flavors next-csid lblen 32 nflen 32 dev "$veth_rt2_rt3"
run ip netns exec "$ns_router2" ip -6 route add local fd00:aaaa:b002:a001::/64 encap seg6local action End.X nh6 fc00:12::1 flavors next-csid lblen 32 nflen 32 dev "$veth_rt2_rt1"

# router3: headend towards host1 + terminal uDX4 for the forward direction
ns_sysctl "$ns_router3" net.ipv6.conf.${veth_rt3_h2}.seg6_enabled 1
ns_sysctl "$ns_router3" net.ipv6.conf.${veth_rt3_rt2}.seg6_enabled 1
ns_sysctl "$ns_router3" net.ipv4.conf.${veth_rt3_rt2}.rp_filter 0
ns_sysctl "$ns_router3" net.ipv4.conf.${veth_rt3_h2}.rp_filter 0

run ip netns exec "$ns_router3" ip route add 172.0.1.0/24 encap seg6 mode encap segs fd00:aaaa:b002:a001:b001:d001:: dev "$veth_rt3_rt2"
run ip netns exec "$ns_router3" ip -6 route add fd00:aaaa:b002::/48 via fc00:23::2 dev "$veth_rt3_rt2"
run ip netns exec "$ns_router3" ip -6 route add local fd00:aaaa:b003:d004::/128 encap seg6local action End.DX4 nh4 172.0.2.1 dev "$veth_rt3_h2"

echo ""
echo "=========================================="
echo "SRv6 uA (NEXT-C-SID) Setup Complete!"
echo "=========================================="
echo "uSID plan (block fd00:aaaa/32, 16-bit uSIDs):"
echo "  r1: terminal fd00:aaaa:b001:d001::/128 (End.DX4 -> host1)"
echo "  r2: uA       fd00:aaaa:b002:a003::/64 -> fc00:23::1 (r3)"
echo "  r2: uA       fd00:aaaa:b002:a001::/64 -> fc00:12::1 (r1)"
echo "  r3: terminal fd00:aaaa:b003:d004::/128 (End.DX4 -> host2)"
echo "Containers:"
echo "  host1 -> host2: fd00:aaaa:b002:a003:b003:d004::"
echo "  host2 -> host1: fd00:aaaa:b002:a001:b001:d001::"
echo ""
print_success "Ready for testing!"
