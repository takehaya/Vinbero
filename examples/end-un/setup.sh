#!/bin/bash
# examples/end-un/setup.sh
# Setup uN (NEXT-C-SID, RFC 9800) operation demonstration environment

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
#   r2 node b002, uN             fd00:aaaa:b002::/48
#   r3 node b003, terminal uDX4  fd00:aaaa:b003:d004::/128
# Forward container: fd00:aaaa:b002:b003:d004:: (r2 shifts, r3 terminates)
# Return  container: fd00:aaaa:b002:b001:d001:: (r2 shifts, r1 terminates)
print_info "Configuring NEXT-C-SID (uN) settings..."

# router1: headend towards host2 + terminal uDX4 for the return direction
ns_sysctl "$ns_router1" net.ipv6.conf.${veth_rt1_h1}.seg6_enabled 1
ns_sysctl "$ns_router1" net.ipv6.conf.${veth_rt1_rt2}.seg6_enabled 1
ns_sysctl "$ns_router1" net.ipv4.conf.${veth_rt1_rt2}.rp_filter 0
ns_sysctl "$ns_router1" net.ipv4.conf.${veth_rt1_h1}.rp_filter 0

run ip netns exec "$ns_router1" ip route add 172.0.2.0/24 encap seg6 mode encap segs fd00:aaaa:b002:b003:d004:: dev "$veth_rt1_rt2"
run ip netns exec "$ns_router1" ip -6 route add fd00:aaaa:b002::/48 via fc00:12::2 dev "$veth_rt1_rt2"
run ip netns exec "$ns_router1" ip -6 route add local fd00:aaaa:b001:d001::/128 encap seg6local action End.DX4 nh4 172.0.1.1 dev "$veth_rt1_h1"

# router2: uN. Phase 1 of test.sh uses this Linux-native next-csid route as
# the oracle; phase 2 removes it and reinstalls the same SID via Vinbero.
ns_sysctl "$ns_router2" net.ipv6.conf.${veth_rt2_rt1}.seg6_enabled 1
ns_sysctl "$ns_router2" net.ipv6.conf.${veth_rt2_rt3}.seg6_enabled 1

run ip netns exec "$ns_router2" ip -6 route add local fd00:aaaa:b002::/48 encap seg6local action End flavors next-csid lblen 32 nflen 16 dev "$veth_rt2_rt1"
run ip netns exec "$ns_router2" ip -6 route add fd00:aaaa:b003::/48 via fc00:23::1 dev "$veth_rt2_rt3"
run ip netns exec "$ns_router2" ip -6 route add fd00:aaaa:b001::/48 via fc00:12::1 dev "$veth_rt2_rt1"

# router3: headend towards host1 + terminal uDX4 for the forward direction
ns_sysctl "$ns_router3" net.ipv6.conf.${veth_rt3_h2}.seg6_enabled 1
ns_sysctl "$ns_router3" net.ipv6.conf.${veth_rt3_rt2}.seg6_enabled 1
ns_sysctl "$ns_router3" net.ipv4.conf.${veth_rt3_rt2}.rp_filter 0
ns_sysctl "$ns_router3" net.ipv4.conf.${veth_rt3_h2}.rp_filter 0

run ip netns exec "$ns_router3" ip route add 172.0.1.0/24 encap seg6 mode encap segs fd00:aaaa:b002:b001:d001:: dev "$veth_rt3_rt2"
run ip netns exec "$ns_router3" ip -6 route add fd00:aaaa:b002::/48 via fc00:23::2 dev "$veth_rt3_rt2"
run ip netns exec "$ns_router3" ip -6 route add local fd00:aaaa:b003:d004::/128 encap seg6local action End.DX4 nh4 172.0.2.1 dev "$veth_rt3_h2"

# Pre-resolve NDP from router2 to both neighbors. The XDP uN shift path is
# fail-closed: bpf_fib_lookup returning no-neighbor drops instead of passing
# to the kernel, so the neighbor entries must exist before phase 2 traffic.
run ip netns exec "$ns_router2" ping -6 -c 1 -W 2 fc00:23::1 > /dev/null
run ip netns exec "$ns_router2" ping -6 -c 1 -W 2 fc00:12::1 > /dev/null

echo ""
echo "=========================================="
echo "SRv6 uN (NEXT-C-SID) Setup Complete!"
echo "=========================================="
echo "uSID plan (block fd00:aaaa/32, 16-bit uSIDs):"
echo "  r1: terminal fd00:aaaa:b001:d001::/128 (End.DX4 -> host1)"
echo "  r2: uN       fd00:aaaa:b002::/48"
echo "  r3: terminal fd00:aaaa:b003:d004::/128 (End.DX4 -> host2)"
echo "Containers:"
echo "  host1 -> host2: fd00:aaaa:b002:b003:d004::"
echo "  host2 -> host1: fd00:aaaa:b002:b001:d001::"
echo ""
print_success "Ready for testing!"
