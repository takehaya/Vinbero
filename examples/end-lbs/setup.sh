#!/bin/bash
# examples/end-lbs/setup.sh
# Setup End.LBS (RFC 9800 Sec.7.1, Locator-Block Swap) environment

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Note: Linux interface names are limited to 15 chars, so use short prefix
export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-lbs-}"

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

# End.LBS plan: the routing domain boundary sits on r2. Block A is
# fd00:aaaa/32 (r1 side), block B is fd77:7777:7777/48 (r3 side).
#   r2: End.LBS  fd00:aaaa:b002::/48, target block fd77:7777:7777::/48
#   r3: terminal fd77:7777:7777:d004::/128 (Linux End.DX4, block B)
# The container fd00:aaaa:b002:d004:: enters in block A; the swap at r2
# re-homes the remaining argument onto block B, producing
# fd77:7777:7777:d004::. Block A is deliberately unrouted past r2 (a
# blackhole), so a plain uN shift -- which would produce
# fd00:aaaa:d004:: -- cannot reach r3: delivery proves the swap.
#
# There is no Linux oracle phase: seg6local implements neither End.LBS
# nor the NEXT-C-SID/REPLACE-CSID variants of it.
print_info "Configuring End.LBS settings..."

# router1: headend towards host2 + return terminal End.DX4
ns_sysctl "$ns_router1" net.ipv6.conf.${veth_rt1_h1}.seg6_enabled 1
ns_sysctl "$ns_router1" net.ipv6.conf.${veth_rt1_rt2}.seg6_enabled 1
ns_sysctl "$ns_router1" net.ipv4.conf.${veth_rt1_rt2}.rp_filter 0
ns_sysctl "$ns_router1" net.ipv4.conf.${veth_rt1_h1}.rp_filter 0

run ip netns exec "$ns_router1" ip route add 172.0.2.0/24 encap seg6 mode encap.red segs fd00:aaaa:b002:d004:: dev "$veth_rt1_rt2"
run ip netns exec "$ns_router1" ip -6 route add fd00:aaaa:b002::/48 via fc00:12::2 dev "$veth_rt1_rt2"
run ip netns exec "$ns_router1" ip -6 route del local fc00:1::1 2>/dev/null || true
run ip netns exec "$ns_router1" ip -6 route add local fc00:1::1/128 encap seg6local action End.DX4 nh4 172.0.1.1 dev "$veth_rt1_h1"

# router2: End.LBS under Vinbero (registered in test.sh). Block B routes
# towards r3; block A is blackholed past this node, so only the swapped
# DA can continue.
ns_sysctl "$ns_router2" net.ipv6.conf.${veth_rt2_rt1}.seg6_enabled 1
ns_sysctl "$ns_router2" net.ipv6.conf.${veth_rt2_rt3}.seg6_enabled 1
run ip netns exec "$ns_router2" ip -6 route add fd77:7777:7777::/48 via fc00:23::1 dev "$veth_rt2_rt3"

# The bare End.LBS SID is a local address: a container ending here
# (Argument zero) is handed up unchanged, and the /128 outranks the
# blackhole below.
run ip netns exec "$ns_router2" ip -6 addr add fd00:aaaa:b002::/128 dev lo nodad
run ip netns exec "$ns_router2" ip -6 route add blackhole fd00:aaaa::/32

# router3: terminal End.DX4 in block B + return headend
ns_sysctl "$ns_router3" net.ipv6.conf.${veth_rt3_h2}.seg6_enabled 1
ns_sysctl "$ns_router3" net.ipv6.conf.${veth_rt3_rt2}.seg6_enabled 1
ns_sysctl "$ns_router3" net.ipv4.conf.${veth_rt3_rt2}.rp_filter 0
ns_sysctl "$ns_router3" net.ipv4.conf.${veth_rt3_h2}.rp_filter 0

run ip netns exec "$ns_router3" ip route add 172.0.1.0/24 encap seg6 mode encap segs fc00:1::1 dev "$veth_rt3_rt2"
run ip netns exec "$ns_router3" ip -6 route add local fd77:7777:7777:d004::/128 encap seg6local action End.DX4 nh4 172.0.2.1 dev "$veth_rt3_h2"

# Pre-resolve NDP (bpf_fib_lookup needs resolved neighbours)
print_info "Pre-resolving NDP..."
ip netns exec "$ns_router1" ping6 -c 1 -W 2 fc00:12::2 > /dev/null 2>&1 || true
ip netns exec "$ns_router2" ping6 -c 1 -W 2 fc00:23::1 > /dev/null 2>&1 || true
ip netns exec "$ns_router3" ping6 -c 1 -W 2 fc00:23::2 > /dev/null 2>&1 || true

echo ""
echo "=========================================="
echo "SRv6 End.LBS Setup Complete!"
echo "=========================================="
echo "Blocks: A = fd00:aaaa/32 (blackholed past r2), B = fd77:7777:7777/48"
echo "  r2: End.LBS fd00:aaaa:b002::/48 -> target fd77:7777:7777::/48"
echo "  r3: terminal fd77:7777:7777:d004::/128 (End.DX4 -> host2)"
echo "Container: fd00:aaaa:b002:d004:: (block A in, block B out)"
echo ""
print_success "Ready for testing!"
