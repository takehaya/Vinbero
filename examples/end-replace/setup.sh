#!/bin/bash
# examples/end-replace/setup.sh
# Setup End with REPLACE-CSID (RFC 9800 Sec.4.2) demonstration environment

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Note: Linux interface names are limited to 15 chars, so use short prefix
export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-repl-}"

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

# REPLACE-CSID plan (48-bit block fd00:aabb:ccdd, 32-bit C-SIDs, K=4):
#   r2: End(REP)  C-SIDs b2b2:1 and b2b2:2   (/80, Vinbero)
#   r3: End(REP)  C-SID  b3b3:1              (/80, Vinbero)
#   r3: terminal  C-SID  b3b3:d              (/80, Linux End.DX4)
# C-SID sequence: [b2b2:1 (in the DA), b3b3:1, b2b2:2, b3b3:d], so the
# packet ping-pongs r2 -> r3 -> r2 -> r3 and every walk shape runs on the
# wire: the container cross at r2 (Index 0 -> K-1) and two in-container
# replacements. The single packed container is the SRH segment list entry
#   pos3=b3b3:1  pos2=b2b2:2  pos1=b3b3:d  pos0=0
# which reads as the IPv6 literal 0:0:b3b3:d:b2b2:2:b3b3:1.
#
# There is no Linux oracle phase: seg6local implements only the
# NEXT-C-SID flavor, so REPLACE-CSID has nothing native to compare
# against. test.sh asserts delivery plus the r2 -> r3 TX packet counter
# (two crossings per echo), since delivery alone cannot rule out a
# broken index skipping the middle C-SIDs.
print_info "Configuring REPLACE-CSID settings..."

# router1: headend towards host2 + return terminal End.DX4
ns_sysctl "$ns_router1" net.ipv6.conf.${veth_rt1_h1}.seg6_enabled 1
ns_sysctl "$ns_router1" net.ipv6.conf.${veth_rt1_rt2}.seg6_enabled 1
ns_sysctl "$ns_router1" net.ipv4.conf.${veth_rt1_rt2}.rp_filter 0
ns_sysctl "$ns_router1" net.ipv4.conf.${veth_rt1_h1}.rp_filter 0

run ip netns exec "$ns_router1" ip route add 172.0.2.0/24 encap seg6 mode encap segs fd00:aabb:ccdd:b2b2:1::,0:0:b3b3:d:b2b2:2:b3b3:1 dev "$veth_rt1_rt2"
run ip netns exec "$ns_router1" ip -6 route add fd00:aabb:ccdd::/48 via fc00:12::2 dev "$veth_rt1_rt2"
run ip netns exec "$ns_router1" ip -6 route del local fc00:1::1 2>/dev/null || true
run ip netns exec "$ns_router1" ip -6 route add local fc00:1::1/128 encap seg6local action End.DX4 nh4 172.0.1.1 dev "$veth_rt1_h1"

# router2: two End(REP) C-SIDs under Vinbero (registered in test.sh).
# The block routes towards r3 for C-SIDs this node does not own.
ns_sysctl "$ns_router2" net.ipv6.conf.${veth_rt2_rt1}.seg6_enabled 1
ns_sysctl "$ns_router2" net.ipv6.conf.${veth_rt2_rt3}.seg6_enabled 1
run ip netns exec "$ns_router2" ip -6 route add fd00:aabb:ccdd::/48 via fc00:23::1 dev "$veth_rt2_rt3"

# router3: one End(REP) C-SID under Vinbero + the terminal (Linux
# End.DX4 on the /80: the last C-SID of a REPLACE sequence can be any
# behavior, and the DA's argument bits vary, so the terminal matches the
# block + C-SID prefix rather than a /128).
ns_sysctl "$ns_router3" net.ipv6.conf.${veth_rt3_h2}.seg6_enabled 1
ns_sysctl "$ns_router3" net.ipv6.conf.${veth_rt3_rt2}.seg6_enabled 1
ns_sysctl "$ns_router3" net.ipv4.conf.${veth_rt3_rt2}.rp_filter 0
ns_sysctl "$ns_router3" net.ipv4.conf.${veth_rt3_h2}.rp_filter 0

run ip netns exec "$ns_router3" ip -6 route add fd00:aabb:ccdd::/48 via fc00:23::2 dev "$veth_rt3_rt2"
run ip netns exec "$ns_router3" ip -6 route add local fd00:aabb:ccdd:b3b3:d::/80 encap seg6local action End.DX4 nh4 172.0.2.1 dev "$veth_rt3_h2"

# Return path: host2 -> host1 over the native baseline
run ip netns exec "$ns_router3" ip route add 172.0.1.0/24 encap seg6 mode encap segs fc00:1::1 dev "$veth_rt3_rt2"

# Pre-resolve NDP (bpf_fib_lookup needs resolved neighbours)
print_info "Pre-resolving NDP..."
ip netns exec "$ns_router1" ping6 -c 1 -W 2 fc00:12::2 > /dev/null 2>&1 || true
ip netns exec "$ns_router2" ping6 -c 1 -W 2 fc00:23::1 > /dev/null 2>&1 || true
ip netns exec "$ns_router2" ping6 -c 1 -W 2 fc00:12::1 > /dev/null 2>&1 || true
ip netns exec "$ns_router3" ping6 -c 1 -W 2 fc00:23::2 > /dev/null 2>&1 || true

echo ""
echo "=========================================="
echo "SRv6 REPLACE-CSID Setup Complete!"
echo "=========================================="
echo "C-SID sequence (block fd00:aabb:ccdd/48, 32-bit C-SIDs):"
echo "  b2b2:1 (r2) -> b3b3:1 (r3) -> b2b2:2 (r2) -> b3b3:d (r3, End.DX4)"
echo "Packed container: 0:0:b3b3:d:b2b2:2:b3b3:1"
echo "Return path: fc00:1::1 (End.DX4 on r1)"
echo ""
print_success "Ready for testing!"
