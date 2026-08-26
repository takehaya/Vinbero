#!/bin/bash
# examples/end-ut/setup.sh
# Setup uT (End.T with NEXT-C-SID, RFC 9800 Sec.4.1.3) environment

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Note: Linux interface names are limited to 15 chars, so use short prefix
export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-ut-}"

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
#   r2 node b002: uT   fd00:aaaa:b002::/48, bound to vrf100 (table 100)
#   r3 node b003: terminal fd00:aaaa:b003:d004::/128 (Linux End.DX4)
# Forward container: fd00:aaaa:b002:b003:d004:: sent by r1 with
# H.Encaps.Red (a single container emits no SRH), so r2's uT runs on the
# no-SRH dispatch path. The shifted DA is routed in table 100 ONLY: the
# main table carries a blackhole for the same prefix, so a delivered ping
# proves the shift-and-forward used the VRF table (End.T semantics), not
# the default FIB (which would be uN).
#
# There is no Linux oracle phase: seg6local's next-csid flavor exists for
# End and End.X only, so uT has nothing native to compare against.
print_info "Configuring uT (NEXT-C-SID) settings..."

# router1: headend towards host2 (H.Encaps.Red) + return terminal End.DX4
ns_sysctl "$ns_router1" net.ipv6.conf.${veth_rt1_h1}.seg6_enabled 1
ns_sysctl "$ns_router1" net.ipv6.conf.${veth_rt1_rt2}.seg6_enabled 1
ns_sysctl "$ns_router1" net.ipv4.conf.${veth_rt1_rt2}.rp_filter 0
ns_sysctl "$ns_router1" net.ipv4.conf.${veth_rt1_h1}.rp_filter 0

run ip netns exec "$ns_router1" ip route add 172.0.2.0/24 encap seg6 mode encap.red segs fd00:aaaa:b002:b003:d004:: dev "$veth_rt1_rt2"
run ip netns exec "$ns_router1" ip -6 route add fd00:aaaa:b002::/48 via fc00:12::2 dev "$veth_rt1_rt2"
run ip netns exec "$ns_router1" ip -6 route del local fc00:1::1 2>/dev/null || true
run ip netns exec "$ns_router1" ip -6 route add local fc00:1::1/128 encap seg6local action End.DX4 nh4 172.0.1.1 dev "$veth_rt1_h1"

# router2: uT under Vinbero (registered in test.sh). The VRF holds the only
# usable route towards the next uSID node; the main table blackholes it.
ns_sysctl "$ns_router2" net.ipv6.conf.${veth_rt2_rt1}.seg6_enabled 1
ns_sysctl "$ns_router2" net.ipv6.conf.${veth_rt2_rt3}.seg6_enabled 1

run ip netns exec "$ns_router2" ip link add vrf100 type vrf table 100
run ip netns exec "$ns_router2" ip link set vrf100 up
ip netns exec "$ns_router2" ip rule add l3mdev protocol kernel prio 1000 2>/dev/null || true

# The bare uT SID is a local address: a container ending here is handed up.
run ip netns exec "$ns_router2" ip -6 addr add fd00:aaaa:b002::/128 dev lo nodad

run ip netns exec "$ns_router2" ip -6 route add fd00:aaaa:b003::/48 via fc00:23::1 dev "$veth_rt2_rt3" table 100
run ip netns exec "$ns_router2" ip -6 route add blackhole fd00:aaaa:b003::/48

# router3: terminal End.DX4 for the forward direction + return headend
ns_sysctl "$ns_router3" net.ipv6.conf.${veth_rt3_h2}.seg6_enabled 1
ns_sysctl "$ns_router3" net.ipv6.conf.${veth_rt3_rt2}.seg6_enabled 1
ns_sysctl "$ns_router3" net.ipv4.conf.${veth_rt3_rt2}.rp_filter 0
ns_sysctl "$ns_router3" net.ipv4.conf.${veth_rt3_h2}.rp_filter 0

run ip netns exec "$ns_router3" ip route add 172.0.1.0/24 encap seg6 mode encap segs fc00:1::1 dev "$veth_rt3_rt2"
run ip netns exec "$ns_router3" ip -6 route add local fd00:aaaa:b003:d004::/128 encap seg6local action End.DX4 nh4 172.0.2.1 dev "$veth_rt3_h2"

# Pre-resolve NDP (bpf_fib_lookup answers NO_NEIGH otherwise, and uT is
# fail-closed there: the kernel cannot repeat a VRF-scoped lookup for a
# packet that arrived on a non-VRF interface)
print_info "Pre-resolving NDP..."
ip netns exec "$ns_router1" ping6 -c 1 -W 2 fc00:12::2 > /dev/null 2>&1 || true
ip netns exec "$ns_router2" ping6 -c 1 -W 2 fc00:23::1 > /dev/null 2>&1 || true
ip netns exec "$ns_router3" ping6 -c 1 -W 2 fc00:23::2 > /dev/null 2>&1 || true

echo ""
echo "=========================================="
echo "SRv6 uT (NEXT-C-SID) Setup Complete!"
echo "=========================================="
echo "uSID plan (block fd00:aaaa/32, 16-bit uSIDs):"
echo "  r2: uT       fd00:aaaa:b002::/48 (vrf100 = table 100; main table blackholes)"
echo "  r3: terminal fd00:aaaa:b003:d004::/128 (End.DX4 -> host2)"
echo "Forward container (H.Encaps.Red, no SRH): fd00:aaaa:b002:b003:d004::"
echo "Return path: fc00:1::1 (End.DX4 on r1)"
echo ""
print_success "Ready for testing!"
