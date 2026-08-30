#!/bin/bash
# examples/end-un-usd/setup.sh
# Setup uN + USD (decap at the end of a no-SRH uSID container) environment

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Note: Linux interface names are limited to 15 chars, so use short prefix
export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-unusd-}"

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
#   r3 node b003: uN fd00:aaaa:b003::/48 with the USD flavor
# Forward path: r1 sends H.Encaps.Red with the single-uSID container
# fd00:aaaa:b003:: -- a bare uN SID and no SRH on the wire. At r3 the
# Argument is already zero, so this is the container's end; USD strips the
# outer IPv6 and forwards the inner IPv4 to host2 over the connected
# route. Without USD the packet would be handed to the kernel still
# encapsulated and go nowhere.
#
# There is no Linux oracle phase: the kernel's seg6local End rejects
# "flavors usd" (only PSP and NEXT-C-SID are implemented), so there is
# nothing native to compare against.
print_info "Configuring uN + USD settings..."

# router1: headend towards host2 (H.Encaps.Red) + return terminal End.DX4
ns_sysctl "$ns_router1" net.ipv6.conf.${veth_rt1_h1}.seg6_enabled 1
ns_sysctl "$ns_router1" net.ipv6.conf.${veth_rt1_rt2}.seg6_enabled 1
ns_sysctl "$ns_router1" net.ipv4.conf.${veth_rt1_rt2}.rp_filter 0
ns_sysctl "$ns_router1" net.ipv4.conf.${veth_rt1_h1}.rp_filter 0

run ip netns exec "$ns_router1" ip route add 172.0.2.0/24 encap seg6 mode encap.red segs fd00:aaaa:b003:: dev "$veth_rt1_rt2"
run ip netns exec "$ns_router1" ip -6 route add fd00:aaaa:b003::/48 via fc00:12::2 dev "$veth_rt1_rt2"
run ip netns exec "$ns_router1" ip -6 route del local fc00:1::1 2>/dev/null || true
run ip netns exec "$ns_router1" ip -6 route add local fc00:1::1/128 encap seg6local action End.DX4 nh4 172.0.1.1 dev "$veth_rt1_h1"

# router2: plain IPv6 transit towards the uSID block
run ip netns exec "$ns_router2" ip -6 route add fd00:aaaa:b003::/48 via fc00:23::1 dev "$veth_rt2_rt3"

# router3: uN + USD under Vinbero (registered in test.sh) + return headend
ns_sysctl "$ns_router3" net.ipv6.conf.${veth_rt3_h2}.seg6_enabled 1
ns_sysctl "$ns_router3" net.ipv6.conf.${veth_rt3_rt2}.seg6_enabled 1
ns_sysctl "$ns_router3" net.ipv4.conf.${veth_rt3_rt2}.rp_filter 0
ns_sysctl "$ns_router3" net.ipv4.conf.${veth_rt3_h2}.rp_filter 0

# The bare uN SID is a local address on the node, as an operator would
# configure it; USD intercepts the tunnelled packets before delivery.
run ip netns exec "$ns_router3" ip -6 addr add fd00:aaaa:b003::/128 dev lo nodad

run ip netns exec "$ns_router3" ip route add 172.0.1.0/24 encap seg6 mode encap segs fc00:1::1 dev "$veth_rt3_rt2"

# Pre-resolve NDP/ARP (bpf_fib_lookup needs resolved neighbours; the
# post-decap IPv4 hop towards host2 needs ARP)
print_info "Pre-resolving NDP/ARP..."
ip netns exec "$ns_router1" ping6 -c 1 -W 2 fc00:12::2 > /dev/null 2>&1 || true
ip netns exec "$ns_router2" ping6 -c 1 -W 2 fc00:23::1 > /dev/null 2>&1 || true
ip netns exec "$ns_router3" ping6 -c 1 -W 2 fc00:23::2 > /dev/null 2>&1 || true
ip netns exec "$ns_router3" ping -c 1 -W 2 172.0.2.1 > /dev/null 2>&1 || true

echo ""
echo "=========================================="
echo "SRv6 uN + USD Setup Complete!"
echo "=========================================="
echo "uSID plan (block fd00:aaaa/32, 16-bit uSIDs):"
echo "  r3: uN fd00:aaaa:b003::/48, flavor USD"
echo "Forward (H.Encaps.Red, no SRH): container fd00:aaaa:b003:: -> USD decap at r3"
echo "Return path: fc00:1::1 (End.DX4 on r1)"
echo ""
print_success "Ready for testing!"
