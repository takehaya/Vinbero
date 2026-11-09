#!/bin/bash
# examples/bum-ecmp-underlay/setup.sh
# Build the environment: a host behind one PE with two uplinks to a transit
# router, and the peers of the BD reached over a multipath route.
#
#   host (ce) ---- PE (vinberod) ==== up1/up2 ==== transit (rt)
#
# The peers are only destinations: the test counts their copies on the
# transit router's two ports, which is all a peer's copy needs to prove.

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/test_utils.sh"
source "${SCRIPT_DIR}/../common/netns.sh"
source "${SCRIPT_DIR}/../common/veth.sh"

check_root

ns_ce=becmp-ce
ns_pe=becmp-pe
ns_rt=becmp-rt

print_info "Creating namespaces..."
create_netns "$ns_ce"
create_netns "$ns_pe"
create_netns "$ns_rt"

create_veth_pair becmp-c0 "$ns_ce" becmp-ac "$ns_pe"
create_veth_pair becmp-up1 "$ns_pe" becmp-d1 "$ns_rt"
create_veth_pair becmp-up2 "$ns_pe" becmp-d2 "$ns_rt"

ip netns exec "$ns_pe" sysctl -qw net.ipv6.conf.all.forwarding=1 net.ipv6.conf.default.forwarding=1
ip netns exec "$ns_rt" sysctl -qw net.ipv6.conf.all.forwarding=1

# The host side: a VLAN-tagged access port.
run modprobe 8021q 2>/dev/null || true
ip -n "$ns_ce" link add link becmp-c0 name becmp-c0.100 type vlan id 100
ip -n "$ns_ce" link set becmp-c0.100 up
# The tag must stay in the frame for the AC match (generic XDP on veth).
run ip netns exec "$ns_ce" ethtool -K becmp-c0 txvlan off 2>/dev/null || true

# The uplinks. nodad: a tentative address cannot be used right away.
ip -n "$ns_pe" addr add fd00:a::1/64 dev becmp-up1 nodad
ip -n "$ns_pe" addr add fd00:b::1/64 dev becmp-up2 nodad
ip -n "$ns_pe" addr add fc00:1::1/128 dev lo
ip -n "$ns_rt" addr add fd00:a::2/64 dev becmp-d1 nodad
ip -n "$ns_rt" addr add fd00:b::2/64 dev becmp-d2 nodad

# The peers' locators, reached over both uplinks.
ip -n "$ns_pe" -6 route add fc00:100::/32 \
    nexthop via fd00:a::2 dev becmp-up1 \
    nexthop via fd00:b::2 dev becmp-up2

print_success "Environment ready"
