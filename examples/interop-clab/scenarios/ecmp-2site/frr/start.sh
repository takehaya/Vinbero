#!/bin/sh
# Bring up one of the two FRR PEs of the ecmp-2site scenario. The two
# nodes differ only in their addresses, so the per-node values arrive as
# arguments (see clab.yml):
#
#   $1  loopback        (iBGP peering / SRv6 transport, /128 on lo)
#   $2  underlay addr   (eth2 towards the core, /64)
#   $3  customer addr   (eth1 on the dual-homed site LAN, /24, in vrf-cust)
#
# The customer VRF must exist in the kernel *before* FRR loads
# frr.conf -- zebra binds to existing devices, it does not create the
# VRF master itself.
LOOPBACK=$1
UNDERLAY=$2
CUSTOMER=$3

# SRv6 needs IPv6 forwarding and the seg6 dataplane knobs. These are
# namespace-scoped, so they must be set inside the container.
sysctl -w net.ipv4.ip_forward=1 2>/dev/null || true
sysctl -w net.ipv6.conf.all.forwarding=1 2>/dev/null || true
sysctl -w net.ipv6.conf.all.seg6_enabled=1 2>/dev/null || true
sysctl -w net.ipv6.conf.default.seg6_enabled=1 2>/dev/null || true
sysctl -w net.ipv6.conf.eth1.seg6_enabled=1 2>/dev/null || true
sysctl -w net.ipv6.conf.eth2.seg6_enabled=1 2>/dev/null || true
sysctl -w net.ipv4.conf.all.rp_filter=0 2>/dev/null || true
sysctl -w net.ipv4.conf.default.rp_filter=0 2>/dev/null || true
# VRF strict mode is required by the kernel before FRR's auto-installed
# seg6local End.DT4 localsid (which uses `vrftable`) can come up.
sysctl -w net.vrf.strict_mode=1 2>/dev/null || true

# --- customer VRF + customer-facing port -----------------------------------
if ! ip link show vrf-cust >/dev/null 2>&1; then
    ip link add vrf-cust type vrf table 100
fi
if ! ip link show vrf-cust >/dev/null 2>&1; then
    echo "ERROR: failed to create VRF vrf-cust -- is the kernel 'vrf' module loaded on the host? (modprobe vrf)" >&2
    exit 1
fi
ip link set vrf-cust up
ip link set eth1 master vrf-cust
ip link set eth1 up

# --- addressing ------------------------------------------------------------
# frr.conf repeats these (interface stanzas), but assigning them here too
# keeps the node reachable even before the daemons settle.
ip -6 addr add "$LOOPBACK"/128 dev lo 2>/dev/null || true
ip -6 addr add "$UNDERLAY"/64 dev eth2 nodad 2>/dev/null || true
ip addr add "$CUSTOMER"/24 dev eth1 2>/dev/null || true

# --- underlay link towards the core ----------------------------------------
ip link set eth2 up 2>/dev/null || true

# NOTE: unlike the l3vpn-2site scenario, Vinbero's locator block is NOT
# added as a connected prefix here. FRR 10.2.1 validates the received
# service SID against the static fd00:100::/48 route just fine, and the
# connected prefix is actively harmful: distance 0 beats the static in
# the kernel, the post-encap outer packet then resolves the SID as
# on-link, and its NDP -- which nothing on the core link answers --
# fails, blackholing every return packet.

# FRR ships an entrypoint that starts the daemons selected in
# /etc/frr/daemons. watchfrr then keeps them alive.
/usr/lib/frr/frrinit.sh start

# Give the daemons a moment, then load the integrated config so that
# any ordering-sensitive SRv6/BGP statements apply cleanly.
sleep 4
vtysh -b || true
