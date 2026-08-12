#!/bin/sh
# Bring up the FRR PE (pe-osaka) inside the containerlab node.
#
# The customer VRF must exist in the kernel *before* FRR loads
# frr.conf -- zebra binds to existing devices, it does not create the
# VRF master itself. eth1 (customer-facing) is enslaved to vrf-cust.
#
# Interfaces:
#   eth1  pe-osaka <-> ce-osaka  customer 10.2.0.0/24  (in vrf-cust)
#   eth2  pe-osaka <-> core      underlay 2001:db8:2::/64
#   lo    loopback 2001:db8:ff::2  (iBGP peering / SRv6 transport)

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
# vrf-cust is the L3VPN tenant. eth1 faces ce-osaka and is enslaved to
# the VRF; FRR exports the 10.2.0.0/24 connected prefix into VPNv4 with
# an SRv6 service SID.
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

# --- underlay link towards the core ----------------------------------------
ip link set eth2 up 2>/dev/null || true

# Vinbero's locator block is deliberately NOT configured as a connected
# prefix here. FRR 10.2.1 validates the service SID against the static
# fd00:100::/48 route in frr.conf just fine, and a connected /48 is
# actively harmful: it makes the whole locator on-link for FRR (the SID
# gets NDPed on eth2 instead of routed) and leaks into FRR's router
# advertisements as an on-link prefix, teaching the core a poisonous
# fd00:100::/48-on-eth2 route that beats its static toward pe-tokyo --
# a nondeterministic (RA-timing-dependent) blackhole of the return path.

# FRR ships an entrypoint that starts the daemons selected in
# /etc/frr/daemons. watchfrr then keeps them alive.
/usr/lib/frr/frrinit.sh start

# Give the daemons a moment, then load the integrated config so that
# any ordering-sensitive SRv6/BGP statements apply cleanly.
sleep 4
vtysh -b || true

# --- data-plane wiring (SRv6 L3VPN forwarding) -----------------------------
# Wait for zebra to settle the locator + VPN routes before adding the
# static glue the data plane needs.
sleep 4

# The encapsulated return traffic follows the static fd00:100::/48 route
# from frr.conf via the core; no per-SID /128 override is needed.

# FRR auto-installs its End.DT4 localsid at the transposed full SID
# (fd00:200:0:0:1::). Vinbero applies RFC 9252 §4 transposition when it
# decodes the route, so it encapsulates straight to that full SID --
# no lab-side static localsid for the bare locator is needed.

# Pre-resolve the NDP neighbour for the underlay so the first
# encapsulated packet is not dropped on BPF_FIB_LKUP_RET_NO_NEIGH.
ping6 -c 1 -W 2 2001:db8:2::2 >/dev/null 2>&1 || true

echo "[start.sh] pe-osaka (FRR) PE data plane ready"
