#!/bin/sh
# Bring up the FRR remote PE inside the containerlab node.
#
# The customer VRF and its dummy interface must exist in the kernel
# *before* FRR loads frr.conf -- zebra binds to existing devices, it
# does not create the VRF master or the customer port itself.

# SRv6 needs IPv6 forwarding and the seg6 dataplane knobs. These are
# namespace-scoped, so they must be set inside the container.
sysctl -w net.ipv4.ip_forward=1 2>/dev/null || true
sysctl -w net.ipv6.conf.all.forwarding=1 2>/dev/null || true
sysctl -w net.ipv6.conf.all.seg6_enabled=1 2>/dev/null || true
sysctl -w net.ipv6.conf.default.seg6_enabled=1 2>/dev/null || true
sysctl -w net.ipv6.conf.eth1.seg6_enabled=1 2>/dev/null || true
sysctl -w net.ipv4.conf.all.rp_filter=0 2>/dev/null || true
sysctl -w net.ipv4.conf.default.rp_filter=0 2>/dev/null || true
# VRF strict mode is required by the kernel before FRR's auto-installed
# seg6local End.DT4 localsid (which uses `vrftable`) can come up.
sysctl -w net.vrf.strict_mode=1 2>/dev/null || true

# --- customer VRF + customer-facing port -----------------------------------
# vrf-cust is the L3VPN tenant. cust0 is a dummy carrying the customer
# prefixes FRR exports into VPNv4/VPNv6 with an SRv6 service SID.
ip link add vrf-cust type vrf table 100 2>/dev/null || true
ip link set vrf-cust up
ip link add cust0 type dummy 2>/dev/null || true
ip link set cust0 master vrf-cust
ip link set cust0 up

# Vinbero's locator block as a *connected* prefix on eth1, added before
# FRR starts so it is already present when the first VPN route arrives.
# FRR's SRv6 nexthop validation rejects a service SID reachable only via
# a gateway ("Must be Connected"); without this the 10.0.0.0/24 route
# Vinbero advertises stays `invalid` and never installs into vrf-cust.
ip link set eth1 up 2>/dev/null || true
ip -6 addr add fd00:100::ffff/48 dev eth1 nodad 2>/dev/null || true

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

# More-specific forwarding route for Vinbero's End.DT4 SID. The
# connected /48 above would otherwise make FRR treat the SID as on-link
# and ARP/NDP for it; this /128 sends the encapsulated return traffic
# to Vinbero (2001:db8:ff::2) instead. fd00:100:0:1:: == the SID
# Vinbero advertises with 10.0.0.0/24.
ip -6 route replace fd00:100:0:1::/128 via 2001:db8:ff::2 dev eth1

# FRR auto-installs its End.DT4 localsid at the transposed full SID
# (fd00:200:0:0:1::). Vinbero applies RFC 9252 §4 transposition when it
# decodes the route, so it encapsulates straight to that full SID --
# no lab-side static localsid for the bare locator is needed.

# Pre-resolve the NDP neighbour for the underlay so the first
# encapsulated packet is not dropped on BPF_FIB_LKUP_RET_NO_NEIGH.
ping6 -c 1 -W 2 2001:db8:ff::2 >/dev/null 2>&1 || true

echo "[start.sh] frr PE data plane ready"
