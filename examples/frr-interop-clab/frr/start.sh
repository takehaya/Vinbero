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

# --- customer VRF + customer-facing port -----------------------------------
# vrf-cust is the L3VPN tenant. cust0 is a dummy carrying the customer
# prefixes FRR exports into VPNv4/VPNv6 with an SRv6 service SID.
ip link add vrf-cust type vrf table 100 2>/dev/null || true
ip link set vrf-cust up
ip link add cust0 type dummy 2>/dev/null || true
ip link set cust0 master vrf-cust
ip link set cust0 up

# FRR ships an entrypoint that starts the daemons selected in
# /etc/frr/daemons. watchfrr then keeps them alive.
/usr/lib/frr/frrinit.sh start

# Give the daemons a moment, then load the integrated config so that
# any ordering-sensitive SRv6/BGP statements apply cleanly.
sleep 4
vtysh -b || true
