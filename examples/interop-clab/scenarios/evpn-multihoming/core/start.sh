#!/bin/sh
# Provider backbone router for the evpn-multihoming scenario.
#
# `core` is a plain IPv6 router (no BGP, no SRv6 service); it forwards by the
# outer IPv6 header between the three PEs. Static routes (no IGP) keep the
# underlay deterministic.
#
#   eth1  pe1 <-> core  2001:db8:1::/64  (core = ::2, pe1 = ::1)
#   eth2  pe2 <-> core  2001:db8:2::/64  (core = ::2, pe2 = ::1)
#   eth3  pe3 <-> core  2001:db8:3::/64  (core = ::2, pe3 = ::1)

set -u

# tcpdump lets the test confirm SRv6 outer DAs on transit.
apk add --no-cache tcpdump >/dev/null 2>&1 || true

ip link set eth1 up; ip -6 addr add 2001:db8:1::2/64 dev eth1 2>/dev/null || true
ip link set eth2 up; ip -6 addr add 2001:db8:2::2/64 dev eth2 2>/dev/null || true
ip link set eth3 up; ip -6 addr add 2001:db8:3::2/64 dev eth3 2>/dev/null || true

sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true

# Loopbacks (iBGP) per PE.
ip -6 route replace 2001:db8:ff::1/128 via 2001:db8:1::1 dev eth1
ip -6 route replace 2001:db8:ff::2/128 via 2001:db8:2::1 dev eth2
ip -6 route replace 2001:db8:ff::3/128 via 2001:db8:3::1 dev eth3
# Locator blocks (End.DT2U/DT2M service SIDs) per PE.
ip -6 route replace fd00:100::/48 via 2001:db8:1::1 dev eth1
ip -6 route replace fd00:200::/48 via 2001:db8:2::1 dev eth2
ip -6 route replace fd00:300::/48 via 2001:db8:3::1 dev eth3

ping6 -c 1 -W 2 2001:db8:1::1 >/dev/null 2>&1 || true
ping6 -c 1 -W 2 2001:db8:2::1 >/dev/null 2>&1 || true
ping6 -c 1 -W 2 2001:db8:3::1 >/dev/null 2>&1 || true

echo "[start.sh] core IPv6 router ready"
