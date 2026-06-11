#!/bin/sh
# Provider backbone router for the mup-2site-multivrf scenario.
#
# Plain IPv6 router (no BGP). Carries the SRv6 underlay between the two MUP
# gateways and the iBGP session to/from the MUP controller, by static routes.
#
#   eth1  mup-gw <-> core  2001:db8:1::/64  (core = ::2, mup-gw = ::1)
#   eth2  core <-> mup-pe    2001:db8:2::/64  (core = ::2, mup-pe  = ::1)
#   eth3  core <-> mup-c      2001:db8:3::/64  (core = ::2, mup-c    = ::1)
set -u

ip link set eth1 up; ip -6 addr add 2001:db8:1::2/64 dev eth1 2>/dev/null || true
ip link set eth2 up; ip -6 addr add 2001:db8:2::2/64 dev eth2 2>/dev/null || true
ip link set eth3 up; ip -6 addr add 2001:db8:3::2/64 dev eth3 2>/dev/null || true

sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true

# Loopbacks (iBGP peers).
ip -6 route replace 2001:db8:ff::a/128 via 2001:db8:1::1 dev eth1   # mup-gw
ip -6 route replace 2001:db8:ff::d/128 via 2001:db8:2::1 dev eth2   # mup-pe
ip -6 route replace 2001:db8:ff::c/128 via 2001:db8:3::1 dev eth3   # mup-c
# SRv6 locator blocks (service SIDs): interwork at mup-gw, direct at mup-pe.
ip -6 route replace fd00:a::/48 via 2001:db8:1::1 dev eth1
ip -6 route replace fd00:d::/48 via 2001:db8:2::1 dev eth2

echo "[start.sh] core (IPv6 backbone) ready"
