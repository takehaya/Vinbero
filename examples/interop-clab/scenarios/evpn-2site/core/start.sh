#!/bin/sh
# Provider backbone router for the evpn-2site scenario.
#
# `core` is a plain IPv6 router (no BGP, no SRv6 service). It forwards purely
# by the outer IPv6 header between the two PEs. Static routes (no IGP) keep
# the underlay deterministic.
#
# Links:
#   eth1  pe-tokyo <-> core  2001:db8:1::/64  (core = ::2, pe-tokyo = ::1)
#   eth2  pe-osaka <-> core  2001:db8:2::/64  (core = ::2, pe-osaka = ::1)

set -u

# tcpdump lets the test confirm the SRv6 outer DA on transit (no XDP here).
apk add --no-cache tcpdump >/dev/null 2>&1 || true

ip link set eth1 up
ip -6 addr add 2001:db8:1::2/64 dev eth1 2>/dev/null || true
ip link set eth2 up
ip -6 addr add 2001:db8:2::2/64 dev eth2 2>/dev/null || true

sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true

# Towards pe-tokyo: loopback (iBGP) + locator block (End.DT2U service SID).
ip -6 route replace 2001:db8:ff::1/128 via 2001:db8:1::1 dev eth1
ip -6 route replace fd00:100::/48      via 2001:db8:1::1 dev eth1
# Towards pe-osaka: loopback + locator block.
ip -6 route replace 2001:db8:ff::2/128 via 2001:db8:2::1 dev eth2
ip -6 route replace fd00:200::/48      via 2001:db8:2::1 dev eth2

ping6 -c 1 -W 2 2001:db8:1::1 >/dev/null 2>&1 || true
ping6 -c 1 -W 2 2001:db8:2::1 >/dev/null 2>&1 || true

echo "[start.sh] core IPv6 router ready"
