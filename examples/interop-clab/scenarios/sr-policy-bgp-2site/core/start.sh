#!/bin/sh
# Provider backbone router for the sr-policy-bgp-2site scenario.
#
# `core` is a plain IPv6 router (no BGP, no SRv6 service). It is the hub
# that connects both PEs and the TE waypoint; it forwards purely by the
# outer IPv6 header. Static routes (no IGP) keep the underlay deterministic.
#
# Links:
#   eth1  pe-tokyo <-> core     2001:db8:1::/64  (core = ::2, pe-tokyo = ::1)
#   eth2  pe-osaka <-> core     2001:db8:2::/64  (core = ::2, pe-osaka = ::1)
#   eth3  core     <-> waypoint 2001:db8:3::/64  (core = ::2, waypoint = ::1)

set -u

# --- interface addressing --------------------------------------------------
ip link set eth1 up
ip -6 addr add 2001:db8:1::2/64 dev eth1 2>/dev/null || true
ip link set eth2 up
ip -6 addr add 2001:db8:2::2/64 dev eth2 2>/dev/null || true
ip link set eth3 up
ip -6 addr add 2001:db8:3::2/64 dev eth3 2>/dev/null || true

# --- IPv6 forwarding -------------------------------------------------------
sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true

# --- static underlay routes ------------------------------------------------
# Towards pe-tokyo: loopback + locator block.
ip -6 route replace 2001:db8:ff::1/128 via 2001:db8:1::1 dev eth1
ip -6 route replace fd00:100::/48      via 2001:db8:1::1 dev eth1
# Towards pe-osaka: loopback + locator block.
ip -6 route replace 2001:db8:ff::2/128 via 2001:db8:2::1 dev eth2
ip -6 route replace fd00:200::/48      via 2001:db8:2::1 dev eth2
# Towards the waypoint: its SRv6 End block. A steered packet's first hop is
# the waypoint End SID (fd00:300:0:ee::1), so the core must route the
# fd00:300::/48 block out eth3.
ip -6 route replace fd00:300::/48      via 2001:db8:3::1 dev eth3

# Pre-resolve the underlay NDP neighbours so the first transit packet is
# forwarded immediately rather than queued behind NDP resolution.
ping6 -c 1 -W 2 2001:db8:1::1 >/dev/null 2>&1 || true
ping6 -c 1 -W 2 2001:db8:2::1 >/dev/null 2>&1 || true
ping6 -c 1 -W 2 2001:db8:3::1 >/dev/null 2>&1 || true

echo "[start.sh] core IPv6 router ready"
