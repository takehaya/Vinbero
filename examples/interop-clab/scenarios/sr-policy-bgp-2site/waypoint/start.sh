#!/bin/sh
# SRv6 TE waypoint for the sr-policy-bgp-2site scenario.
#
# Both PEs advertise an SR Policy whose single transport segment is this
# node's End SID (fd00:300:0:ee::1). A steered packet therefore detours
# here before continuing to the egress PE's service SID. End decrements
# Segments Left, copies the next SID (the egress PE's service SID) into the
# IPv6 DA, and re-runs the FIB lookup, which sends it back via the core.
#
# busybox `ip` cannot program seg6local, so install iproute2.
#
# Link:
#   eth1  waypoint <-> core   2001:db8:3::/64   (waypoint = ::1, core = ::2)

set -u

apk add --no-cache iproute2 tcpdump >/dev/null 2>&1 || true

ip link set eth1 up
ip -6 addr add 2001:db8:3::1/64 dev eth1 2>/dev/null || true

sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.all.seg6_enabled=1 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.eth1.seg6_enabled=1 >/dev/null 2>&1 || true

# After End, the DA becomes the egress PE's service SID (fd00:100::/48 or
# fd00:200::/48); route both PE locator blocks back to the core.
ip -6 route replace fd00:100::/48 via 2001:db8:3::2 dev eth1
ip -6 route replace fd00:200::/48 via 2001:db8:3::2 dev eth1

# The TE waypoint End SID.
ip -6 route replace fd00:300:0:ee::1/128 encap seg6local action End dev eth1

ping6 -c 1 -W 2 2001:db8:3::2 >/dev/null 2>&1 || true

echo "[start.sh] waypoint (SRv6 End) ready"
