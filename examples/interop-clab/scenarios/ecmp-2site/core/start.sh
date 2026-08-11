#!/bin/sh
# Provider backbone router for the ecmp-2site interop scenario: a plain
# IPv6 router with static routes towards the three PEs (no IGP, no
# convergence race). This is also where the failover test cuts one FRR
# PE off (eth3 down), so the loss is a mid-path underlay failure -- the
# kind BGP takes its hold time to notice and the prober catches in
# hundreds of milliseconds.
#
# Underlay links:
#   eth1  pe-tokyo   <-> core  2001:db8:1::/64  (core = ::2, pe = ::1)
#   eth2  pe-osaka-a <-> core  2001:db8:2::/64  (core = ::2, pe = ::1)
#   eth3  pe-osaka-b <-> core  2001:db8:3::/64  (core = ::2, pe = ::1)
set -u

ip link set eth1 up
ip -6 addr add 2001:db8:1::2/64 dev eth1 2>/dev/null || true
ip link set eth2 up
ip -6 addr add 2001:db8:2::2/64 dev eth2 2>/dev/null || true
ip link set eth3 up
ip -6 addr add 2001:db8:3::2/64 dev eth3 2>/dev/null || true

sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true

# Towards pe-tokyo: its loopback + Vinbero's locator block.
ip -6 route replace 2001:db8:ff::1/128 via 2001:db8:1::1 dev eth1
ip -6 route replace fd00:100::/48      via 2001:db8:1::1 dev eth1
# Towards pe-osaka-a: its loopback + locator block.
ip -6 route replace 2001:db8:ff::2/128 via 2001:db8:2::1 dev eth2
ip -6 route replace fd00:200::/48      via 2001:db8:2::1 dev eth2
# Towards pe-osaka-b: its loopback + locator block.
ip -6 route replace 2001:db8:ff::3/128 via 2001:db8:3::1 dev eth3
ip -6 route replace fd00:300::/48      via 2001:db8:3::1 dev eth3

# Pre-resolve the underlay NDP neighbours so the first transit packet
# is forwarded immediately rather than queued behind NDP resolution.
ping6 -c 1 -W 2 2001:db8:1::1 >/dev/null 2>&1 || true
ping6 -c 1 -W 2 2001:db8:2::1 >/dev/null 2>&1 || true
ping6 -c 1 -W 2 2001:db8:3::1 >/dev/null 2>&1 || true

echo "[start.sh] core IPv6 router ready"
