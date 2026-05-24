#!/bin/sh
# Provider backbone router for the l3vpn-2site interop scenario.
#
# An SRv6 L3VPN transit node forwards purely by the *outer* IPv6 header,
# so `core` needs NO SRv6-service awareness -- it is a plain IPv6
# router. Static routes (no IGP) keep the underlay deterministic: there
# is no convergence race that could make the data-plane test flaky.
#
# Underlay links:
#   eth1  pe-tokyo <-> core      2001:db8:1::/64   (core = ::2, pe-tokyo = ::1)
#   eth2  core     <-> pe-osaka  2001:db8:2::/64   (core = ::2, pe-osaka = ::1)

# Best-effort: alpine's busybox `ip` is limited, so do not abort the
# whole script if one harmless command (e.g. a re-add) returns nonzero.
set -u

# busybox `ip` cannot program seg6local, and this scenario makes `core` an
# SRv6 waypoint (an End segment in the SR Policy), so install the full
# iproute2 (and tcpdump for the chain assertion). The containerlab nodes
# have outbound network during deploy.
apk add --no-cache iproute2 tcpdump >/dev/null 2>&1 || true

# --- interface addressing --------------------------------------------------
ip link set eth1 up
ip -6 addr add 2001:db8:1::2/64 dev eth1 2>/dev/null || true
ip link set eth2 up
ip -6 addr add 2001:db8:2::2/64 dev eth2 2>/dev/null || true

# --- IPv6 forwarding + SRv6 dataplane --------------------------------------
sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.eth1.forwarding=1 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.eth2.forwarding=1 >/dev/null 2>&1 || true
# seg6 must be enabled for the End behavior to process the SRH.
sysctl -w net.ipv6.conf.all.seg6_enabled=1 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.eth1.seg6_enabled=1 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.eth2.seg6_enabled=1 >/dev/null 2>&1 || true

# --- static underlay routes ------------------------------------------------
# Towards pe-tokyo (eth1): its loopback + Vinbero's SRv6 locator block.
ip -6 route replace 2001:db8:ff::1/128 via 2001:db8:1::1 dev eth1
ip -6 route replace fd00:100::/48      via 2001:db8:1::1 dev eth1
# Towards pe-osaka (eth2): its loopback + FRR's SRv6 locator block.
ip -6 route replace 2001:db8:ff::2/128 via 2001:db8:2::1 dev eth2
ip -6 route replace fd00:200::/48      via 2001:db8:2::1 dev eth2

# --- SR Policy waypoint End SID --------------------------------------------
# This scenario steers ce-osaka-bound traffic onto a TWO-segment SR Policy
# [fd00:300:0:ee::1, fd00:200:0:ee::1]: an End on this core node, then an End
# on FRR, then FRR's End.DT4 service SID. That makes core an explicit SRv6
# waypoint (a real segment-by-segment chain, not a single egress detour).
# End decrements Segments Left, copies the next SID (FRR's End) into the
# IPv6 DA, and re-runs the FIB lookup -- fd00:200::/48 is routed to pe-osaka
# above, so the packet advances to the next segment.
ip -6 route replace fd00:300:0:ee::1/128 encap seg6local action End dev eth2

# Pre-resolve the underlay NDP neighbours so the first transit packet
# is forwarded immediately rather than queued behind NDP resolution.
ping6 -c 1 -W 2 2001:db8:1::1 >/dev/null 2>&1 || true
ping6 -c 1 -W 2 2001:db8:2::1 >/dev/null 2>&1 || true

echo "[start.sh] core IPv6 router ready"
