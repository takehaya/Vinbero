#!/bin/sh
# Provider backbone router for the cplane-plugin-2site scenario.
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

# --- interface addressing --------------------------------------------------
# busybox `ip` has no `nodad`; DAD on a point-to-point /64 is harmless.
ip link set eth1 up
ip -6 addr add 2001:db8:1::2/64 dev eth1 2>/dev/null || true
ip link set eth2 up
ip -6 addr add 2001:db8:2::2/64 dev eth2 2>/dev/null || true

# --- IPv6 forwarding -------------------------------------------------------
# A router must not learn routes from neighbors' RAs: an RA-carried
# on-link prefix (FRR advertises its connected prefixes) would install a
# kernel route that outranks the static underlay routes below.
sysctl -w net.ipv6.conf.all.accept_ra=0 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.eth1.accept_ra=0 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.eth2.accept_ra=0 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.eth1.forwarding=1 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.eth2.forwarding=1 >/dev/null 2>&1 || true

# --- static underlay routes ------------------------------------------------
# Towards pe-tokyo (eth1): its loopback + Vinbero's SRv6 locator block.
ip -6 route replace 2001:db8:ff::1/128 via 2001:db8:1::1 dev eth1
ip -6 route replace fd00:100::/48      via 2001:db8:1::1 dev eth1
# Towards pe-osaka (eth2): its loopback + its SRv6 locator block.
ip -6 route replace 2001:db8:ff::2/128 via 2001:db8:2::1 dev eth2
ip -6 route replace fd00:200::/48      via 2001:db8:2::1 dev eth2

# Pre-resolve the underlay NDP neighbours so the first transit packet
# is forwarded immediately rather than queued behind NDP resolution.
ping6 -c 1 -W 2 2001:db8:1::1 >/dev/null 2>&1 || true
ping6 -c 1 -W 2 2001:db8:2::1 >/dev/null 2>&1 || true

echo "[start.sh] core IPv6 router ready"
