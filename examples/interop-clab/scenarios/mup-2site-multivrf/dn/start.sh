#!/bin/sh
# Emulated data network (DN) for the mup-2site-multivrf scenario, shared by
# dn-a and dn-b.
#
# Identical for both DNs on purpose: the two VPNs overlap down to the DN host
# address (10.0.0.1), so a packet reaching the wrong DN would be
# indistinguishable by content — only the per-VPN End.DT4 -> kernel VRF on
# mup-pe keeps them apart, which is exactly what test.sh asserts.
#
#   eth1  DN <-> mup-pe  N6  10.0.0.0/24  (DN = .1, mup-pe = .254)
set -u

ip addr add 10.0.0.1/24 dev eth1 2>/dev/null || true
ip link set eth1 up

# Reach the UE subnet via the data gateway.
ip route replace 10.1.0.0/24 via 10.0.0.254 dev eth1

apk add --no-cache tcpdump >/dev/null 2>&1 || true
ping -c 1 -W 2 10.0.0.254 >/dev/null 2>&1 || true

echo "[start.sh] dn ready (N6 10.0.0.1, UE 10.1.0.0/24 via mup-pe)"
