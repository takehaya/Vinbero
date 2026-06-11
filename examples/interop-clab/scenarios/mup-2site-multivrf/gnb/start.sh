#!/bin/sh
# Emulated gNB for the mup-2site-multivrf scenario, shared by gnb-a and gnb-b.
#
# The script is deliberately identical for both gNBs: the two VPNs fully
# overlap (same N3 subnet, same N3 endpoint, same TEID, same inner
# addressing), so the ONLY thing distinguishing their uplink traffic is the
# GW access interface it arrives on.
#
#   eth1  gNB <-> mup-gw  N3  172.16.0.0/24  (gNB = .1, mup-gw = .254)
set -u

ip addr add 172.16.0.1/24 dev eth1 2>/dev/null || true
ip link set eth1 up

# Toolchain for the data-path test (stdlib send_gtpu.py + tcpdump).
apk add --no-cache python3 tcpdump >/dev/null 2>&1 || true

# Pre-resolve the access gateway so the first GTP-U send does not ARP-drop.
ping -c 1 -W 2 172.16.0.254 >/dev/null 2>&1 || true

echo "[start.sh] gnb ready (N3 172.16.0.1 -> mup-gw 172.16.0.254)"
