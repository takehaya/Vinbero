#!/bin/sh
# Emulated gNB for the mup-2site scenario.
#
# Sends uplink GTP-U/IPv4 toward the N3 endpoint (mup-gw) and receives the
# downlink GTP-U the access gateway's End.M.GTP4.E emits. python3 (stdlib
# send_gtpu.py) + tcpdump are installed at boot.
#
#   eth1  gNB <-> mup-gw  N3  172.16.0.0/24  (gNB = .1, mup-gw = .254)
set -u

ip addr add 172.16.0.1/24 dev eth1 2>/dev/null || true
ip link set eth1 up

# UE downlink return subnet is reached through the N3 tunnel; nothing to route
# here. Toolchain for the data-path test:
apk add --no-cache python3 tcpdump >/dev/null 2>&1 || true

# Pre-resolve the access gateway so the first GTP-U send does not ARP-drop.
ping -c 1 -W 2 172.16.0.254 >/dev/null 2>&1 || true

echo "[start.sh] gnb ready (N3 172.16.0.1 -> mup-gw 172.16.0.254)"
