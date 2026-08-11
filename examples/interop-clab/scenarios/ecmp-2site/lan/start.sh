#!/bin/sh
# L2 bridge for the dual-homed customer site: pe-osaka-a (eth1),
# pe-osaka-b (eth2) and ce-osaka (eth3) share one Ethernet segment, so
# both PEs see the same connected 10.2.0.0/24 and the CE can reach
# either gateway.
set -u

ip link add br0 type bridge 2>/dev/null || true
ip link set br0 up
for port in eth1 eth2 eth3; do
    ip link set "$port" master br0
    ip link set "$port" up
done

echo "[start.sh] lan-osaka bridge ready"
