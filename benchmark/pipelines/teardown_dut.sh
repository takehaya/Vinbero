#!/bin/bash
# Undo setup_dut.sh: stop vinberod, clear XDP, remove the benchmark
# route/neigh/VRF state, and restore NIC offloads.
set -uo pipefail
cd "$(dirname "$0")"
. ./common.sh

echo "=== stop vinberod ==="
if [ -f "$PID_FILE" ]; then
    sudo pkill -F "$PID_FILE" 2>/dev/null || true
    sleep 1
    sudo rm -f "$PID_FILE"
fi
# Catch strays from a setup that died before writing the PID file, but
# only ones running this repo's binary; an unrelated vinberod on the
# host is not ours to kill. The prefix match keeps covering a binary
# rebuilt since start (/proc exe then reads "... (deleted)").
for pid in $(pgrep -x vinberod); do
    exe=$(sudo readlink "/proc/$pid/exe" 2>/dev/null || echo "")
    case "$exe" in
        "$VINBEROD_BIN"*) sudo kill "$pid" 2>/dev/null || true ;;
    esac
done
sleep 1

echo "=== clear XDP / restore NICs ==="
# A crashed vinberod leaves its bpf_link attached; always force-detach.
for ifname in "$IN_IF" "$OUT_IF"; do
    sudo ip link set dev "$ifname" xdp off 2>/dev/null || true
    sudo ip link set dev "$ifname" xdpgeneric off 2>/dev/null || true
done
sudo ethtool -K "$IN_IF" rxvlan on 2>/dev/null || true
sudo ip link set dev "$IN_IF" promisc off 2>/dev/null || true

echo "=== remove benchmark route/neigh/VRF state ==="
sudo ip -6 neigh del "$NH6" dev "$OUT_IF" 2>/dev/null || true
sudo ip -6 route del "$REMOTE_SID_PREFIX" via "$NH6" dev "$OUT_IF" 2>/dev/null || true
sudo ip -6 addr del "$EGRESS_ADDR6" dev "$OUT_IF" 2>/dev/null || true
sudo ip neigh del "$NH4" dev "$OUT_IF" 2>/dev/null || true
sudo ip route del 10.98.0.0/24 table "$VRF_TABLE" 2>/dev/null || true
sudo ip addr del "$EGRESS_ADDR4" dev "$OUT_IF" 2>/dev/null || true
sudo ip link del "$VRF_NAME" 2>/dev/null || true

echo "teardown complete (MTU left at 3000; reset manually if needed)"
