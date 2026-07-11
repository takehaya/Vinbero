#!/bin/bash
# Pin the ingress NIC's RX queues 1:1 onto physical cores.
#
# Aggregate forwarding at small frame sizes is bounded by which cores
# the RSS queues land on. Measured on the E810 + Xeon 8362 DUT with
# 64B T.Encaps at line rate (256 flows):
#
#   default (64q, unpinned)          47.5 Mpps
#   32q pinned to physical cores     51.3 Mpps   <- this script
#   32q pinned + fixed coalescing    51.8 Mpps
#   64q, all 34 MSI-X vectors pinned 50.3 Mpps
#
# Per-core throughput drops as cores are added (1.89 Mpps/core at 16
# cores, 1.60 at 32), so the ceiling comes from shared resources, not
# queue count; more vectors than physical cores does not help.
#
# Run BEFORE setup_dut.sh: changing the channel count while the XDP
# program is attached fails. HT sibling layout is CPU N / N+32 on this
# host; queue i goes to CPU i, one per physical core.
#
# Usage: tune_dut.sh [apply|revert]
#   QUEUES=32     queue/core count for apply
#   COALESCE_US=  set to e.g. 25 to also fix interrupt coalescing
set -euo pipefail
cd "$(dirname "$0")"
. ./common.sh

QUEUES=${QUEUES:-32}
COALESCE_US=${COALESCE_US:-}
MODE="${1:-apply}"

if pgrep -x vinberod > /dev/null; then
    echo "vinberod is running; run teardown_dut.sh first (channel changes need XDP detached)" >&2
    exit 1
fi
if systemctl is-active --quiet irqbalance; then
    echo "stopping irqbalance (it would rewrite the pinned affinities)"
    sudo systemctl stop irqbalance
fi

case "$MODE" in
    apply)
        sudo ethtool -L "$IN_IF" combined "$QUEUES"
        sleep 2
        i=0
        for irq in $(awk -F: "/ice-${IN_IF}-TxRx-/{gsub(/ /,\"\",\$1); print \$1}" /proc/interrupts); do
            [ "$i" -ge "$QUEUES" ] && break
            echo "$i" | sudo tee "/proc/irq/$irq/smp_affinity_list" > /dev/null
            i=$((i + 1))
        done
        if [ -n "$COALESCE_US" ]; then
            sudo ethtool -C "$IN_IF" adaptive-rx off adaptive-tx off \
                rx-usecs "$COALESCE_US" tx-usecs "$COALESCE_US"
        fi
        echo "pinned $i TxRx IRQs of $IN_IF to CPUs 0..$((i - 1))"
        ;;
    revert)
        sudo ethtool -L "$IN_IF" combined 64
        sudo ethtool -C "$IN_IF" adaptive-rx on adaptive-tx on \
            rx-usecs 50 tx-usecs 50 2>/dev/null || true
        echo "restored $IN_IF to 64 combined queues, adaptive coalescing"
        ;;
    *)
        echo "usage: tune_dut.sh [apply|revert]" >&2
        exit 2
        ;;
esac
