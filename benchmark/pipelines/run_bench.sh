#!/bin/bash
# Run one scenario across a frame-size sweep with repetitions.
# setup_dut.sh for the same scenario must have completed first.
#
# Usage: run_bench.sh <scenario> [size ...]
#   Env: DURATION (s/run, default 30), REPS (default 5),
#        PPS (offered total, default 200e6), PEERS (bum amplification),
#        RESULT_DIR (default benchmark/results)
#
# One CSV per rep: <scenario>_rep<k>.csv with a row per size.
set -euo pipefail
cd "$(dirname "$0")"
. ./common.sh

SCENARIO="${1:?usage: run_bench.sh <scenario> [size ...]}"
shift
if [ $# -gt 0 ]; then
    SIZES=("$@")
else
    case "$SCENARIO" in
        encaps-v4|ecmp) SIZES=(64 128 256 512 1024 1420) ;;
        end|end-dt4)    SIZES=(118 160 256 512 1024 1420) ;;
        l2-unicast|bum) SIZES=(68 512 1420) ;;
        *) echo "unknown scenario: $SCENARIO" >&2; exit 2 ;;
    esac
fi

mkdir -p "$RESULT_DIR"

echo "=== deploy TRex driver to $TREX_HOST ==="
ssh "$TREX_HOST" "mkdir -p ~/$TREX_DRIVER_DIR"
scp -q "$REPO_ROOT/benchmark/trex/vinbero_streams.py" \
    "$TREX_HOST:$TREX_DRIVER_DIR/vinbero_streams.py"

HEADER="scenario,size,rep,duration_s,peers,tx_opackets,rx_ipackets,tx_mpps,rx_mpps,tx_gbps,loss_pct,nic_rx_mpps,nic_tx_mpps"

for rep in $(seq 1 "$REPS"); do
    CSV="$RESULT_DIR/${SCENARIO}_rep${rep}.csv"
    echo "$HEADER" > "$CSV"
    for size in "${SIZES[@]}"; do
        echo "=== $SCENARIO size=$size rep=$rep/$REPS (${DURATION}s) ==="
        rx_before=$(nic_pkts "$IN_IF" rx)
        tx_before=$(nic_pkts "$OUT_IF" tx)

        trex_json=$(ssh "$TREX_HOST" \
            "python3 ~/$TREX_DRIVER_DIR/vinbero_streams.py \
             --scenario $SCENARIO --duration $DURATION --size $size \
             --pps $PPS --peers $PEERS --flows $FLOWS")

        rx_after=$(nic_pkts "$IN_IF" rx)
        tx_after=$(nic_pkts "$OUT_IF" tx)

        python3 - "$SCENARIO" "$size" "$rep" "$trex_json" \
            "$rx_before" "$rx_after" "$tx_before" "$tx_after" "$CSV" <<'PY'
import sys, json
scen, size, rep, trex_json, rb, ra, tb, ta, csv = sys.argv[1:10]
t = json.loads(trex_json)
dur = float(t["duration_s"])
row = (f'{scen},{size},{rep},{t["duration_s"]},{t["peers"]},'
       f'{t["tx_opackets"]},{t["rx_ipackets"]},{t["tx_mpps"]},{t["rx_mpps"]},'
       f'{t["tx_gbps"]},{t["loss_pct"]},'
       f'{(int(ra) - int(rb)) / dur / 1e6:.3f},'
       f'{(int(ta) - int(tb)) / dur / 1e6:.3f}')
print(row)
open(csv, "a").write(row + "\n")
PY
        sleep 2
    done
    echo "wrote $CSV"
done

echo
echo "aggregate with: python3 $REPO_ROOT/benchmark/analysis/stats.py $RESULT_DIR/${SCENARIO}_rep*.csv"
