#!/usr/bin/env python3
"""Aggregate benchmark reps into mean/sd per (scenario, size).

Input : one or more <scenario>_rep<k>.csv produced by
        pipelines/run_bench.sh (one row per frame size).
Output: CSV to stdout with mean and sd across reps for rx_mpps
        (forwarded rate), loss_pct, and tx_mpps (offered rate).

Usage: python3 benchmark/analysis/stats.py results/encaps-v4_rep*.csv
"""
import csv
import statistics as st
import sys


def load(path):
    rows = {}
    with open(path) as f:
        for r in csv.DictReader(f):
            key = (r["scenario"], int(r["size"]))
            rows[key] = {
                "rx_mpps": float(r["rx_mpps"]),
                "tx_mpps": float(r["tx_mpps"]),
                "loss_pct": float(r["loss_pct"]),
            }
    return rows


def msd(xs):
    return st.mean(xs), (st.stdev(xs) if len(xs) > 1 else 0.0)


def main(argv):
    paths = argv[1:]
    if not paths:
        sys.exit("usage: stats.py rep1.csv [rep2.csv ...]")
    reps = [load(p) for p in paths]
    keys = sorted(set().union(*[set(r) for r in reps]))

    # Keep stdout pure CSV so it can be piped into other tools.
    print(f"n={len(reps)} reps from: {', '.join(paths)}", file=sys.stderr)
    print("scenario,size,n,"
          "rx_mpps_mean,rx_mpps_sd,tx_mpps_mean,tx_mpps_sd,"
          "loss_pct_mean,loss_pct_sd")
    for key in keys:
        cells = [r[key] for r in reps if key in r]
        rx_m, rx_s = msd([c["rx_mpps"] for c in cells])
        tx_m, tx_s = msd([c["tx_mpps"] for c in cells])
        lo_m, lo_s = msd([c["loss_pct"] for c in cells])
        print(f"{key[0]},{key[1]},{len(cells)},"
              f"{rx_m:.3f},{rx_s:.4f},{tx_m:.3f},{tx_s:.4f},"
              f"{lo_m:.3f},{lo_s:.4f}")


if __name__ == "__main__":
    main(sys.argv)
