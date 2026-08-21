#!/bin/bash
# Prepare the DUT for one benchmark scenario: NIC state, static
# route/neigh toward the TRex receive port, vinberod, and the
# scenario's map entries.
#
# Usage: setup_dut.sh <scenario> [--peers N] [--stats]
#   scenario: encaps-v4 | end | end-dt4 | ecmp | l2-unicast | bum
#   --peers N   bum only: number of bd peers to install (default 1)
#   --stats     use the enable_stats: true config (smoke/debug runs)
set -euo pipefail
cd "$(dirname "$0")"
. ./common.sh

SCENARIO="${1:?usage: setup_dut.sh <scenario> [--peers N] [--stats]}"
shift
# Reject typos before any NIC/route mutation or daemon start; the
# per-scenario case below runs only after those side effects.
case "$SCENARIO" in
    encaps-v4|ecmp|end|end-dt4|l2-unicast|bum) ;;
    *) echo "unknown scenario: $SCENARIO" >&2; exit 2 ;;
esac
CONFIG="$REPO_ROOT/benchmark/configs/vinbero-bench.yml"
while [ $# -gt 0 ]; do
    case "$1" in
        --peers)
            # The dataplane holds at most 8 peers per BD; catch bad
            # values here, before any NIC/daemon side effects.
            case "$2" in
                [1-8]) PEERS="$2" ;;
                *) echo "--peers must be 1..8, got: $2" >&2; exit 2 ;;
            esac
            shift 2 ;;
        --stats) CONFIG="$REPO_ROOT/benchmark/configs/vinbero-bench-stats.yml"; shift ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

BINS=("$VINBEROD_BIN" "$VINBERO_BIN")
[ "$SCENARIO" = ecmp ] && BINS+=("$ECMPDEMO_BIN")
for bin in "${BINS[@]}"; do
    [ -x "$bin" ] || { echo "$bin not found; run 'make build' first" >&2; exit 1; }
done

# Any live vinberod holds an XDP attachment on these NICs, so bail out
# before the force-detach below cuts its dataplane. Catch processes
# without a PID file too (a previous setup that died before writing it).
for pid in $(pgrep -x vinberod); do
    state=$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null || echo "")
    [ "$state" = "Z" ] && continue
    echo "vinberod is running (pid $pid); run teardown_dut.sh first" >&2
    exit 1
done

echo "=== NIC preparation ==="
# Clear any stale XDP attachment (a crashed vinberod leaves its
# bpf_link attached and blocks re-attachment).
for ifname in "$IN_IF" "$OUT_IF"; do
    sudo ip link set dev "$ifname" xdp off 2>/dev/null || true
    sudo ip link set dev "$ifname" xdpgeneric off 2>/dev/null || true
    sudo ip link set dev "$ifname" mtu 3000
    sudo ip link set dev "$ifname" up
done

# bpf_fib_lookup fails with FWD_DISABLED unless forwarding is on.
sudo sysctl -q -w net.ipv6.conf.all.forwarding=1 net.ipv4.ip_forward=1

# Egress toward TRex port 1. The TRex port never answers ND/ARP, so
# the neighbor entries must be static.
sudo ip -6 addr replace "$EGRESS_ADDR6" dev "$OUT_IF"
sudo ip -6 route replace "$REMOTE_SID_PREFIX" via "$NH6" dev "$OUT_IF"
sudo ip -6 neigh replace "$NH6" lladdr "$TREX_PORT1_MAC" dev "$OUT_IF" nud permanent

case "$SCENARIO" in
    end-dt4)
        # End.DT4 looks the inner IPv4 packet up in the VRF table.
        sudo ip link add "$VRF_NAME" type vrf table "$VRF_TABLE" 2>/dev/null || true
        sudo ip link set "$VRF_NAME" up
        sudo ip addr replace "$EGRESS_ADDR4" dev "$OUT_IF"
        # onlink: the gateway is a direct-cabled TRex port with a
        # static neighbor entry, so skip gateway reachability checks.
        sudo ip route replace 10.98.0.0/24 via "$NH4" dev "$OUT_IF" \
            onlink table "$VRF_TABLE"
        sudo ip neigh replace "$NH4" lladdr "$TREX_PORT1_MAC" dev "$OUT_IF" nud permanent
        ;;
    l2-unicast|bum)
        # XDP reads the VLAN tag from packet data; rx offload would
        # strip it into the skb before XDP sees the frame.
        sudo ethtool -K "$IN_IF" rxvlan off
        # L2 frames carry customer MACs, not the NIC MAC; without
        # promiscuous mode the MAC filter drops them in hardware.
        sudo ip link set dev "$IN_IF" promisc on
        ;;
esac

echo "=== start vinberod ==="
sudo setsid "$VINBEROD_BIN" -c "$CONFIG" > "$LOG_FILE" 2>&1 &
wait_health 15 || { cat "$LOG_FILE" >&2; exit 1; }
# $! is the sudo wrapper; vinbero-ecmpdemo reads the daemon's map fds
# via /proc/<pid>/fdinfo, so record the actual vinberod pid.
pgrep -x -n vinberod | sudo tee "$PID_FILE" > /dev/null
[ -s "$PID_FILE" ] || { echo "failed to resolve vinberod pid" >&2; exit 1; }

echo "=== scenario config: $SCENARIO ==="
case "$SCENARIO" in
    encaps-v4)
        vbctl hv4 create --trigger-prefix 10.99.0.0/24 \
            --src-addr "$SID_END" --segments "$SEG_REMOTE"
        ;;
    ecmp)
        vbctl hv4 create --trigger-prefix 10.99.0.0/24 \
            --src-addr "$SID_END" --segments "$SEG_REMOTE"
        sudo "$ECMPDEMO_BIN" group-put --pid "$(cat "$PID_FILE")" \
            --group-id "$ECMP_GROUP_ID" --from-trigger 10.99.0.0/24 \
            --path "fd00:c::1@1" --path "fd00:c::2@1" \
            --path "fd00:c::3@1" --path "fd00:c::4@1"
        sudo "$ECMPDEMO_BIN" attach --pid "$(cat "$PID_FILE")" \
            --group-id "$ECMP_GROUP_ID" --trigger 10.99.0.0/24
        ;;
    end)
        vbctl sid create --trigger-prefix "$SID_END/128" --action END
        ;;
    end-dt4)
        vbctl sid create --trigger-prefix "$SID_DT4/128" \
            --action END_DT4 --vrf-name "$VRF_NAME"
        ;;
    l2-unicast)
        vbctl hl2 create --interface "$IN_IF" --vlan-id "$VLAN_ID" \
            --src-addr "$SID_END" --segments "$SEG_REMOTE"
        ;;
    bum)
        vbctl hl2 create --interface "$IN_IF" --vlan-id "$VLAN_ID" \
            --src-addr "$SID_END" --segments "$SEG_REMOTE" --bd-id "$BD_ID"
        for k in $(seq 1 "$PEERS"); do
            vbctl peer create --bd-id "$BD_ID" --src-addr "$SID_END" \
                --segments "fd00:c::$k"
        done
        ;;
    *)
        echo "unknown scenario: $SCENARIO" >&2
        exit 2
        ;;
esac

echo "DUT ready for scenario $SCENARIO (vinberod pid $(cat "$PID_FILE"))"
