# Shared settings for the Vinbero TRex benchmark pipelines.
# Source this from setup_dut.sh / run_bench.sh / teardown_dut.sh.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# DUT NICs (E810-C 100G, direct-cabled to the TRex host)
IN_IF=${IN_IF:-enp138s0f0np0}       # TRex port 0 -> Vinbero ingress
OUT_IF=${OUT_IF:-enp138s0f1np1}     # Vinbero egress -> TRex port 1

# TRex host
TREX_HOST=${TREX_HOST:-ocxma-trex}
TREX_PORT1_MAC=${TREX_PORT1_MAC:-40:a6:b7:82:cd:d9}
TREX_DRIVER_DIR=${TREX_DRIVER_DIR:-vinbero-bench}

# Benchmark addressing (self-contained; must match trex/vinbero_streams.py)
SID_END=fc00:a::1
SID_DT4=fc00:a::d4
SEG_REMOTE=fd00:c::1
EGRESS_ADDR6=fd00:b::1/64
NH6=fd00:b::2
REMOTE_SID_PREFIX=fd00:c::/64
EGRESS_ADDR4=192.0.2.1/24
NH4=192.0.2.2
VRF_NAME=vrf100
VRF_TABLE=100
BD_ID=100
VLAN_ID=100
ECMP_GROUP_ID=1

RPC=${RPC:-http://127.0.0.1:8082}
VINBEROD_BIN="$REPO_ROOT/out/bin/vinberod"
VINBERO_BIN="$REPO_ROOT/out/bin/vinbero"
ECMPDEMO_BIN="$REPO_ROOT/out/bin/vinbero-ecmpdemo"
PID_FILE=/tmp/vinbero-bench.pid
LOG_FILE=/tmp/vinbero-bench.log

DURATION=${DURATION:-30}
REPS=${REPS:-5}
PPS=${PPS:-0}          # 0 = line rate (mult=100%)
PEERS=${PEERS:-1}
FLOWS=${FLOWS:-32}
RESULT_DIR=${RESULT_DIR:-$REPO_ROOT/benchmark/results}

vbctl() {
    "$VINBERO_BIN" -s "$RPC" "$@"
}

# Sum of the wire-level MAC counters (unicast+multicast+broadcast) for
# one direction. XDP_REDIRECT bypasses the kernel software stats, so
# only the .nic hardware counters see the forwarded packets.
nic_pkts() {
    local ifname="$1" dir="$2"  # dir: rx|tx
    sudo ethtool -S "$ifname" \
        | awk -v d="$dir" '$1 ~ d"_(unicast|multicast|broadcast).nic:" {s += $NF} END {print s+0}'
}

wait_health() {
    local addr="${RPC#http://}" timeout="${1:-15}" elapsed=0
    while [ "$elapsed" -lt "$timeout" ]; do
        if curl -sf "http://${addr}/health" > /dev/null 2>&1; then
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    echo "vinberod not ready after ${timeout}s" >&2
    return 1
}
