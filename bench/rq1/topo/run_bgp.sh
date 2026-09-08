#!/bin/bash
# Compare BGP -> builtin/cplane/relay -> forwarding, with fixed kernel End.DT4
# endpoints. Requires make bench-rq1-build; run with sudo MODE=cplane ./run_bgp.sh.
set -euo pipefail

# Parse the whole driver before starting a long run. Bash otherwise reads
# later commands from the file again, so an edit can change an active trial.
main() {
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
export REPO_ROOT
cd "$REPO_ROOT"
MODE="${MODE:-builtin}"
[[ "$MODE" != inproc ]] || MODE=builtin
case "$MODE" in builtin|cplane|relay) ;; *) echo "MODE must be builtin, cplane or relay" >&2; exit 2 ;; esac
TRIALS="${1:-10}"
RATE="${RATE:-100000}"
[[ "$TRIALS" =~ ^[1-9][0-9]*$ && "$RATE" =~ ^[1-9][0-9]*$ ]] || { echo "TRIALS and RATE must be positive integers" >&2; exit 2; }
# Compare decimal text before arithmetic, leaving room for the final trial++
# in Bash's signed 64-bit loop counter.
if (( ${#TRIALS} > 19 )) || { (( ${#TRIALS} == 19 )) && [[ "$TRIALS" > 9223372036854775806 ]]; }; then
    echo "TRIALS exceeds the supported loop counter range" >&2
    exit 2
fi
if (( ${#RATE} > 10 )) || (( RATE > 1000000000 )); then
    echo "RATE exceeds nanosecond pacing resolution" >&2
    exit 2
fi
[[ "$EUID" == 0 ]] || { echo "run with sudo after make bench-rq1-build" >&2; exit 2; }

VINBEROD="${VINBEROD:-${REPO_ROOT}/out/bin/vinberod}"
VBCTL="${VBCTL:-${REPO_ROOT}/out/bin/vinbero}"
PROBE="${REPO_ROOT}/out/bench/rq1probe"
CHURN="${REPO_ROOT}/out/bench/rq1bgp"
RELAY="${REPO_ROOT}/out/bench/rq1relay"
WASM="${WASM:-${REPO_ROOT}/sdk/examples/cplane-custom-behavior/plugin.wasm}"
for bin in "$VINBEROD" "$VBCTL" "$PROBE" "$CHURN" "$RELAY"; do
    [[ -x "$bin" ]] || { echo "missing executable $bin; run make bench-rq1-build" >&2; exit 2; }
done
if [[ "$MODE" == cplane && ! -r "$WASM" ]]; then echo "missing WASM: $WASM" >&2; exit 2; fi
for command in ip python3 ethtool timeout flock; do command -v "$command" >/dev/null; done

umask 077
WORK="$(python3 - "${WORK:-}" <<'PY'
import os, stat, sys, tempfile
from pathlib import Path
path = Path(os.path.abspath(sys.argv[1])) if sys.argv[1] else Path('/tmp/unused')
# A private leaf is insufficient when another user can replace its parent.
# Root-owned sticky directories such as /tmp protect root-owned children.
for parent in reversed(path.parents):
    info = parent.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or
            (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX)):
        raise SystemExit('WORK requires trusted root-owned parents without symlinks: ' + str(parent))
if sys.argv[1]:
    try:
        os.mkdir(path, 0o700)
    except FileExistsError:
        raise SystemExit('WORK must be a new directory: ' + str(path))
else:
    path = Path(tempfile.mkdtemp(prefix='vinbero-rq1.', dir='/tmp'))
print(path)
PY
)"
OUT="$(python3 - "$WORK" "${OUT:-${WORK}/results.csv}" <<'PY'
import os, sys
work, out = sys.argv[1], os.path.abspath(sys.argv[2])
if out == work or os.path.commonpath([work, out]) != work:
    raise SystemExit('OUT must be inside WORK')
print(out)
PY
)"
[[ ! -e "$OUT" && ! -L "$OUT" ]] || { echo "refusing to overwrite $OUT" >&2; exit 2; }
mkdir -p "$(dirname "$OUT")"
# Hold the exclusively-created file open for the whole run. Replacing its
# pathname later must not redirect privileged appends to another file.
set -o noclobber
exec 8>"$OUT"
set +o noclobber
export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-b$(printf '%x' "$$")-}"
[[ "$TOPO_NS_PREFIX" =~ ^[a-zA-Z0-9-]{1,9}$ ]] || { echo "invalid namespace prefix" >&2; exit 2; }
# Serialise uses of a chosen prefix, including across trials. The setup also
# refuses namespaces that predate this run.
python3 - <<'PY'
import os, stat
path = '/run/vinbero-rq1'
try:
    os.mkdir(path, 0o700)
except FileExistsError:
    pass
info = os.lstat(path)
if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
    raise SystemExit('unsafe lock directory: ' + path)
PY
exec 9>"/run/vinbero-rq1/${TOPO_NS_PREFIX}.lock"
flock -n 9 || { echo "namespace prefix is already in use" >&2; exit 2; }
ns_src="${TOPO_NS_PREFIX}src"
ns_rt="${TOPO_NS_PREFIX}rt"
ns_pea="${TOPO_NS_PREFIX}pea"
ns_peb="${TOPO_NS_PREFIX}peb"
topology_up=false
export TOPOLOGY_READY_FILE="$WORK/topology-ready"
pids=()
completed=0

cleanup_trial() {
    # A signal can arrive between launching an asynchronous command and saving
    # $! in pids. Bash's own job table already owns that child at this point.
    while read -r pid; do
        [[ " ${pids[*]} " == *" $pid "* ]] || pids+=("$pid")
    done < <(jobs -p)
    # Every PID was started by this shell. Never kill by process name: another
    # lab or measurement may be using the same daemon binary.
    for pid in "${pids[@]}"; do kill -TERM "$pid" 2>/dev/null || true; done
    for attempt in {1..50}; do
        alive=false
        for pid in "${pids[@]}"; do if kill -0 "$pid" 2>/dev/null; then alive=true; fi; done
        if ! "$alive"; then break; fi
        sleep 0.1
    done
    for pid in "${pids[@]}"; do kill -KILL "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; done
    pids=()
    if "$topology_up" || [[ -f "$TOPOLOGY_READY_FILE" ]]; then
        "$SCRIPT_DIR/teardown.sh" >/dev/null || return 1
        topology_up=false
        rm -f -- "$TOPOLOGY_READY_FILE"
    fi
    return 0
}
finish() {
    local status=$?
    trap - EXIT INT TERM
    cleanup_trial || { if (( status == 0 )); then status=1; fi; }
    printf '{"exit_code":%d,"completed_trials":%d,"requested_trials":%d}\n' "$status" "$completed" "$TRIALS" > "$WORK/status.json"
    echo "artifacts: $WORK" >&2
    exit "$status"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir "$WORK/instrument"
cp "$SCRIPT_DIR/"{setup.sh,teardown.sh,check.py,vinbero-bgp.yml,run_bgp.sh} "$WORK/instrument/"
cp "$REPO_ROOT/examples/common/netns.sh" "$WORK/instrument/netns.sh"
SCRIPT_DIR="$WORK/instrument"
export NETNS_HELPER="$SCRIPT_DIR/netns.sh"
mkdir "$WORK/bin"
# A later build must not change subsequent trials or invalidate the hashes.
cp --reflink=auto -- "$VINBEROD" "$WORK/bin/vinberod"
cp --reflink=auto -- "$VBCTL" "$WORK/bin/vinbero"
cp --reflink=auto -- "$PROBE" "$WORK/bin/rq1probe"
cp --reflink=auto -- "$CHURN" "$WORK/bin/rq1bgp"
cp --reflink=auto -- "$RELAY" "$WORK/bin/rq1relay"
VINBEROD="$WORK/bin/vinberod"
VBCTL="$WORK/bin/vinbero"
PROBE="$WORK/bin/rq1probe"
CHURN="$WORK/bin/rq1bgp"
RELAY="$WORK/bin/rq1relay"
if [[ "$MODE" == cplane ]]; then
    cp --reflink=auto -- "$WASM" "$WORK/bin/plugin.wasm"
    WASM="$WORK/bin/plugin.wasm"
fi
python3 - "$WORK/run.json" "$MODE" "$RATE" "$TRIALS" "$TOPO_NS_PREFIX" "$VINBEROD" "$VBCTL" "$PROBE" "$CHURN" "$RELAY" "$WASM" "$SCRIPT_DIR/"* <<'PY'
import hashlib, json, os, platform, subprocess, sys
from pathlib import Path
out, mode, rate, trials, prefix, *artifacts = sys.argv[1:]
def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()
data = dict(mode=mode, rate=int(rate), trials=int(trials), namespace_prefix=prefix,
            kernel=platform.release(), machine=platform.machine(), cpu_affinity=sorted(os.sched_getaffinity(0)),
            kernel_cmdline=Path('/proc/cmdline').read_text().strip(),
            source_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
            source_dirty=bool(subprocess.check_output(['git', '--no-optional-locks', 'status', '--porcelain'], text=True).strip()),
            endpoint_behavior='0xfe01' if mode == 'cplane' else '0x0013',
            endpoint='kernel End.DT4', xdp_mode='generic', persistence=False,
            artifacts={str(Path(p).resolve()): digest(p) for p in artifacts if Path(p).is_file()})
Path(out).write_text(json.dumps(data, indent=2) + '\n')
PY
echo "trial,mode,latency_us,lost,misdelivered,sample_gap_us" >&8

ctl() { timeout 5 ip netns exec "$ns_rt" "$VBCTL" -s http://127.0.0.1:18081 "$@"; }
check() { ip netns exec "$ns_rt" python3 "$SCRIPT_DIR/check.py" wait --mode "$MODE" "$@"; }
wait_receiver() {
    local pid=$1 log=$2
    for attempt in {1..50}; do
        if grep -qx ready "$log"; then return; fi
        kill -0 "$pid" || return 1
        sleep 0.1
    done
    echo "receiver did not bind: $log" >&2
    return 1
}
wait_child() {
    local child=$1 status=0
    wait "$child" || status=$?
    local remaining=()
    for pid in "${pids[@]}"; do
        [[ "$pid" == "$child" ]] || remaining+=("$pid")
    done
    pids=("${remaining[@]}")
    return "$status"
}

for ((trial=1; trial<=TRIALS; trial++)); do
    trial_dir="$WORK/trial-$trial"
    mkdir "$trial_dir"
    "$SCRIPT_DIR/setup.sh" > "$trial_dir/setup.log" 2>&1
    topology_up=true
    python3 - "$SCRIPT_DIR/vinbero-bgp.yml" "$trial_dir/vinbero.yml" "$TOPO_NS_PREFIX" "$trial_dir/state.json" <<'PY'
import json, sys
from pathlib import Path
source, target, prefix, state = sys.argv[1:]
Path(target).write_text(Path(source).read_text().replace('@PREFIX@', prefix).replace("'@STATE_PATH@'", json.dumps(state)))
PY
    bgp_flags=()
    [[ "$MODE" == relay ]] || bgp_flags+=(--bgp-enabled)
    ip netns exec "$ns_rt" "$VINBEROD" --config "$trial_dir/vinbero.yml" "${bgp_flags[@]}" > "$trial_dir/daemon.log" 2>&1 &
    daemon_pid=$!; pids+=("$daemon_pid")
    check --out "$trial_dir/empty.json"
    ctl locator create --name LOC1 --prefix fd00:100::/48 --block-len 32 --node-len 16 --function-len 16 --argument-len 64 --behavior classic > "$trial_dir/locator.log"

    behavior=0
    relay_pid=""
    if [[ "$MODE" == cplane ]]; then
        behavior=65025
        ctl plugin cplane register --name rq1-receiver --wasm "$WASM" \
            --behavior 0xFE01 --family vpnv4 --capability headend \
            --headend-prefix 10.0.2.0/24 --tick-ms 1000 > "$trial_dir/register.log"
    elif [[ "$MODE" == relay ]]; then
        ip netns exec "$ns_rt" "$RELAY" -neighbor fd00:12::2 -rpc 127.0.0.1:18081 > "$trial_dir/relay.log" 2>&1 &
        relay_pid=$!; pids+=("$relay_pid")
    fi
    ip netns exec "$ns_pea" "$CHURN" -neighbor fd00:12::1 -next-hop fd00:12::2 \
        -initial-sid fd00:a::100 -change-to fd00:b::100 -behavior "$behavior" \
        -change-file "$trial_dir/change-at" -ready-timeout 90s -hold 30s > "$trial_dir/churn.log" 2>&1 &
    churn_pid=$!; pids+=("$churn_pid")
    check --sid fd00:a::100 --out "$trial_dir/initial.json"

    ip netns exec "$ns_pea" "$PROBE" recv -bind 0.0.0.0:9999 -name pe-a -duration 7s -out "$trial_dir/pea.csv" > "$trial_dir/pea.log" 2>&1 &
    pid_a=$!; pids+=("$pid_a")
    ip netns exec "$ns_peb" "$PROBE" recv -bind 0.0.0.0:9999 -name pe-b -duration 7s -out "$trial_dir/peb.csv" > "$trial_dir/peb.log" 2>&1 &
    pid_b=$!; pids+=("$pid_b")
    wait_receiver "$pid_a" "$trial_dir/pea.log"
    wait_receiver "$pid_b" "$trial_dir/peb.log"
    change_at=$(( $(date +%s%N) + 2000000000 ))
    ip netns exec "$ns_src" "$PROBE" send -target 10.0.2.2:9999 -rate "$RATE" -duration 3s -tag 1 \
        -start-at "$((change_at - 1000000000))" -out "$trial_dir/sent.csv" > "$trial_dir/sender.log" 2>&1 &
    pid_s=$!; pids+=("$pid_s")
    printf '%s\n' "$change_at" > "$trial_dir/change-at.tmp"
    mv "$trial_dir/change-at.tmp" "$trial_dir/change-at"
    wait_child "$pid_s"
    wait_child "$pid_a"
    wait_child "$pid_b"
    kill -0 "$daemon_pid" "$churn_pid"
    if [[ -n "$relay_pid" ]]; then kill -0 "$relay_pid"; fi
    check --sid fd00:b::100 --previous "$trial_dir/initial.json" --timeout 5 --out "$trial_dir/final.json"
    change_ns="$(sed -n 's/^change_ns=//p' "$trial_dir/churn.log")"
    [[ "$change_ns" =~ ^[0-9]+$ ]] || { echo "missing change timestamp" >&2; exit 1; }
    python3 "$SCRIPT_DIR/check.py" capture --sent "$trial_dir/sent.csv" \
        --recv "$trial_dir/pea.csv" "$trial_dir/peb.csv" --change-ns "$change_ns"
    "$PROBE" analyze -sent "$trial_dir/sent.csv" -recv "$trial_dir/pea.csv,$trial_dir/peb.csv" \
        -change-ns "$change_ns" -old pe-a -new pe-b > "$trial_dir/verdict.txt"
    cleanup_trial
    python3 - "$trial_dir/verdict.txt" "$trial" "$MODE" <<'PY'
import csv, os, sys
from pathlib import Path
verdict, trial, mode = sys.argv[1:]
fields = dict(word.split('=', 1) for word in Path(verdict).read_text().split())
if fields.get('detected') != 'true':
    raise SystemExit('convergence not detected')
with os.fdopen(os.dup(8), 'a', newline='') as stream:
    csv.writer(stream).writerow([trial, mode] + [fields[k] for k in ('latency_us', 'lost', 'misdelivered', 'sample_gap_us')])
PY
    completed=$trial
    echo "trial $trial ($MODE): $(cat "$trial_dir/verdict.txt")"
done
echo "wrote $OUT"
}

main "$@"
