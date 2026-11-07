#!/bin/bash
# examples/common/test_utils.sh
# Test utility functions

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error: This script must be run as root${NC}"
        exit 1
    fi
}

# Execute command with echo (for debugging)
# Usage: run <command...>
run() {
    echo "$@"
    "$@" || exit 1
}

# Print success message
print_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

# Print error message
print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Print info message
print_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}


# Start vinbero daemon in a namespace with signal isolation.
# Uses setsid to prevent signal propagation from parent shell.
# Sets VINBERO_LAST_PID to the background process PID.
# Usage: start_vinbero <namespace> <config_path> <log_file>
start_vinbero() {
    local ns="$1" config="$2" log="$3"
    if [ ! -x "${VINBEROD_BIN}" ]; then
        print_error "vinberod not found at ${VINBEROD_BIN}. Build it first from the repo root: make build"
        return 1
    fi
    setsid ip netns exec "$ns" ${VINBEROD_BIN} -c "$config" > "$log" 2>&1 &
    VINBERO_LAST_PID=$!
    sleep 0.5
    if ! ps -p $VINBERO_LAST_PID > /dev/null 2>&1; then
        print_error "Vinbero failed to start"
        cat "$log" 2>/dev/null
        return 1
    fi
    print_success "Vinbero started (PID: $VINBERO_LAST_PID)"
    return 0
}

# Wait for vinbero's health endpoint to respond.
# Polls /health every second until ready or timeout.
# Usage: wait_vinbero_ready <namespace> <bind_addr> [timeout_sec]
wait_vinbero_ready() {
    local ns="$1" addr="$2" timeout="${3:-10}"
    local elapsed=0
    while [ $elapsed -lt $timeout ]; do
        if ip netns exec "$ns" curl -sf "http://${addr}/health" > /dev/null 2>&1; then
            print_success "Vinbero ready (${elapsed}s)"
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    print_error "Vinbero not ready after ${timeout}s"
    return 1
}

# Test ping connectivity (auto-detects IPv4/IPv6)
# Usage: test_ping <namespace> <destination> [count]
test_ping() {
    local ns="$1"
    local dst="$2"
    local count="${3:-3}"
    local cmd="ping"
    local proto="IPv4"

    # Auto-detect IPv6 by presence of colon
    if [[ "$dst" == *":"* ]]; then
        cmd="ping6"
        proto="IPv6"
    fi

    print_info "Testing $proto ping from $ns to $dst..."

    if ip netns exec "$ns" $cmd -c "$count" -W 2 "$dst" > /dev/null 2>&1; then
        print_success "$proto ping to $dst succeeded"
        return 0
    else
        print_error "$proto ping to $dst failed"
        return 1
    fi
}

# Usage: test_ping_with_counter <namespace> <destination> <description> [interface]
# Like test_ping but tallies the caller's TESTS_PASSED / TESTS_FAILED counters
# (define both before calling). Pass an interface to ping with -I (used by the
# VLAN/L2 examples to pick the source subinterface).
#
# Always returns 0: callers run under `set -e` and want every assertion to run
# and be tallied, then fail at the end via `[ $TESTS_FAILED -gt 0 ] && exit 1`.
# A non-zero return would abort the script on the first failed ping, before the
# summary. The ping argv is built as an array so the target / -I argument are
# never word-split or globbed.
test_ping_with_counter() {
    local ns=$1
    local target=$2
    local desc=$3
    local interface=${4:-}

    print_info "Testing: $desc"
    # Auto-detect IPv6 by the presence of a colon in the target, mirroring
    # test_ping above so callers do not need a separate ping6 helper.
    local ping_bin=ping
    [[ "$target" == *":"* ]] && ping_bin=ping6
    local ping_cmd=("$ping_bin" -c 3 -W 2)
    [ -n "$interface" ] && ping_cmd+=(-I "$interface")
    ping_cmd+=("$target")

    if ip netns exec "$ns" "${ping_cmd[@]}" > /dev/null 2>&1; then
        print_success "$desc: PASS"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        print_error "$desc: FAIL"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
    return 0
}

# ========== BUM replication mode (settings.l2.bum_mode) ==========

# bum_mode_config <yaml> <out>: prints the vinberod config to start with for
# BUM_MODE (default tc). tc prints <yaml> unchanged; xdp writes <yaml> plus
# settings.l2.bum_mode to <out> and prints <out>. <yaml> must end with its
# top-level settings: block.
bum_mode_config() {
    local src="$1" out="$2"
    case "${BUM_MODE:-tc}" in
        tc) echo "$src" ;;
        xdp)
            { cat "$src"; printf '  l2:\n    bum_mode: xdp\n'; } > "$out"
            echo "$out"
            ;;
        *)
            print_error "unknown BUM_MODE '${BUM_MODE}' (want tc or xdp)" >&2
            return 1
            ;;
    esac
}

# bum_marker_send <ns> <iface> <tag>: sends one broadcast Ethernet frame
# (EtherType 0x88b5, local experimental) whose payload carries <tag>, so a
# capture can count the copies of exactly this frame.
bum_marker_send() {
    local ns="$1" iface="$2" tag="$3"
    ip netns exec "$ns" python3 -c '
import socket, sys
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind((sys.argv[1], 0))
mac = s.getsockname()[4]
payload = sys.argv[2].encode().ljust(46, b"\0")
s.send(b"\xff" * 6 + mac + b"\x88\xb5" + payload)
' "$iface" "$tag"
}

# bum_capture_start <ns> <iface> <pcap>: background tcpdump; sets CAPTURE_PID.
bum_capture_start() {
    # -Z root: a privilege-dropped tcpdump cannot reopen a pcap it left in
    # sticky /tmp under fs.protected_regular.
    ip netns exec "$1" tcpdump -Z root -i "$2" -U -nn -p -w "$3" > /dev/null 2>&1 &
    CAPTURE_PID=$!
}

# bum_effective_mode <vinberod log>: the BUM mode that vinberod runs with:
# BUM_MODE, or tc-fallback when BUM_MODE is xdp but vinberod found at
# startup that this kernel cannot run xdp mode (the copies of a generic XDP
# broadcast share one buffer) and replicates in tc instead.
bum_effective_mode() {
    if [ "${BUM_MODE:-tc}" = xdp ] && grep -q "xdp BUM replication unavailable" "$1"; then
        echo tc-fallback
    else
        echo "${BUM_MODE:-tc}"
    fi
}

# bum_marker_count <pcap> <tag>: number of captured frames that contain
# <tag>, plain or SRv6-encapsulated alike.
bum_marker_count() {
    python3 - "$1" "$2" <<'PY'
import struct, sys
data = open(sys.argv[1], "rb").read()
tag = sys.argv[2].encode()
off, n = 24, 0
while off + 16 <= len(data):
    incl = struct.unpack("<I", data[off + 8:off + 12])[0]
    off += 16
    if tag in data[off:off + incl]:
        n += 1
    off += incl
print(n)
PY
}


