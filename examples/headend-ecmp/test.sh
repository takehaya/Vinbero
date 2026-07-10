#!/bin/bash
# examples/headend-ecmp/test.sh
# Test the headend ECMP path group: per-flow spread over two paths and
# liveness-driven fast reroute.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/test_utils.sh"

check_root

VINBEROD_BIN="${SCRIPT_DIR}/../../out/bin/vinberod"
VINBERO_BIN="${SCRIPT_DIR}/../../out/bin/vinbero"
ECMPDEMO_BIN="${SCRIPT_DIR}/../../out/bin/vinbero-ecmpdemo"
VINBERO_CONFIG="${SCRIPT_DIR}/vinbero_router1.yaml"

# Set namespace prefix (must match setup.sh)
export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-hec-}"
ns_host1="${TOPO_NS_PREFIX}host1"
ns_host2="${TOPO_NS_PREFIX}host2"
ns_router1="${TOPO_NS_PREFIX}router1"
ns_router2a="${TOPO_NS_PREFIX}router2a"
ns_router2b="${TOPO_NS_PREFIX}router2b"
if_path_a="${TOPO_NS_PREFIX}r2art1"  # router2a's interface facing router1
if_path_b="${TOPO_NS_PREFIX}r2brt1"  # router2b's interface facing router1

GROUP_ID=1
NUM_FLOWS=100

TESTS_PASSED=0
TESTS_FAILED=0
VINBERO_PID=""

if [ ! -x "$ECMPDEMO_BIN" ]; then
    print_error "vinbero-ecmpdemo not found at ${ECMPDEMO_BIN}. Build it first from the repo root: make build"
    exit 1
fi

cleanup() {
    # Guard against PID reuse: only kill if the PID is still our vinberod.
    if [ -n "$VINBERO_PID" ] && [ "$(ps -o comm= -p "$VINBERO_PID" 2>/dev/null)" = "vinberod" ]; then
        kill "$VINBERO_PID" 2>/dev/null || true
        wait "$VINBERO_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# rx_packets of the router1-facing interface on each transit router. Forward
# traffic is the only bulk stream in that direction, so deltas isolate the
# per-path load.
rx_path_a() { ip netns exec "$ns_router2a" cat "/sys/class/net/${if_path_a}/statistics/rx_packets"; }
rx_path_b() { ip netns exec "$ns_router2b" cat "/sys/class/net/${if_path_b}/statistics/rx_packets"; }

# Send NUM_FLOWS single-datagram UDP flows from host1 to host2. Every
# datagram uses a fresh ephemeral source port, so each one is a distinct
# 5-tuple for the headend's flow hash.
send_flows() {
    for _ in $(seq 1 "$NUM_FLOWS"); do
        ip netns exec "$ns_host1" bash -c 'echo -n x > /dev/udp/172.0.2.1/33434' 2>/dev/null || true
    done
}

# assert_spread <label> <min_a> <min_b> <max_a> — sends flows, then checks
# the per-path packet deltas against the bounds ("" = unbounded).
assert_spread() {
    local label="$1" min_a="$2" min_b="$3" max_a="${4:-}"
    local a0 b0 a1 b1 da db
    a0=$(rx_path_a); b0=$(rx_path_b)
    send_flows
    sleep 0.5
    a1=$(rx_path_a); b1=$(rx_path_b)
    da=$((a1 - a0)); db=$((b1 - b0))
    print_info "$label: path A carried $da packets, path B carried $db packets (of $NUM_FLOWS flows)"
    local ok=1
    [ "$da" -ge "$min_a" ] || { print_error "$label: path A carried $da packets, want >= $min_a"; ok=0; }
    [ "$db" -ge "$min_b" ] || { print_error "$label: path B carried $db packets, want >= $min_b"; ok=0; }
    if [ -n "$max_a" ] && [ "$da" -gt "$max_a" ]; then
        print_error "$label: path A carried $da packets, want <= $max_a"
        ok=0
    fi
    if [ "$ok" -eq 1 ]; then
        print_success "$label: PASS"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

echo "=========================================="
echo "SRv6 Headend ECMP Path Group Test"
echo "=========================================="
echo ""

# Phase 1: Linux native single-path baseline
echo "=========================================="
echo "Phase 1: Linux Native SRv6 (Baseline, path A only)"
echo "=========================================="

test_ping_with_counter "$ns_host1" 172.0.2.1 "host1 -> host2 (Linux native T.Encaps via path A)"

print_info "Removing Linux native encap route from $ns_router1..."
ip netns exec "$ns_router1" ip route del 172.0.2.0/24 2>/dev/null || true

echo ""

# Phase 2: Vinbero single-path headend
echo "=========================================="
echo "Phase 2: Vinbero XDP H.Encaps (single path)"
echo "=========================================="

print_info "Starting Vinbero on $ns_router1..."
start_vinbero "$ns_router1" "${VINBERO_CONFIG}" "/tmp/vinbero_ecmp_test.log"
VINBERO_PID=$VINBERO_LAST_PID
wait_vinbero_ready "$ns_router1" "127.0.0.1:8082" 10

# Resolve NDP towards both next hops first: bpf_fib_lookup returns NO_NEIGH
# for unresolved neighbors and the headend would drop the first flows.
print_info "Pre-resolving NDP to both next hops..."
ip netns exec "$ns_router1" ping6 -c 2 -W 2 fc00:12a::2 > /dev/null || true
ip netns exec "$ns_router1" ping6 -c 2 -W 2 fc00:12b::2 > /dev/null || true

print_info "Registering HeadendV4 trigger entry (path A as its segment list)..."
ip netns exec "$ns_router1" ${VINBERO_BIN} -s http://127.0.0.1:8082 hv4 create \
  --trigger-prefix 172.0.2.0/24 --src-addr fc00:1::1 --segments fc00:a::2,fc00:3::3 > /dev/null
print_success "HeadendV4 entry registered"
sleep 1

test_ping_with_counter "$ns_host1" 172.0.2.1 "host1 -> host2 (Vinbero XDP, single path)"
test_ping_with_counter "$ns_host2" 172.0.1.1 "host2 -> host1 (return path)"

echo ""

# Phase 3: ECMP path group
echo "=========================================="
echo "Phase 3: ECMP path group (2 equal-weight paths)"
echo "=========================================="

print_info "Installing ECMP group ${GROUP_ID} and attaching the trigger entry..."
"$ECMPDEMO_BIN" group-put --pid "$VINBERO_PID" --group-id "$GROUP_ID" \
  --from-trigger 172.0.2.0/24 \
  --path "fc00:a::2+fc00:3::3@1" \
  --path "fc00:b::2+fc00:3::3@1"
"$ECMPDEMO_BIN" attach --pid "$VINBERO_PID" --trigger 172.0.2.0/24 --group-id "$GROUP_ID"

test_ping_with_counter "$ns_host1" 172.0.2.1 "host1 -> host2 (via ECMP group)"

# jhash over 100 distinct 5-tuples: each equal-weight path must take a
# substantial share. 15% is far below the binomial mean (50%) but far above
# what a broken constant hash would yield.
assert_spread "flow spread across both paths" 15 15

echo ""

# Phase 4: liveness-driven fast reroute
echo "=========================================="
echo "Phase 4: Fast reroute via the liveness bitmap"
echo "=========================================="

print_info "Marking path 0 (via router2a) down: bitmap 0x2..."
"$ECMPDEMO_BIN" live-set --pid "$VINBERO_PID" --group-id "$GROUP_ID" --bitmap 0x2

# All flows must shift to path B; a small allowance on path A absorbs
# unrelated control traffic (NDP) on the counter.
assert_spread "all flows on surviving path B" 0 80 5
test_ping_with_counter "$ns_host1" 172.0.2.1 "host1 -> host2 (rerouted to path B)"

print_info "Clearing the liveness entry (fail-open: all paths live)..."
"$ECMPDEMO_BIN" live-clear --pid "$VINBERO_PID" --group-id "$GROUP_ID"

assert_spread "spread restored after live-clear" 15 15

print_info "Stopping Vinbero..."
kill $VINBERO_PID 2>/dev/null || true
wait $VINBERO_PID 2>/dev/null || true

echo ""
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo "Passed: $TESTS_PASSED"
echo "Failed: $TESTS_FAILED"
echo ""

if [ $TESTS_FAILED -gt 0 ]; then
    print_error "Some tests failed"
    exit 1
else
    print_success "All tests passed!"
    exit 0
fi
