#!/bin/bash
# examples/end-dt4/test.sh
# Test End.DT4 with Vinbero XDP (VRF-aware FIB lookup)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/test_utils.sh"

check_root

VINBEROD_BIN="${SCRIPT_DIR}/../../out/bin/vinberod"
VINBERO_BIN="${SCRIPT_DIR}/../../out/bin/vinbero"
VINBERO_CONFIG="${SCRIPT_DIR}/vinbero_router3.yaml"

export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-dt4-}"
ns_host1="${TOPO_NS_PREFIX}host1"
ns_host2="${TOPO_NS_PREFIX}host2"
ns_router3="${TOPO_NS_PREFIX}router3"

TESTS_PASSED=0
TESTS_FAILED=0
VINBERO_PID=""

cleanup() {
    if [ -n "$VINBERO_PID" ] && ps -p "$VINBERO_PID" > /dev/null 2>&1; then
        kill "$VINBERO_PID" 2>/dev/null || true
        wait "$VINBERO_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

test_ping_with_counter() {
    local ns=$1
    local target=$2
    local desc=$3

    print_info "Testing: $desc"
    if ip netns exec $ns ping -c 3 -W 2 $target > /dev/null 2>&1; then
        print_success "$desc: PASS"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        print_error "$desc: FAIL"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

echo "=========================================="
echo "SRv6 End.DT4 (VRF) Test"
echo "=========================================="
echo ""

# Phase 1: Test with Linux native SRv6
echo "=========================================="
echo "Phase 1: Linux Native SRv6 (Baseline)"
echo "=========================================="

print_info "Linux native End.DT4 vrftable 100 is configured on $ns_router3"

test_ping_with_counter "$ns_host1" 172.0.2.1 "host1 -> host2 (Linux native End.DT4 VRF)"
test_ping_with_counter "$ns_host2" 172.0.1.1 "host2 -> host1 (Linux native)"

print_info "Removing Linux native End.DT4 route from $ns_router3..."
ip netns exec "$ns_router3" ip -6 route del local fc00:3::3/128 2>/dev/null || true

echo ""

# Phase 2: Test with Vinbero XDP End.DT4
echo "=========================================="
echo "Phase 2: Vinbero XDP End.DT4 (VRF)"
echo "=========================================="

print_info "Starting Vinbero on $ns_router3..."
start_vinbero "$ns_router3" "${VINBERO_CONFIG}" "/tmp/vinbero_end_dt4_test.log"
VINBERO_PID=$VINBERO_LAST_PID
wait_vinbero_ready "$ns_router3" "127.0.0.1:8082" 10

print_info "Registering SidFunction (End.DT4) entry with vrf_name=vrf100..."
ip netns exec "$ns_router3" ${VINBERO_BIN} -s http://127.0.0.1:8082 sid create \
  --trigger-prefix fc00:3::3/128 --action END_DT4 --vrf-name vrf100 > /dev/null

print_success "SidFunction (End.DT4) entry registered"

sleep 1

# Pre-resolve NDP between routers (required for bpf_fib_lookup)
print_info "Pre-resolving NDP..."
ip netns exec "$ns_router3" ping6 -c 1 -W 1 fc00:23::2 > /dev/null 2>&1 || true

test_ping_with_counter "$ns_host1" 172.0.2.1 "host1 -> host2 (Vinbero XDP End.DT4 VRF)"
test_ping_with_counter "$ns_host2" 172.0.1.1 "host2 -> host1 (Vinbero XDP)"

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
