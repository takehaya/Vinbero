#!/bin/bash
# examples/end-t/test.sh
# Test End.T with Vinbero XDP (VRF-aware FIB lookup after SRH processing)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/test_utils.sh"

check_root

VINBEROD_BIN="${SCRIPT_DIR}/../../out/bin/vinberod"
VINBERO_BIN="${SCRIPT_DIR}/../../out/bin/vinbero"
VINBERO_CONFIG="${SCRIPT_DIR}/vinbero_router2.yaml"

EXAMPLE_NAME="$(basename "$SCRIPT_DIR")"
export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-${EXAMPLE_NAME}-}"
ns_host1="${TOPO_NS_PREFIX}host1"
ns_host2="${TOPO_NS_PREFIX}host2"
ns_router2="${TOPO_NS_PREFIX}router2"

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
echo "SRv6 End.T (VRF) Test"
echo "=========================================="
echo ""

# Phase 1: Test with Linux native SRv6
echo "=========================================="
echo "Phase 1: Linux Native SRv6 (Baseline)"
echo "=========================================="

print_info "Linux native End.T vrftable 100 is configured on $ns_router2"

test_ping_with_counter "$ns_host1" 172.0.2.1 "host1 -> host2 (Linux native End.T VRF)"
test_ping_with_counter "$ns_host2" 172.0.1.1 "host2 -> host1 (Linux native End.T VRF)"

print_info "Removing Linux native End.T routes from $ns_router2..."
ip netns exec "$ns_router2" ip -6 route del local fc00:2::1/128 2>/dev/null || true
ip netns exec "$ns_router2" ip -6 route del local fc00:2::2/128 2>/dev/null || true

echo ""

# Phase 2: Test with Vinbero XDP End.T
echo "=========================================="
echo "Phase 2: Vinbero XDP End.T (VRF)"
echo "=========================================="

print_info "Starting Vinbero on $ns_router2..."
start_vinbero "$ns_router2" "${VINBERO_CONFIG}" "/tmp/vinbero_end_t_test.log"
VINBERO_PID=$VINBERO_LAST_PID
wait_vinbero_ready "$ns_router2" "127.0.0.1:8082" 10

# Register End.T SID functions with VRF
print_info "Registering SidFunction (End.T) entries with vrf_name=vrf100..."
ip netns exec "$ns_router2" ${VINBERO_BIN} -s http://127.0.0.1:8082 sid create \
  --trigger-prefix fc00:2::1/128 --action END_T --vrf-name vrf100 > /dev/null
ip netns exec "$ns_router2" ${VINBERO_BIN} -s http://127.0.0.1:8082 sid create \
  --trigger-prefix fc00:2::2/128 --action END_T --vrf-name vrf100 > /dev/null

print_success "SidFunction (End.T) entries registered"

sleep 1

# Pre-resolve NDP (required for bpf_fib_lookup)
print_info "Pre-resolving NDP..."
ip netns exec "$ns_router2" ip vrf exec vrf100 ping6 -c 1 -W 1 fc00:23::1 > /dev/null 2>&1 || true
ip netns exec "$ns_router2" ip vrf exec vrf100 ping6 -c 1 -W 1 fc00:12::1 > /dev/null 2>&1 || true

test_ping_with_counter "$ns_host1" 172.0.2.1 "host1 -> host2 (Vinbero XDP End.T VRF)"
test_ping_with_counter "$ns_host2" 172.0.1.1 "host2 -> host1 (Vinbero XDP End.T VRF)"

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
