#!/bin/bash
# examples/end-dx6/test.sh
# Test End.DX6 with Vinbero XDP

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/test_utils.sh"

check_root

VINBEROD_BIN="${SCRIPT_DIR}/../../out/bin/vinberod"
VINBERO_BIN="${SCRIPT_DIR}/../../out/bin/vinbero"
VINBERO_CONFIG="${SCRIPT_DIR}/vinbero_router3.yaml"

# Set namespace prefix (must match setup.sh)
export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-dx6-}"
ns_host1="${TOPO_NS_PREFIX}host1"
ns_host2="${TOPO_NS_PREFIX}host2"
ns_router3="${TOPO_NS_PREFIX}router3"

TESTS_PASSED=0
TESTS_FAILED=0

# Test ping6 with counter
test_ping6_with_counter() {
    local ns=$1
    local target=$2
    local desc=$3

    print_info "Testing: $desc"
    if ip netns exec $ns ping -6 -c 3 -W 2 $target > /dev/null 2>&1; then
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
echo "SRv6 End.DX6 Test"
echo "=========================================="
echo ""

# Phase 1: Test with Linux native SRv6
echo "=========================================="
echo "Phase 1: Linux Native SRv6 (Baseline)"
echo "=========================================="

print_info "Linux native End.DX6 is already configured on $ns_router3 (from setup.sh)"

test_ping6_with_counter "$ns_host1" 2001:2::1 "host1 -> host2 (Linux native End.DX6)"
test_ping6_with_counter "$ns_host2" 2001:1::1 "host2 -> host1 (Linux native)"

print_info "Removing Linux native End.DX6 route from $ns_router3..."
ip netns exec "$ns_router3" ip -6 route del local fc00:3::3/128 2>/dev/null || true

echo ""

# Phase 2: Test with Vinbero XDP End.DX6
echo "=========================================="
echo "Phase 2: Vinbero XDP End.DX6"
echo "=========================================="

print_info "Starting Vinbero on $ns_router3..."
start_vinbero "$ns_router3" "${VINBERO_CONFIG}" "/tmp/vinbero_end_dx6_test.log"
VINBERO_PID=$VINBERO_LAST_PID
wait_vinbero_ready "$ns_router3" "127.0.0.1:8082" 10

print_info "Registering SidFunction (End.DX6) entry..."
ip netns exec "$ns_router3" ${VINBERO_BIN} -s http://127.0.0.1:8082 sid create \
  --trigger-prefix fc00:3::3/128 --action END_DX6 > /dev/null

print_success "SidFunction (End.DX6) entry registered"

sleep 1

test_ping6_with_counter "$ns_host1" 2001:2::1 "host1 -> host2 (Vinbero XDP End.DX6)"
test_ping6_with_counter "$ns_host2" 2001:1::1 "host2 -> host1 (Vinbero XDP)"

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
