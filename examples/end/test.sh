#!/bin/bash
# examples/end/test.sh
# Test 3-router SRv6 topology with Vinbero XDP

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/test_utils.sh"

check_root

VINBERO_BIN="${SCRIPT_DIR}/../../out/bin/vinbero"
VINBERO_CONFIG="${SCRIPT_DIR}/vinbero_router2.yaml"

# Set namespace prefix (must match setup.sh)
# Default: use directory name (e.g., "end" -> "end-")
EXAMPLE_NAME="$(basename "$SCRIPT_DIR")"
export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-${EXAMPLE_NAME}-}"
ns_host1="${TOPO_NS_PREFIX}host1"
ns_host2="${TOPO_NS_PREFIX}host2"
ns_router2="${TOPO_NS_PREFIX}router2"

TESTS_PASSED=0
TESTS_FAILED=0

# Test ping with counter (wrapper around test_utils.sh's test_ping)
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
echo "SRv6 End Operation Test"
echo "=========================================="
echo ""

# Phase 1: Test with Linux native SRv6
echo "=========================================="
echo "Phase 1: Linux Native SRv6"
echo "=========================================="

print_info "Linux native SRv6 is already enabled on $ns_router2 (from setup.sh)"

test_ping_with_counter "$ns_host1" 172.0.2.1 "host1 -> host2 (Linux native)"
test_ping_with_counter "$ns_host2" 172.0.1.1 "host2 -> host1 (Linux native)"

print_info "Removing Linux native SRv6 from $ns_router2..."
ip netns exec "$ns_router2" ip -6 route del local fc00:2::1/128 2>/dev/null || true
ip netns exec "$ns_router2" ip -6 route del local fc00:2::2/128 2>/dev/null || true

echo ""

# Phase 2: Test with Vinbero XDP
echo "=========================================="
echo "Phase 2: Vinbero XDP"
echo "=========================================="

print_info "Starting Vinbero on $ns_router2..."
ip netns exec "$ns_router2" ${VINBERO_BIN} -c ${VINBERO_CONFIG} > /tmp/vinbero_test.log 2>&1 &
VINBERO_PID=$!
sleep 2

if ! ps -p $VINBERO_PID > /dev/null; then
    print_error "Vinbero failed to start"
    cat /tmp/vinbero_test.log
    exit 1
fi

print_success "Vinbero started (PID: $VINBERO_PID)"

print_info "Registering SID functions..."
ip netns exec "$ns_router2" curl -s -X POST http://127.0.0.1:8082/vinbero.v1.SidFunctionService/SidFunctionCreate \
  -H "Content-Type: application/json" \
  -d '{
    "sid_functions": [
      {
        "trigger_prefix": "fc00:2::1/128",
        "action": "SRV6_LOCAL_ACTION_END",
        "flavor": "SRV6_LOCAL_FLAVOR_NONE"
      },
      {
        "trigger_prefix": "fc00:2::2/128",
        "action": "SRV6_LOCAL_ACTION_END",
        "flavor": "SRV6_LOCAL_FLAVOR_NONE"
      }
    ]
  }' > /dev/null

print_success "SID functions registered"

sleep 1

test_ping_with_counter "$ns_host1" 172.0.2.1 "host1 -> host2 (Vinbero XDP)"
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
