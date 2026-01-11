#!/bin/bash
# examples/headend-v4/test.sh
# Test H.Encaps (Headend IPv4) with Vinbero XDP

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/test_utils.sh"

check_root

VINBERO_BIN="${SCRIPT_DIR}/../../out/bin/vinbero"
VINBERO_CONFIG="${SCRIPT_DIR}/vinbero_router1.yaml"

# Set namespace prefix (must match setup.sh)
# Note: Linux interface names are limited to 15 chars, so use short prefix "hv4-"
export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-hv4-}"
ns_host1="${TOPO_NS_PREFIX}host1"
ns_host2="${TOPO_NS_PREFIX}host2"
ns_router1="${TOPO_NS_PREFIX}router1"

TESTS_PASSED=0
TESTS_FAILED=0

# Test ping with counter
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
echo "SRv6 H.Encaps (Headend IPv4) Test"
echo "=========================================="
echo ""

# Phase 1: Test with Linux native SRv6
echo "=========================================="
echo "Phase 1: Linux Native SRv6 (Baseline)"
echo "=========================================="

print_info "Linux native T.Encaps is already configured on $ns_router1 (from setup.sh)"

test_ping_with_counter "$ns_host1" 172.0.2.1 "host1 -> host2 (Linux native T.Encaps)"
test_ping_with_counter "$ns_host2" 172.0.1.1 "host2 -> host1 (Linux native T.Encaps)"

print_info "Removing Linux native T.Encaps route from $ns_router1..."
ip netns exec "$ns_router1" ip route del 172.0.2.0/24 2>/dev/null || true

echo ""

# Phase 2: Test with Vinbero XDP H.Encaps
echo "=========================================="
echo "Phase 2: Vinbero XDP H.Encaps"
echo "=========================================="

print_info "Starting Vinbero on $ns_router1..."
ip netns exec "$ns_router1" ${VINBERO_BIN} -c ${VINBERO_CONFIG} > /tmp/vinbero_headend_test.log 2>&1 &
VINBERO_PID=$!
sleep 2

if ! ps -p $VINBERO_PID > /dev/null; then
    print_error "Vinbero failed to start"
    cat /tmp/vinbero_headend_test.log
    exit 1
fi

print_success "Vinbero started (PID: $VINBERO_PID)"

print_info "Registering HeadendV4 entry..."
ip netns exec "$ns_router1" curl -s -X POST http://127.0.0.1:8082/vinbero.v1.Headendv4Service/Headendv4Create \
  -H "Content-Type: application/json" \
  -d '{
    "headendv4s": [
      {
        "trigger_prefix": "172.0.2.0/24",
        "mode": "SRV6_HEADEND_BEHAVIOR_H_ENCAPS",
        "src_addr": "fc00:1::1",
        "dst_addr": "fc00:2::1",
        "segments": ["fc00:2::1", "fc00:3::3"]
      }
    ]
  }' > /dev/null

print_success "HeadendV4 entry registered"

sleep 1

test_ping_with_counter "$ns_host1" 172.0.2.1 "host1 -> host2 (Vinbero XDP H.Encaps)"
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
