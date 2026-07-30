#!/bin/bash
# examples/end-an/test.sh
# Test End.AN (SR-aware native) with Vinbero XDP

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/test_utils.sh"

check_root

VINBEROD_BIN="${SCRIPT_DIR}/../../out/bin/vinberod"
VINBERO_BIN="${SCRIPT_DIR}/../../out/bin/vinbero"
VINBERO_CONFIG="${SCRIPT_DIR}/vinbero_router2.yaml"

export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-an-}"
ns_host1="${TOPO_NS_PREFIX}host1"
ns_host2="${TOPO_NS_PREFIX}host2"
ns_router2="${TOPO_NS_PREFIX}router2"

TESTS_PASSED=0
TESTS_FAILED=0
VINBERO_PID=""

cleanup() {
    if [ -n "$VINBERO_PID" ] && [ "$(ps -o comm= -p "$VINBERO_PID" 2>/dev/null)" = "vinberod" ]; then
        kill "$VINBERO_PID" 2>/dev/null || true
        wait "$VINBERO_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "=========================================="
echo "SRv6 End.AN (SR-aware native) Test"
echo "=========================================="
echo ""

# Phase 1: baseline without the proxy. Linux has no End.AN, so the proxy
# SID acts as a plain End; this proves the underlay chain and resolves
# the routers' neighbour entries.
echo "=========================================="
echo "Phase 1: Linux Native SRv6 (Baseline, End instead of End.AN)"
echo "=========================================="

test_ping_with_counter "$ns_host1" 172.0.2.1 "host1 -> host2 (baseline, proxy bypassed)"
test_ping_with_counter "$ns_host2" 172.0.1.1 "host2 -> host1 (native return path)"

print_info "Removing the native End baseline from $ns_router2..."
ip netns exec "$ns_router2" ip -6 route del local fc00:2::200/128 2>/dev/null || true

echo ""

# Phase 2: Vinbero XDP End.AN - traffic must now detour through the
# service namespace and come back re-encapsulated.
echo "=========================================="
echo "Phase 2: Vinbero XDP End.AN"
echo "=========================================="

print_info "Starting Vinbero on $ns_router2..."
start_vinbero "$ns_router2" "${VINBERO_CONFIG}" "/tmp/vinbero_end_an_test.log"
VINBERO_PID=$VINBERO_LAST_PID
wait_vinbero_ready "$ns_router2" "127.0.0.1:8082" 10

print_info "Registering SidFunction (End.AN) entry with NF-catalog metadata..."
ip netns exec "$ns_router2" ${VINBERO_BIN} -s http://127.0.0.1:8082 sid create \
  --trigger-prefix fc00:2::200/128 --action END_AN \
  --service-name demo-fw > /dev/null

print_success "SidFunction (End.AN) entry registered"
sleep 1

test_ping_with_counter "$ns_host1" 172.0.2.1 "host1 -> host2 (via Vinbero End.AN)"

print_info "Verifying the NF-catalog metadata round trip..."
if ip netns exec "$ns_router2" ${VINBERO_BIN} -s http://127.0.0.1:8082 sid get \
  --trigger-prefix fc00:2::200/128 2>/dev/null | grep -q "demo-fw"; then
    print_success "service_name is visible via SidFunctionGet"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    print_error "service_name did not round trip"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

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
