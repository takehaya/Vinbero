#!/bin/bash
# examples/end-lbs/test.sh
# Test End.LBS: the C-SID sequence crosses a locator-block boundary at r2

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/test_utils.sh"

check_root

VINBEROD_BIN="${SCRIPT_DIR}/../../out/bin/vinberod"
VINBERO_BIN="${SCRIPT_DIR}/../../out/bin/vinbero"
VINBERO_CONFIG="${SCRIPT_DIR}/vinbero_router2.yaml"

export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-lbs-}"
ns_host1="${TOPO_NS_PREFIX}host1"
ns_host2="${TOPO_NS_PREFIX}host2"
ns_router2="${TOPO_NS_PREFIX}router2"

TESTS_PASSED=0
TESTS_FAILED=0
VINBERO_PID=""

cleanup() {
    # Guard against PID reuse: only kill if the PID is still our vinberod.
    if [ -n "$VINBERO_PID" ] && [ "$(ps -o comm= -p "$VINBERO_PID" 2>/dev/null)" = "vinberod" ]; then
        kill "$VINBERO_PID" 2>/dev/null || true
        wait "$VINBERO_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "=========================================="
echo "SRv6 End.LBS Operation Test"
echo "=========================================="
echo ""
echo "No Linux oracle phase: seg6local implements neither End.LBS nor the"
echo "compressed-SID flavors it builds on."
echo ""

print_info "Starting Vinbero on $ns_router2..."
start_vinbero "$ns_router2" "${VINBERO_CONFIG}" "/tmp/vinbero_end_lbs_test.log"
VINBERO_PID=$VINBERO_LAST_PID
wait_vinbero_ready "$ns_router2" "127.0.0.1:8097" 10

print_info "Registering the End.LBS SID (target block fd77:7777:7777::/48)..."
ip netns exec "$ns_router2" ${VINBERO_BIN} -s http://127.0.0.1:8097 \
  sid create --trigger-prefix fd00:aaaa:b002::/48 --action END_LBS \
  --target-block fd77:7777:7777::/48
print_success "SID function registered"

sleep 1
ip netns exec "$ns_router2" ping6 -c 1 -W 1 fc00:23::1 > /dev/null 2>&1 || true

# Block A is blackholed past r2, so this ping is only delivered when the
# argument was re-homed onto block B (a plain uN shift would produce a
# block-A DA and die in the blackhole).
test_ping_with_counter "$ns_host1" 172.0.2.1 "host1 -> host2 (block A in, End.LBS swap, block B out)"
test_ping_with_counter "$ns_host2" 172.0.1.1 "host2 -> host1 (return, native)"

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
