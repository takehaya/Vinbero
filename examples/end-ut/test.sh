#!/bin/bash
# examples/end-ut/test.sh
# Test uT (End.T with NEXT-C-SID): shift-and-forward bound to a VRF table

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/test_utils.sh"

check_root

VINBEROD_BIN="${SCRIPT_DIR}/../../out/bin/vinberod"
VINBERO_BIN="${SCRIPT_DIR}/../../out/bin/vinbero"
VINBERO_CONFIG="${SCRIPT_DIR}/vinbero_router2.yaml"

export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-ut-}"
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
echo "SRv6 uT (NEXT-C-SID) Operation Test"
echo "=========================================="
echo ""
echo "No Linux oracle phase: seg6local's next-csid flavor covers End and"
echo "End.X only, so there is nothing native to compare uT against."
echo ""

print_info "Starting Vinbero on $ns_router2..."
start_vinbero "$ns_router2" "${VINBERO_CONFIG}" "/tmp/vinbero_end_ut_test.log"
VINBERO_PID=$VINBERO_LAST_PID
wait_vinbero_ready "$ns_router2" "127.0.0.1:8093" 10

print_info "Registering the uT SID (locator-prefix entry, /48, vrf100)..."
ip netns exec "$ns_router2" ${VINBERO_BIN} -s http://127.0.0.1:8093 \
  sid create --trigger-prefix fd00:aaaa:b002::/48 --action END_UT --vrf-name vrf100
print_success "SID function registered"

sleep 1

# Pre-resolve NDP again right before the traffic: uT is fail-closed on
# NO_NEIGH (the kernel cannot repeat a VRF-scoped lookup), so a cold
# neighbour table would black-hole the first pings.
ip netns exec "$ns_router2" ping6 -c 1 -W 1 fc00:23::1 > /dev/null 2>&1 || true

# The main table blackholes fd00:aaaa:b003::/48 (setup.sh), so this ping
# is only delivered if the shift-and-forward ran in table 100: End.T
# semantics, not plain uN.
test_ping_with_counter "$ns_host1" 172.0.2.1 "host1 -> host2 (uT shift via vrf100, no SRH)"
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
