#!/bin/bash
# examples/end-un/test.sh
# Test uN (NEXT-C-SID, RFC 9800) against the Linux seg6local next-csid oracle

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
    # Guard against PID reuse: only kill if the PID is still our vinberod.
    if [ -n "$VINBERO_PID" ] && [ "$(ps -o comm= -p "$VINBERO_PID" 2>/dev/null)" = "vinberod" ]; then
        kill "$VINBERO_PID" 2>/dev/null || true
        wait "$VINBERO_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "=========================================="
echo "SRv6 uN (NEXT-C-SID) Operation Test"
echo "=========================================="
echo ""

# Phase 1: Linux seg6local next-csid as the oracle. Both directions traverse
# the same uN on router2, so a broken shift fails both pings.
echo "=========================================="
echo "Phase 1: Linux Native uN (next-csid)"
echo "=========================================="

print_info "Linux native uN is already enabled on $ns_router2 (from setup.sh)"

test_ping_with_counter "$ns_host1" 172.0.2.1 "host1 -> host2 (Linux native uN)"
test_ping_with_counter "$ns_host2" 172.0.1.1 "host2 -> host1 (Linux native uN)"

print_info "Removing Linux native uN from $ns_router2..."
# The oracle route must actually go away: if it lingered, the kernel would
# keep forwarding whenever Vinbero returns XDP_PASS and phase 2 would pass
# vacuously. Deletion failure aborts the test (set -e).
ip netns exec "$ns_router2" ip -6 route del local fd00:aaaa:b002::/48

echo ""

# Phase 2: the same uN served by Vinbero XDP
echo "=========================================="
echo "Phase 2: Vinbero XDP uN (END_UN)"
echo "=========================================="

print_info "Starting Vinbero on $ns_router2..."
start_vinbero "$ns_router2" "${VINBERO_CONFIG}" "/tmp/vinbero_end_un_test.log"
VINBERO_PID=$VINBERO_LAST_PID
wait_vinbero_ready "$ns_router2" "127.0.0.1:8087" 10

print_info "Registering the uN SID (locator-prefix entry, /48)..."
ip netns exec "$ns_router2" ${VINBERO_BIN} -s http://127.0.0.1:8087 \
  sid create --trigger-prefix fd00:aaaa:b002::/48 --action END_UN
print_success "SID function registered"

# The XDP shift path is fail-closed on unresolved neighbors, so re-warm NDP
# right before the traffic (kernel entries may have gone stale).
ip netns exec "$ns_router2" ping -6 -c 1 -W 2 fc00:23::1 > /dev/null 2>&1 || true
ip netns exec "$ns_router2" ping -6 -c 1 -W 2 fc00:12::1 > /dev/null 2>&1 || true
sleep 1

test_ping_with_counter "$ns_host1" 172.0.2.1 "host1 -> host2 (Vinbero XDP uN)"
test_ping_with_counter "$ns_host2" 172.0.1.1 "host2 -> host1 (Vinbero XDP uN)"

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
