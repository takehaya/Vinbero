#!/bin/bash
# examples/end-un-usd/test.sh
# Test uN + USD: outer decap at the end of a no-SRH uSID container

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/test_utils.sh"

check_root

VINBEROD_BIN="${SCRIPT_DIR}/../../out/bin/vinberod"
VINBERO_BIN="${SCRIPT_DIR}/../../out/bin/vinbero"
VINBERO_CONFIG="${SCRIPT_DIR}/vinbero_router3.yaml"

export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-unusd-}"
ns_host1="${TOPO_NS_PREFIX}host1"
ns_host2="${TOPO_NS_PREFIX}host2"
ns_router3="${TOPO_NS_PREFIX}router3"

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
echo "SRv6 uN + USD Operation Test"
echo "=========================================="
echo ""
echo "No Linux oracle phase: the kernel's seg6local End rejects"
echo "\"flavors usd\", so there is nothing native to compare against."
echo ""

print_info "Starting Vinbero on $ns_router3..."
start_vinbero "$ns_router3" "${VINBERO_CONFIG}" "/tmp/vinbero_end_un_usd_test.log"
VINBERO_PID=$VINBERO_LAST_PID
wait_vinbero_ready "$ns_router3" "127.0.0.1:8094" 10

print_info "Registering the uN SID with the USD flavor..."
ip netns exec "$ns_router3" ${VINBERO_BIN} -s http://127.0.0.1:8094 \
  sid create --trigger-prefix fd00:aaaa:b003::/48 --action END_UN --flavor USD
print_success "SID function registered"

sleep 1

# Pre-resolve ARP for the post-decap IPv4 hop.
ip netns exec "$ns_router3" ping -c 1 -W 1 172.0.2.1 > /dev/null 2>&1 || true

# The forward packet arrives at r3 as a bare uN SID with no SRH and an
# IPIP payload. Delivery proves the USD branch decapped and forwarded the
# inner IPv4; without USD the encapsulated packet is handed to the kernel
# and never reaches host2.
test_ping_with_counter "$ns_host1" 172.0.2.1 "host1 -> host2 (uN USD decap, no SRH)"
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
