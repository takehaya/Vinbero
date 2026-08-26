#!/bin/bash
# examples/end-replace/test.sh
# Test End with REPLACE-CSID: a four-hop C-SID walk across two Vinbero nodes

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/test_utils.sh"

check_root

VINBEROD_BIN="${SCRIPT_DIR}/../../out/bin/vinberod"
VINBERO_BIN="${SCRIPT_DIR}/../../out/bin/vinbero"

export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-repl-}"
ns_host1="${TOPO_NS_PREFIX}host1"
ns_host2="${TOPO_NS_PREFIX}host2"
ns_router2="${TOPO_NS_PREFIX}router2"
ns_router3="${TOPO_NS_PREFIX}router3"
veth_rt2_rt3="${TOPO_NS_PREFIX}rt2rt3"

TESTS_PASSED=0
TESTS_FAILED=0
VINBERO_PID_R2=""
VINBERO_PID_R3=""

cleanup() {
    # Guard against PID reuse: only kill if the PID is still our vinberod.
    for pid in "$VINBERO_PID_R2" "$VINBERO_PID_R3"; do
        if [ -n "$pid" ] && [ "$(ps -o comm= -p "$pid" 2>/dev/null)" = "vinberod" ]; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
}
trap cleanup EXIT

echo "=========================================="
echo "SRv6 REPLACE-CSID Operation Test"
echo "=========================================="
echo ""
echo "No Linux oracle phase: seg6local implements only the NEXT-C-SID"
echo "flavor, so there is nothing native to compare REPLACE-CSID against."
echo ""

print_info "Starting Vinbero on $ns_router2 and $ns_router3..."
start_vinbero "$ns_router2" "${SCRIPT_DIR}/vinbero_router2.yaml" "/tmp/vinbero_end_replace_r2.log"
VINBERO_PID_R2=$VINBERO_LAST_PID
start_vinbero "$ns_router3" "${SCRIPT_DIR}/vinbero_router3.yaml" "/tmp/vinbero_end_replace_r3.log"
VINBERO_PID_R3=$VINBERO_LAST_PID
wait_vinbero_ready "$ns_router2" "127.0.0.1:8095" 10
wait_vinbero_ready "$ns_router3" "127.0.0.1:8096" 10

print_info "Registering the End(REP) C-SIDs (block 48, csid 32)..."
ip netns exec "$ns_router2" ${VINBERO_BIN} -s http://127.0.0.1:8095 \
  sid create --trigger-prefix fd00:aabb:ccdd:b2b2:1::/80 --action END_REPLACE --usid-block-len 48
ip netns exec "$ns_router2" ${VINBERO_BIN} -s http://127.0.0.1:8095 \
  sid create --trigger-prefix fd00:aabb:ccdd:b2b2:2::/80 --action END_REPLACE --usid-block-len 48
ip netns exec "$ns_router3" ${VINBERO_BIN} -s http://127.0.0.1:8096 \
  sid create --trigger-prefix fd00:aabb:ccdd:b3b3:1::/80 --action END_REPLACE --usid-block-len 48
print_success "SID functions registered"

sleep 1

# The forward ping only arrives if all four walk steps work: the
# container cross at r2 (Index 0 -> 3), the in-container replacements at
# r3 and r2, and the terminal End.DX4 match on the /80 at r3. Delivery
# alone cannot prove the middle hops (a broken index that jumps straight
# to the terminal C-SID would still ping), so the r2 -> r3 link's TX
# counter pins the ping-pong: each echo request crosses it twice.
tx_before=$(ip netns exec "$ns_router2" cat /sys/class/net/${veth_rt2_rt3}/statistics/tx_packets)
test_ping_with_counter "$ns_host1" 172.0.2.1 "host1 -> host2 (REPLACE-CSID walk r2->r3->r2->r3)"
tx_after=$(ip netns exec "$ns_router2" cat /sys/class/net/${veth_rt2_rt3}/statistics/tx_packets)
tx_delta=$((tx_after - tx_before))
if [ "$tx_delta" -ge 6 ]; then
    print_success "walk traversal: PASS (r2->r3 tx +${tx_delta}, 2 crossings x 3 echoes)"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    print_error "walk traversal: FAIL (r2->r3 tx +${tx_delta}, want >= 6: the b2b2:2 step was skipped)"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

test_ping_with_counter "$ns_host2" 172.0.1.1 "host2 -> host1 (return, native)"

print_info "Stopping Vinbero..."
cleanup
VINBERO_PID_R2=""
VINBERO_PID_R3=""

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
