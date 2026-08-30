#!/bin/bash
# examples/end-ua/test.sh
# Test uA (NEXT-C-SID, RFC 9800) against the Linux seg6local next-csid oracle

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
echo "SRv6 uA (NEXT-C-SID) Operation Test"
echo "=========================================="
echo ""

# Phase 1: Linux seg6local next-csid as the oracle. Each direction traverses
# its own uA on router2, so a broken shift or a wrong adjacency fails the
# corresponding ping.
echo "=========================================="
echo "Phase 1: Linux Native uA (End.X next-csid)"
echo "=========================================="

print_info "Linux native uA is already enabled on $ns_router2 (from setup.sh)"

test_ping_with_counter "$ns_host1" 172.0.2.1 "host1 -> host2 (Linux native uA)"
test_ping_with_counter "$ns_host2" 172.0.1.1 "host2 -> host1 (Linux native uA)"

print_info "Removing Linux native uA from $ns_router2..."
# The oracle routes must actually go away: if one lingered, the kernel would
# keep forwarding whenever Vinbero returns XDP_PASS and phase 2 would pass
# vacuously. Deletion failure aborts the test (set -e).
ip netns exec "$ns_router2" ip -6 route del local fd00:aaaa:b002:a003::/64
ip netns exec "$ns_router2" ip -6 route del local fd00:aaaa:b002:a001::/64

echo ""

# Phase 2: the same uA SIDs served by Vinbero XDP
echo "=========================================="
echo "Phase 2: Vinbero XDP uA (END_UA)"
echo "=========================================="

print_info "Starting Vinbero on $ns_router2..."
start_vinbero "$ns_router2" "${VINBERO_CONFIG}" "/tmp/vinbero_end_ua_test.log"
VINBERO_PID=$VINBERO_LAST_PID
wait_vinbero_ready "$ns_router2" "127.0.0.1:8082" 10

print_info "Registering the uA SIDs (/64 each, one per adjacency)..."
ip netns exec "$ns_router2" ${VINBERO_BIN} -s http://127.0.0.1:8082 \
  sid create --trigger-prefix fd00:aaaa:b002:a003::/64 --action END_UA --nexthop fc00:23::1
ip netns exec "$ns_router2" ${VINBERO_BIN} -s http://127.0.0.1:8082 \
  sid create --trigger-prefix fd00:aaaa:b002:a001::/64 --action END_UA --nexthop fc00:12::1
print_success "SID functions registered"

# uA forwards over its configured adjacency, so it stays fail-closed when
# bpf_fib_lookup answers NO_NEIGH: handing the packet up would let the
# kernel route it by the DA instead, which is a different next hop. The
# neighbours therefore have to be resolved before the traffic, exactly as
# classic End.X requires.
ip netns exec "$ns_router2" ping -6 -c 3 -W 2 fc00:23::1 > /dev/null 2>&1 ||
    print_info "NDP warm-up towards fc00:23::1 failed; the fail-closed uA path will drop"
ip netns exec "$ns_router2" ping -6 -c 3 -W 2 fc00:12::1 > /dev/null 2>&1 ||
    print_info "NDP warm-up towards fc00:12::1 failed; the fail-closed uA path will drop"
sleep 1

# Both directions leave router2 over the adjacency named by the uA SID, not
# by a FIB lookup on the shifted DA: router2 has no route to the terminal
# SIDs at all, so a uA that ignored its nexthop would drop the traffic.
test_ping_with_counter "$ns_host1" 172.0.2.1 "host1 -> host2 (Vinbero XDP uA)"
test_ping_with_counter "$ns_host2" 172.0.1.1 "host2 -> host1 (Vinbero XDP uA)"

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
