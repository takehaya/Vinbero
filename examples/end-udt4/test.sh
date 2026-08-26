#!/bin/bash
# examples/end-udt4/test.sh
# Test uDT4 (End.DT4 as the last uSID) against the Linux seg6local oracle

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/test_utils.sh"

check_root

VINBEROD_BIN="${SCRIPT_DIR}/../../out/bin/vinberod"
VINBERO_BIN="${SCRIPT_DIR}/../../out/bin/vinbero"
VINBERO_CONFIG="${SCRIPT_DIR}/vinbero_router3.yaml"

export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-udt4-}"
ns_host1="${TOPO_NS_PREFIX}host1"
ns_host2="${TOPO_NS_PREFIX}host2"
ns_router1="${TOPO_NS_PREFIX}router1"
ns_router3="${TOPO_NS_PREFIX}router3"
veth_rt1_rt2="${TOPO_NS_PREFIX}rt1rt2"

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
echo "SRv6 uDT4 (NEXT-C-SID terminal) Test"
echo "=========================================="
echo ""

# Phase 1: Linux seg6local (next-csid uN + End.DT4 /128) as the oracle.
# Both routes are installed, so a delivered ping proves the zero-padded
# /128 wins the LPM over the uN /48.
echo "=========================================="
echo "Phase 1: Linux Native uN + End.DT4"
echo "=========================================="

print_info "Linux native routes are already installed on $ns_router3 (from setup.sh)"

test_ping_with_counter "$ns_host1" 172.0.2.1 "host1 -> host2 (Linux native /128 over /48)"
test_ping_with_counter "$ns_host2" 172.0.1.1 "host2 -> host1 (return, native)"

print_info "Removing Linux native routes from $ns_router3..."
# Both oracle routes must actually go away, or phase 2 passes vacuously.
ip netns exec "$ns_router3" ip -6 route del local fd00:aaaa:b003::/48
ip netns exec "$ns_router3" ip -6 route del local fd00:aaaa:b003:d004::/128

echo ""

# Phase 2: the same SIDs served by Vinbero XDP. The uDT4 needs no dedicated
# action: it is the existing END_DT4 registered at the zero-padded /128,
# which wins the LPM over the uN /48 -- that is the property under test.
echo "=========================================="
echo "Phase 2: Vinbero XDP uN + END_DT4 /128"
echo "=========================================="

print_info "Starting Vinbero on $ns_router3..."
start_vinbero "$ns_router3" "${VINBERO_CONFIG}" "/tmp/vinbero_end_udt4_test.log"
VINBERO_PID=$VINBERO_LAST_PID
wait_vinbero_ready "$ns_router3" "127.0.0.1:8092" 10

print_info "Registering the uN /48 and the uDT4 /128..."
ip netns exec "$ns_router3" ${VINBERO_BIN} -s http://127.0.0.1:8092 \
  sid create --trigger-prefix fd00:aaaa:b003::/48 --action END_UN
ip netns exec "$ns_router3" ${VINBERO_BIN} -s http://127.0.0.1:8092 \
  sid create --trigger-prefix fd00:aaaa:b003:d004::/128 --action END_DT4 --vrf-name vrf100
print_success "SID functions registered"

sleep 1

# Pre-resolve NDP/ARP (bpf_fib_lookup needs resolved neighbours)
print_info "Pre-resolving NDP/ARP..."
ip netns exec "$ns_router3" ping6 -c 1 -W 1 fc00:23::2 > /dev/null 2>&1 || true
ip netns exec "$ns_router3" ip vrf exec vrf100 ping -c 1 -W 1 172.0.2.1 > /dev/null 2>&1 || true

test_ping_with_counter "$ns_host1" 172.0.2.1 "host1 -> host2 (Vinbero /128 over /48)"
test_ping_with_counter "$ns_host2" 172.0.1.1 "host2 -> host1 (return, native)"

# The two-uSID container [b003, b003:d004]: the uN shifts once and the
# shifted DA lands on this node's own uDT4 /128. Vinbero re-dispatches that
# inside the XDP loop; Linux seg6local cannot forward a shifted DA back
# into its own local SID, which is why this container only appears in the
# Vinbero phase.
print_info "Switching the headend to the two-uSID container (shift, then own uDT4)..."
ip netns exec "$ns_router1" ip route replace 172.0.2.0/24 encap seg6 mode encap segs fd00:aaaa:b003:b003:d004:: dev "$veth_rt1_rt2"

test_ping_with_counter "$ns_host1" 172.0.2.1 "host1 -> host2 (Vinbero uN shift -> own uDT4)"

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
