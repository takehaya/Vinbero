#!/bin/bash
# examples/end-dt4/test.sh
# Test End.DT4 with Vinbero XDP (VRF-aware FIB lookup)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/test_utils.sh"

check_root

VINBEROD_BIN="${SCRIPT_DIR}/../../out/bin/vinberod"
VINBERO_BIN="${SCRIPT_DIR}/../../out/bin/vinbero"
VINBERO_CONFIG="${SCRIPT_DIR}/vinbero_router3.yaml"

export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-dt4-}"
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

# dt4_runs: how many packets router3's End.DT4 slot (endpoint slot 8) has
# processed (needs settings.enable_stats).
dt4_runs() {
    ip netns exec "$ns_router3" ${VINBERO_BIN} -s http://127.0.0.1:8082 --json \
        stats slot show --type endpoint --all | jq -er '.[] | select(.slot == 8) | (.packets // 0)'
}

# check_dt4_runs <description> <test-op> <count> <command...>: runs the
# command and tallies whether the End.DT4 runs it caused satisfy
# "delta <test-op> count".
check_dt4_runs() {
    local desc=$1 op=$2 want=$3; shift 3
    print_info "Testing: $desc"
    local before after
    before=$(dt4_runs)
    "$@" > /dev/null 2>&1 || true
    after=$(dt4_runs)
    if [ "$((after - before))" "$op" "$want" ]; then
        print_success "$desc: PASS ($((after - before)) runs)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        print_error "$desc: FAIL ($((after - before)) runs)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

echo "=========================================="
echo "SRv6 End.DT4 (VRF) Test"
echo "=========================================="
echo ""

# Phase 1: Test with Linux native SRv6
echo "=========================================="
echo "Phase 1: Linux Native SRv6 (Baseline)"
echo "=========================================="

print_info "Linux native End.DT4 vrftable 100 is configured on $ns_router3"

test_ping_with_counter "$ns_host1" 172.0.2.1 "host1 -> host2 (Linux native End.DT4 VRF)"
test_ping_with_counter "$ns_host2" 172.0.1.1 "host2 -> host1 (Linux native)"

print_info "Removing Linux native End.DT4 route from $ns_router3..."
ip netns exec "$ns_router3" ip -6 route del local fc00:3::3/128 2>/dev/null || true

echo ""

# Phase 2: Test with Vinbero XDP End.DT4
echo "=========================================="
echo "Phase 2: Vinbero XDP End.DT4 (VRF)"
echo "=========================================="

print_info "Starting Vinbero on $ns_router3..."
start_vinbero "$ns_router3" "${VINBERO_CONFIG}" "/tmp/vinbero_end_dt4_test.log"
VINBERO_PID=$VINBERO_LAST_PID
wait_vinbero_ready "$ns_router3" "127.0.0.1:8082" 10

print_info "Registering SidFunction (End.DT4) entry with vrf_name=vrf100..."
ip netns exec "$ns_router3" ${VINBERO_BIN} -s http://127.0.0.1:8082 sid create \
  --trigger-prefix fc00:3::3/128 --action END_DT4 --vrf-name vrf100 > /dev/null

print_success "SidFunction (End.DT4) entry registered"

sleep 1

# Pre-resolve NDP between routers (required for bpf_fib_lookup)
print_info "Pre-resolving NDP..."
ip netns exec "$ns_router3" ping6 -c 1 -W 1 fc00:23::2 > /dev/null 2>&1 || true

test_ping_with_counter "$ns_host1" 172.0.2.1 "host1 -> host2 (Vinbero XDP End.DT4 VRF)"
test_ping_with_counter "$ns_host2" 172.0.1.1 "host2 -> host1 (return path, native baseline)"

echo ""

# Phase 3: a tenant AC cannot address the SID
echo "=========================================="
echo "Phase 3: SID from a tenant AC"
echo "=========================================="

# host2 encapsulates its traffic to host1 straight to router3's End.DT4 SID,
# the way a tenant host would try to reach a SID directly. The outer packet
# enters router3 on the host-facing port.
print_info "Steering host2 -> host1 straight to the SID fc00:3::3..."
rt3h2_mac=$(ip netns exec "$ns_router3" cat "/sys/class/net/${TOPO_NS_PREFIX}rt3h2/address")
ip netns exec "$ns_host2" ip -6 addr add fc00:99::2/128 dev lo
ip netns exec "$ns_host2" ip -6 route add fc00:3::3/128 dev "${TOPO_NS_PREFIX}h2rt3"
ip netns exec "$ns_host2" ip -6 neigh replace fc00:3::3 lladdr "$rt3h2_mac" dev "${TOPO_NS_PREFIX}h2rt3" nud permanent
ip netns exec "$ns_host2" ip route add 172.0.1.1/32 encap seg6 mode encap segs fc00:3::3 dev "${TOPO_NS_PREFIX}h2rt3"

# Without an AC the port is in the global VRF, and End.DT4 decapsulates
# host2's packets. (They go no further: vrf100 reaches host1 through a
# kernel seg6 route, which the XDP FIB lookup does not follow.)
check_dt4_runs "host2 -> SID with the port in the global VRF (End.DT4 runs)" -ge 3 \
  ip netns exec "$ns_host2" ping -c 3 -W 1 172.0.1.1

print_info "Classifying the host-facing port into vrf100 (vbctl vrf ac-add)..."
ip netns exec "$ns_router3" ${VINBERO_BIN} -s http://127.0.0.1:8082 vrf ac-add \
  --vrf vrf100 --interface "${TOPO_NS_PREFIX}rt3h2" > /dev/null

# From a tenant AC the SID table is not looked up, so End.DT4 never runs.
check_dt4_runs "host2 -> SID from the vrf100 AC (End.DT4 does not run)" -eq 0 \
  ip netns exec "$ns_host2" ping -c 3 -W 1 172.0.1.1

ip netns exec "$ns_host2" ip route del 172.0.1.1/32
# The uplink has no AC, so it stays in the global VRF and keeps reaching the SID.
test_ping_with_counter "$ns_host1" 172.0.2.1 "host1 -> host2 with the AC (SID from the underlay)"
test_ping_with_counter "$ns_host2" 172.0.1.1 "host2 -> host1 with the AC (ordinary tenant path)"

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
