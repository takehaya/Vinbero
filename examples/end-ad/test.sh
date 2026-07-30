#!/bin/bash
# examples/end-ad/test.sh
# Test End.AD (static proxy) with Vinbero XDP

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/test_utils.sh"

check_root

VINBEROD_BIN="${SCRIPT_DIR}/../../out/bin/vinberod"
VINBERO_BIN="${SCRIPT_DIR}/../../out/bin/vinbero"
VINBERO_CONFIG="${SCRIPT_DIR}/vinbero_router2.yaml"

export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-ad-}"
ns_host1="${TOPO_NS_PREFIX}host1"
ns_host2="${TOPO_NS_PREFIX}host2"
ns_router2="${TOPO_NS_PREFIX}router2"
ns_svc="${TOPO_NS_PREFIX}svc"
veth_rt2_svc="${TOPO_NS_PREFIX}rt2svc"
veth_svc_rt2="${TOPO_NS_PREFIX}svcrt2"

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

svc_rx_packets() {
    ip netns exec "$ns_svc" cat "/sys/class/net/${veth_svc_rt2}/statistics/rx_packets"
}

echo "=========================================="
echo "SRv6 End.AD (static proxy) Test"
echo "=========================================="
echo ""

# Phase 1: baseline without the proxy. Linux has no End.AD, so the proxy
# SID acts as a plain End; this proves the underlay chain and resolves
# the routers' neighbour entries.
echo "=========================================="
echo "Phase 1: Linux Native SRv6 (Baseline, End instead of End.AD)"
echo "=========================================="

test_ping_with_counter "$ns_host1" 172.0.2.1 "host1 -> host2 (baseline, proxy bypassed)"
test_ping_with_counter "$ns_host2" 172.0.1.1 "host2 -> host1 (native return path)"

print_info "Removing the native End baseline from $ns_router2..."
ip netns exec "$ns_router2" ip -6 route del local fc00:2::100/128 2>/dev/null || true

echo ""

# Phase 2: Vinbero XDP End.AD - traffic must now detour through the
# service namespace and come back re-encapsulated.
echo "=========================================="
echo "Phase 2: Vinbero XDP End.AD"
echo "=========================================="

print_info "Starting Vinbero on $ns_router2..."
start_vinbero "$ns_router2" "${VINBERO_CONFIG}" "/tmp/vinbero_end_ad_test.log"
VINBERO_PID=$VINBERO_LAST_PID
wait_vinbero_ready "$ns_router2" "127.0.0.1:8082" 10

svc_ifindex=$(ip netns exec "$ns_router2" cat "/sys/class/net/${veth_rt2_svc}/ifindex")
svc_mac=$(ip netns exec "$ns_svc" cat "/sys/class/net/${veth_svc_rt2}/address")

print_info "Registering SidFunction (End.AD) entry (iface ${svc_ifindex}, service MAC ${svc_mac})..."
ip netns exec "$ns_router2" ${VINBERO_BIN} -s http://127.0.0.1:8082 sid create \
  --trigger-prefix fc00:2::100/128 --action END_AD \
  --inner-type ipv4 \
  --oif "$svc_ifindex" --iface-in "$svc_ifindex" \
  --service-mac "$svc_mac" \
  --hop-limit-margin 2 > /dev/null

print_success "SidFunction (End.AD) entry registered"
sleep 1

rx_before=$(svc_rx_packets)

test_ping_with_counter "$ns_host1" 172.0.2.1 "host1 -> host2 (via End.AD proxy + service)"

rx_after=$(svc_rx_packets)
if [ "$rx_after" -gt "$rx_before" ]; then
    print_success "service namespace saw the decapsulated traffic (rx ${rx_before} -> ${rx_after})"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    print_error "service namespace saw no traffic (rx ${rx_before} -> ${rx_after})"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

print_info "Verifying the return-circuit uniqueness (second SID on the same IFACE-IN must fail)..."
if ip netns exec "$ns_router2" ${VINBERO_BIN} -s http://127.0.0.1:8082 sid create \
  --trigger-prefix fc00:2::101/128 --action END_AD \
  --inner-type ipv4 \
  --oif "$svc_ifindex" --iface-in "$svc_ifindex" \
  --service-mac "$svc_mac" 2>&1 | grep -qi "already bound"; then
    print_success "duplicate IFACE-IN binding rejected"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    print_error "duplicate IFACE-IN binding was not rejected"
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
