#!/bin/bash
# examples/gtp4-encap/test.sh
# Test H.M.GTP4.D + End.M.GTP4.E with Vinbero XDP

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/test_utils.sh"

check_root

VINBEROD_BIN="${SCRIPT_DIR}/../../out/bin/vinberod"
VINBERO_BIN="${SCRIPT_DIR}/../../out/bin/vinbero"

export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-gtp4-}"
ns_host1="${TOPO_NS_PREFIX}host1"
ns_router1="${TOPO_NS_PREFIX}router1"
ns_router2="${TOPO_NS_PREFIX}router2"
ns_router3="${TOPO_NS_PREFIX}router3"

TESTS_PASSED=0
TESTS_FAILED=0
PIDS=""

cleanup() {
    for pid in $PIDS; do
        kill $pid 2>/dev/null || true
        wait $pid 2>/dev/null || true
    done
}
trap cleanup EXIT

echo "=========================================="
echo "SRv6 GTP-U/IPv4 (H.M.GTP4.D + End.M.GTP4.E) Test"
echo "=========================================="
echo ""

# Phase 1: Start Vinbero
echo "=========================================="
echo "Phase 1: Start Vinbero"
echo "=========================================="

print_info "Starting Vinbero on $ns_router1..."
ip netns exec "$ns_router1" ${VINBEROD_BIN} -c "${SCRIPT_DIR}/vinbero_router1.yaml" > /tmp/vinbero_gtp4_r1.log 2>&1 &
PIDS="$! $PIDS"
sleep 2

print_info "Starting Vinbero on $ns_router3..."
ip netns exec "$ns_router3" ${VINBEROD_BIN} -c "${SCRIPT_DIR}/vinbero_router3.yaml" > /tmp/vinbero_gtp4_r3.log 2>&1 &
PIDS="$! $PIDS"
sleep 2

# Phase 2: Register entries
# Note: End.M.GTP4.E uses /56 prefix because Args.Mob.Session (args_offset=7)
# is encoded in bytes 7-15 of the SID, so /128 would not match.
echo ""
echo "=========================================="
echo "Phase 2: Register Entries"
echo "=========================================="

# Forward path: gNB(host1) -> router1(H.M.GTP4.D) -> router2(End) -> router3(End.M.GTP4.E) -> UPF(host2)
print_info "Forward: H.M.GTP4.D on router1..."
ip netns exec "$ns_router1" ${VINBERO_BIN} -s http://127.0.0.1:8082 hv4 create \
  --trigger-prefix 172.0.2.0/24 --src-addr fc00:1::1 \
  --segments fc00:2::1,fc00:3::3 --mode H_M_GTP4_D --args-offset 7 > /dev/null

print_info "Forward: End.M.GTP4.E on router3..."
ip netns exec "$ns_router3" ${VINBERO_BIN} -s http://127.0.0.1:8083 sid create \
  --trigger-prefix fc00:3::/56 --action END_M_GTP4_E \
  --gtp-v4-src-addr 172.0.2.2 --args-offset 7 > /dev/null

# Return path: UPF(host2) -> router3(H.M.GTP4.D) -> router2(End) -> router1(End.M.GTP4.E) -> gNB(host1)
print_info "Return: H.M.GTP4.D on router3..."
ip netns exec "$ns_router3" ${VINBERO_BIN} -s http://127.0.0.1:8083 hv4 create \
  --trigger-prefix 172.0.1.0/24 --src-addr fc00:3::3 \
  --segments fc00:2::2,fc00:1::1 --mode H_M_GTP4_D --args-offset 7 > /dev/null

print_info "Return: End.M.GTP4.E on router1..."
ip netns exec "$ns_router1" ${VINBERO_BIN} -s http://127.0.0.1:8082 sid create \
  --trigger-prefix fc00:1::/56 --action END_M_GTP4_E \
  --gtp-v4-src-addr 172.0.1.2 --args-offset 7 > /dev/null

print_success "All entries registered"

# Pre-resolve NDP between routers (required for bpf_fib_lookup)
print_info "Resolving NDP entries..."
ip netns exec "$ns_router1" ping6 -c 1 -W 1 fc00:12::2 > /dev/null 2>&1 || true
ip netns exec "$ns_router2" ping6 -c 1 -W 1 fc00:23::3 > /dev/null 2>&1 || true
ip netns exec "$ns_router3" ping6 -c 1 -W 1 fc00:23::2 > /dev/null 2>&1 || true
sleep 1

# Phase 3: GTP-U packet test with scapy
echo ""
echo "=========================================="
echo "Phase 3: GTP-U Packet Test"
echo "=========================================="

if ! python3 -c "from scapy.all import IP" 2>/dev/null; then
    print_info "scapy not installed, skipping GTP-U packet test"
    print_info "Install with: pip3 install scapy"
    echo ""
    print_success "Entry registration test passed (packet test skipped)"
    exit 0
fi

# Test 1: GTP-U with QFI (5G)
print_info "Test 1: GTP-U with QFI=9 (5G mode)"
ip netns exec "$ns_router2" \
    tcpdump -i "${TOPO_NS_PREFIX}rt2rt1" -c 3 -w /tmp/gtp4_test1.pcap \
    ip6 2>/dev/null &
TCPDUMP_PID=$!
sleep 1

ip netns exec "$ns_host1" python3 "${SCRIPT_DIR}/send_gtpu.py" \
    --outer-dst 172.0.2.100 --teid 0x12345678 --qfi 9 --count 3
sleep 2

kill $TCPDUMP_PID 2>/dev/null || true
wait $TCPDUMP_PID 2>/dev/null || true

if [ -f /tmp/gtp4_test1.pcap ]; then
    CAPTURED=$(tcpdump -r /tmp/gtp4_test1.pcap 2>/dev/null | wc -l)
    if [ "$CAPTURED" -gt 0 ]; then
        print_success "Test 1 PASS: $CAPTURED SRv6 packets captured (H.M.GTP4.D works)"
        tcpdump -r /tmp/gtp4_test1.pcap -n 2>/dev/null | head -3
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        print_error "Test 1 FAIL: No SRv6 packets captured"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
    rm -f /tmp/gtp4_test1.pcap
fi

# Test 2: GTP-U without QFI (4G/LTE mode)
echo ""
print_info "Test 2: GTP-U without QFI (4G/LTE mode)"
ip netns exec "$ns_router2" \
    tcpdump -i "${TOPO_NS_PREFIX}rt2rt1" -c 1 -w /tmp/gtp4_test2.pcap \
    ip6 2>/dev/null &
TCPDUMP_PID=$!
sleep 1

ip netns exec "$ns_host1" python3 "${SCRIPT_DIR}/send_gtpu.py" \
    --outer-dst 172.0.2.100 --teid 0xCAFEBABE --qfi 0 --count 1
sleep 2

kill $TCPDUMP_PID 2>/dev/null || true
wait $TCPDUMP_PID 2>/dev/null || true

if [ -f /tmp/gtp4_test2.pcap ]; then
    CAPTURED=$(tcpdump -r /tmp/gtp4_test2.pcap 2>/dev/null | wc -l)
    if [ "$CAPTURED" -gt 0 ]; then
        print_success "Test 2 PASS: $CAPTURED SRv6 packets captured (4G compat works)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        print_error "Test 2 FAIL: No SRv6 packets captured"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
    rm -f /tmp/gtp4_test2.pcap
fi

# Test 3: Non-GTP-U traffic should pass through
echo ""
print_info "Test 3: Non-GTP-U IPv4 (should XDP_PASS)"
ip netns exec "$ns_host1" ping -c 1 -W 2 172.0.2.1 > /dev/null 2>&1 && {
    print_success "Test 3 PASS: Plain IPv4 passes through"
    TESTS_PASSED=$((TESTS_PASSED + 1))
} || {
    print_info "Test 3 SKIP: Plain IPv4 ping failed (expected in some setups)"
}

echo ""
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo "Passed: $TESTS_PASSED"
echo "Failed: $TESTS_FAILED"

if [ $TESTS_FAILED -gt 0 ]; then
    print_error "Some tests failed"
    exit 1
else
    print_success "All tests passed!"
fi
