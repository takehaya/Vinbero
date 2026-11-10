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
start_vinbero "$ns_router1" "${SCRIPT_DIR}/vinbero_router1.yaml" "/tmp/vinbero_gtp4_r1.log"
PIDS="$VINBERO_LAST_PID $PIDS"
wait_vinbero_ready "$ns_router1" "127.0.0.1:8082" 10

print_info "Starting Vinbero on $ns_router3..."
start_vinbero "$ns_router3" "${SCRIPT_DIR}/vinbero_router3.yaml" "/tmp/vinbero_gtp4_r3.log"
PIDS="$VINBERO_LAST_PID $PIDS"
wait_vinbero_ready "$ns_router3" "127.0.0.1:8083" 10

# Phase 2: Register entries
# Note: End.M.GTP4.E uses /56 prefix because Args.Mob.Session (args_offset=7)
# is encoded in bytes 7-15 of the SID, so /128 would not match.
echo ""
echo "=========================================="
echo "Phase 2: Register Entries"
echo "=========================================="

# Forward path: gNB(host1) -> router1(H.M.GTP4.D) -> router2(transit) -> router3(End.M.GTP4.E) -> UPF(host2)
print_info "Forward: H.M.GTP4.D on router1..."
ip netns exec "$ns_router1" ${VINBERO_BIN} -s http://127.0.0.1:8082 hv4 create \
  --trigger-prefix 172.0.2.0/24 --src-addr fc00:1::1 \
  --segments fc00:3::3 --mode H_M_GTP4_D --args-offset 7 > /dev/null

print_info "Forward: End.M.GTP4.E on router3..."
ip netns exec "$ns_router3" ${VINBERO_BIN} -s http://127.0.0.1:8083 sid create \
  --trigger-prefix fc00:3::/56 --action END_M_GTP4_E \
  --gtp-v4-src-addr 172.0.2.2 --args-offset 7 > /dev/null

# Return path: UPF(host2) -> router3(H.M.GTP4.D) -> router2(transit) -> router1(End.M.GTP4.E) -> gNB(host1)
print_info "Return: H.M.GTP4.D on router3..."
ip netns exec "$ns_router3" ${VINBERO_BIN} -s http://127.0.0.1:8083 hv4 create \
  --trigger-prefix 172.0.1.0/24 --src-addr fc00:3::3 \
  --segments fc00:1::1 --mode H_M_GTP4_D --args-offset 7 > /dev/null

print_info "Return: End.M.GTP4.E on router1..."
ip netns exec "$ns_router1" ${VINBERO_BIN} -s http://127.0.0.1:8082 sid create \
  --trigger-prefix fc00:1::/56 --action END_M_GTP4_E \
  --gtp-v4-src-addr 172.0.1.2 --args-offset 7 > /dev/null

print_success "All entries registered"

# Resolve the underlay next hops. The captures below sit on router2's link
# from router1, so router1's entry for fc00:12::2 is the one the tests
# depend on: with it resolved, H.M.GTP4.D redirects the SRv6 packet straight
# out of XDP, which is the path under test. The other two complete the
# underlay in both directions.
print_info "Resolving NDP entries..."
resolve_neigh "$ns_router1" fc00:12::2
resolve_neigh "$ns_router2" fc00:23::1
resolve_neigh "$ns_router3" fc00:23::2

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

# gtp_test <n> <title> <teid> <qfi> <count>: host1 sends <count> GTP-U packets
# to the H.M.GTP4.D trigger, and every one of them must cross router1 ->
# router2 as SRv6 toward the End.M.GTP4.E SID. The capture filters on that
# SID's /56 locator so stray NDP/ICMPv6 on the link is not counted. It is
# listening before the first packet leaves and router1's next hop is
# resolved, so nothing on the path may lose a packet: fewer than <count> is
# a failure.
gtp_test() {
    local n="$1" title="$2" teid="$3" qfi="$4" count="$5"
    local pcap="/tmp/gtp4_test$1.pcap" got
    print_info "Test $n: $title"
    capture_start "$ns_router2" "${TOPO_NS_PREFIX}rt2rt1" "$pcap" -c "$count" \
        'ip6 and dst net fc00:3::/56'
    PIDS="$CAPTURE_PID $PIDS"
    ip netns exec "$ns_host1" python3 "${SCRIPT_DIR}/send_gtpu.py" \
        --outer-dst 172.0.2.100 --teid "$teid" --qfi "$qfi" --count "$count"
    capture_stop "$CAPTURE_PID"
    PIDS="${PIDS/$CAPTURE_PID /}"  # reaped; drop it so the EXIT trap can't kill a recycled PID
    got=$(capture_count "$pcap")
    if [ "$got" -eq "$count" ]; then
        print_success "Test $n PASS: $got of $count SRv6 packets toward End.M.GTP4.E captured"
        tcpdump -r "$pcap" -n 2>/dev/null | head -3
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        print_error "Test $n FAIL: $got of $count SRv6 packets toward End.M.GTP4.E captured"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
    rm -f "$pcap" "$pcap.log"
}

gtp_test 1 "GTP-U with QFI=9 (5G mode)" 0x12345678 9 3
echo ""
gtp_test 2 "GTP-U without QFI (4G/LTE mode)" 0xCAFEBABE 0 3

# Test 3: plain IPv4 to the trigger prefix. 172.0.2.1 lies in the H.M.GTP4.D
# trigger 172.0.2.0/24, but an ICMP echo is not GTP-U, so router1's XDP must
# hand it to the kernel untouched (XDP_PASS). router1 has no IPv4 route to
# 172.0.2.0/24, which is reachable only through the GTP-U/SRv6 conversion,
# so its kernel answers Destination Net Unreachable. That answer is the pass
# condition: an echo reply cannot come back in this topology, and no answer
# at all means XDP dropped or encapsulated the echo.
echo ""
print_info "Test 3: Non-GTP-U IPv4 to the trigger prefix (should XDP_PASS)"
PING_OUT=$(ip netns exec "$ns_host1" ping -c 1 -W 2 172.0.2.1 2>&1 || true)
if echo "$PING_OUT" | grep -q "From 172.0.1.2 .*Net Unreachable"; then
    print_success "Test 3 PASS: router1's kernel answered the plain echo (Net Unreachable)"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    print_error "Test 3 FAIL: no Net Unreachable from router1 for the plain echo"
    echo "$PING_OUT"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

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
