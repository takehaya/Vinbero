#!/bin/bash
# examples/gtp6-encap/test.sh
# Test End.M.GTP6.D + End.M.GTP6.E with Vinbero XDP

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/test_utils.sh"

check_root

VINBEROD_BIN="${SCRIPT_DIR}/../../out/bin/vinberod"
VINBERO_BIN="${SCRIPT_DIR}/../../out/bin/vinbero"

export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-gtp6-}"
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
echo "SRv6 GTP-U/IPv6 (End.M.GTP6.D + End.M.GTP6.E) Test"
echo "=========================================="
echo ""

# Phase 1: Start Vinbero
print_info "Starting Vinbero on $ns_router1..."
start_vinbero "$ns_router1" "${SCRIPT_DIR}/vinbero_router1.yaml" "/tmp/vinbero_gtp6_r1.log"
PIDS="$VINBERO_LAST_PID $PIDS"
wait_vinbero_ready "$ns_router1" "127.0.0.1:8082" 10

print_info "Starting Vinbero on $ns_router3..."
start_vinbero "$ns_router3" "${SCRIPT_DIR}/vinbero_router3.yaml" "/tmp/vinbero_gtp6_r3.log"
PIDS="$VINBERO_LAST_PID $PIDS"
wait_vinbero_ready "$ns_router3" "127.0.0.1:8083" 10

# Phase 2: Register entries.
# End.M.GTP6.D/E encode Args.Mob.Session (TEID + QFI = 5 bytes) into the SID at
# args_offset. GTP6 masks the offset with & 0x0B and 8 stays 8, so the args land
# at bytes 8-12 and the /64 SID locator (bytes 0-7) stays intact and routable.
print_info "Registering End.M.GTP6.D on router1..."
ip netns exec "$ns_router1" ${VINBERO_BIN} -s http://127.0.0.1:8082 sid create \
  --trigger-prefix fc00:1::/56 --action END_M_GTP6_D --args-offset 8 > /dev/null

print_info "Registering End.M.GTP6.E on router3..."
ip netns exec "$ns_router3" ${VINBERO_BIN} -s http://127.0.0.1:8083 sid create \
  --trigger-prefix fc00:3::/56 --action END_M_GTP6_E \
  --src-addr fc00:3::3 --dst-addr fc00:100::1 --args-offset 8 > /dev/null

print_success "All entries registered"

# NDP pre-resolve (End.M.GTP6.D's bpf_fib_lookup + redirect needs the next-hop
# toward the End.M.GTP6.E SID resolved).
print_info "Resolving NDP entries..."
ip netns exec "$ns_router1" ping6 -c 1 -W 1 fc00:12::2 > /dev/null 2>&1 || true
ip netns exec "$ns_router2" ping6 -c 1 -W 1 fc00:23::3 > /dev/null 2>&1 || true
sleep 1

# Phase 3: data-plane test. host1 sends an SRv6 packet carrying GTP-U to router1's
# End.M.GTP6.D SID; router1 strips the GTP-U and forwards the inner over SRv6
# toward the End.M.GTP6.E SID (fc00:3::), which we capture on the r1->r2 link.
echo ""
echo "=========================================="
echo "Phase 3: SRv6+GTP-U Packet Test"
echo "=========================================="

if ! python3 -c "from scapy.all import IPv6" 2>/dev/null; then
    print_info "scapy not installed, skipping data-plane test"
    print_info "Install with: apt-get install -y python3-scapy"
    print_success "Entry registration test passed (packet test skipped)"
    exit 0
fi

print_info "Capturing SRv6 on the router1->router2 link while sending..."
ip netns exec "$ns_router2" \
    tcpdump -i "${TOPO_NS_PREFIX}rt2rt1" -c 3 -w /tmp/gtp6_encap.pcap \
    'ip6 and dst net fc00:3::/64' 2>/dev/null &
TCPDUMP_PID=$!
sleep 1

ip netns exec "$ns_host1" python3 "${SCRIPT_DIR}/send_gtpu_v6.py" \
    --sid fc00:1::1 --next-seg fc00:3::3 --teid 0xAABBCCDD --qfi 5 --count 3
sleep 2

kill $TCPDUMP_PID 2>/dev/null || true
wait $TCPDUMP_PID 2>/dev/null || true

CAPTURED=0
if [ -f /tmp/gtp6_encap.pcap ]; then
    CAPTURED=$(tcpdump -r /tmp/gtp6_encap.pcap 2>/dev/null | wc -l)
fi
if [ "$CAPTURED" -gt 0 ]; then
    print_success "End.M.GTP6.D PASS: $CAPTURED SRv6 packets toward End.M.GTP6.E captured"
    tcpdump -r /tmp/gtp6_encap.pcap -n 2>/dev/null | head -3
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    print_error "End.M.GTP6.D FAIL: no SRv6 packets captured on the r1->r2 link"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
rm -f /tmp/gtp6_encap.pcap

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
    exit 0
fi
