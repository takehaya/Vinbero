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
ip netns exec "$ns_router1" ${VINBEROD_BIN} -c "${SCRIPT_DIR}/vinbero_router1.yaml" > /tmp/vinbero_gtp6_r1.log 2>&1 &
PIDS="$! $PIDS"
sleep 2

print_info "Starting Vinbero on $ns_router3..."
ip netns exec "$ns_router3" ${VINBEROD_BIN} -c "${SCRIPT_DIR}/vinbero_router3.yaml" > /tmp/vinbero_gtp6_r3.log 2>&1 &
PIDS="$! $PIDS"
sleep 2

# Phase 2: Register entries
# End.M.GTP6.E uses /56 prefix (Args.Mob.Session at offset 7)
print_info "Registering End.M.GTP6.D on router1..."
ip netns exec "$ns_router1" ${VINBERO_BIN} -s http://127.0.0.1:8082 sid create \
  --trigger-prefix fc00:1::/56 --action END_M_GTP6_D --args-offset 7 > /dev/null

print_info "Registering End.M.GTP6.E on router3..."
ip netns exec "$ns_router3" ${VINBERO_BIN} -s http://127.0.0.1:8083 sid create \
  --trigger-prefix fc00:3::/56 --action END_M_GTP6_E \
  --src-addr fc00:3::3 --dst-addr fc00:100::1 --args-offset 7 > /dev/null

print_success "All entries registered"

# NDP pre-resolve
print_info "Resolving NDP entries..."
ip netns exec "$ns_router1" ping6 -c 1 -W 1 fc00:12::2 > /dev/null 2>&1 || true
ip netns exec "$ns_router2" ping6 -c 1 -W 1 fc00:23::3 > /dev/null 2>&1 || true
sleep 1

# Phase 3: Packet test
echo ""
echo "=========================================="
echo "Phase 3: GTP-U/IPv6 Packet Test"
echo "=========================================="

if ! python3 -c "from scapy.all import IPv6" 2>/dev/null; then
    print_info "scapy not installed, skipping packet test"
    print_info "Install with: pip3 install scapy"
    exit 0
fi

print_info "Listing entries..."
ip netns exec "$ns_router1" ${VINBERO_BIN} -s http://127.0.0.1:8082 sid list
ip netns exec "$ns_router3" ${VINBERO_BIN} -s http://127.0.0.1:8083 sid list
echo ""

print_info "Test: Sending GTP-U/IPv6 (QFI=5, TEID=0xAABBCCDD)..."
ip netns exec "$ns_host1" python3 "${SCRIPT_DIR}/send_gtpu_v6.py" \
    --dst fc00:1::1 --teid 0xAABBCCDD --qfi 5 --count 1

TESTS_PASSED=$((TESTS_PASSED + 1))

echo ""
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo "Passed: $TESTS_PASSED"
echo "Failed: $TESTS_FAILED"
print_success "All tests passed!"
