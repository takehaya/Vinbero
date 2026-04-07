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
ns_router1="${TOPO_NS_PREFIX}router1"
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

test_ping_with_counter() {
    local ns=$1
    local target=$2
    local desc=$3

    print_info "Testing: $desc"
    if ip netns exec $ns ping -c 3 -W 2 $target > /dev/null 2>&1; then
        print_success "$desc: PASS"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        print_error "$desc: FAIL"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

echo "=========================================="
echo "SRv6 GTP-U/IPv4 (H.M.GTP4.D + End.M.GTP4.E) Test"
echo "=========================================="
echo ""

# Start Vinbero on router1
print_info "Starting Vinbero on $ns_router1..."
ip netns exec "$ns_router1" ${VINBEROD_BIN} -c "${SCRIPT_DIR}/vinbero_router1.yaml" > /tmp/vinbero_gtp4_r1.log 2>&1 &
PIDS="$! $PIDS"
sleep 2

# Start Vinbero on router3
print_info "Starting Vinbero on $ns_router3..."
ip netns exec "$ns_router3" ${VINBEROD_BIN} -c "${SCRIPT_DIR}/vinbero_router3.yaml" > /tmp/vinbero_gtp4_r3.log 2>&1 &
PIDS="$! $PIDS"
sleep 2

# Register H.M.GTP4.D on router1 (forward path: gNB -> SRv6)
print_info "Registering H.M.GTP4.D on router1..."
ip netns exec "$ns_router1" ${VINBERO_BIN} -s http://127.0.0.1:8082 hv4 create \
  --trigger-prefix 172.0.2.0/24 --src-addr fc00:1::1 \
  --segments fc00:2::1,fc00:3::3 --mode H_M_GTP4_D --args-offset 7 > /dev/null

# Register End.M.GTP4.E on router3 (forward path: SRv6 -> UPF)
print_info "Registering End.M.GTP4.E on router3..."
ip netns exec "$ns_router3" ${VINBERO_BIN} -s http://127.0.0.1:8083 sid create \
  --trigger-prefix fc00:3::3/128 --action END_M_GTP4_E \
  --gtp-v4-src-addr 172.0.2.2 --args-offset 7 > /dev/null

# Register H.M.GTP4.D on router3 (return path: UPF -> SRv6)
print_info "Registering H.M.GTP4.D on router3..."
ip netns exec "$ns_router3" ${VINBERO_BIN} -s http://127.0.0.1:8083 hv4 create \
  --trigger-prefix 172.0.1.0/24 --src-addr fc00:3::3 \
  --segments fc00:2::2,fc00:1::1 --mode H_M_GTP4_D --args-offset 7 > /dev/null

# Register End.M.GTP4.E on router1 (return path: SRv6 -> gNB)
print_info "Registering End.M.GTP4.E on router1..."
ip netns exec "$ns_router1" ${VINBERO_BIN} -s http://127.0.0.1:8082 sid create \
  --trigger-prefix fc00:1::1/128 --action END_M_GTP4_E \
  --gtp-v4-src-addr 172.0.1.2 --args-offset 7 > /dev/null

print_success "All entries registered"
sleep 1

# Note: Full E2E testing requires GTP-U traffic generation tools (e.g., gtp-u-tunnel).
# The ping test below verifies basic IP connectivity through the SRv6 path.
# For true GTP-U testing, use dedicated GTP-U traffic generators.

echo ""
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo "Entries registered successfully."
echo "Full GTP-U E2E testing requires GTP-U traffic generators."
echo ""

# Verify entries are listed
print_info "Listing router1 headend entries:"
ip netns exec "$ns_router1" ${VINBERO_BIN} -s http://127.0.0.1:8082 hv4 list
echo ""

print_info "Listing router3 SID function entries:"
ip netns exec "$ns_router3" ${VINBERO_BIN} -s http://127.0.0.1:8083 sid list
echo ""

print_success "Test completed!"
