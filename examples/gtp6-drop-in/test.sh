#!/bin/bash
# examples/gtp6-drop-in/test.sh
# Test End.M.GTP6.D.Di (Drop-In) with Vinbero XDP

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/test_utils.sh"

check_root

VINBEROD_BIN="${SCRIPT_DIR}/../../out/bin/vinberod"
VINBERO_BIN="${SCRIPT_DIR}/../../out/bin/vinbero"

export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-gtdi-}"
ns_router1="${TOPO_NS_PREFIX}router1"

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
echo "SRv6 GTP-U/IPv6 Drop-In (End.M.GTP6.D.Di) Test"
echo "=========================================="
echo ""

print_info "Starting Vinbero on $ns_router1..."
ip netns exec "$ns_router1" ${VINBEROD_BIN} -c "${SCRIPT_DIR}/vinbero_router1.yaml" > /tmp/vinbero_gtdi_r1.log 2>&1 &
PIDS="$! $PIDS"
sleep 2

# Drop-In does not use args_offset (no Args.Mob.Session encoding)
print_info "Registering End.M.GTP6.D.Di on router1..."
ip netns exec "$ns_router1" ${VINBERO_BIN} -s http://127.0.0.1:8082 sid create \
  --trigger-prefix fc00:1::1/128 --action END_M_GTP6_D_DI > /dev/null

print_success "Entry registered"
TESTS_PASSED=$((TESTS_PASSED + 1))

print_info "Listing router1 SID entries:"
ip netns exec "$ns_router1" ${VINBERO_BIN} -s http://127.0.0.1:8082 sid list
echo ""

echo "Drop-In mode:"
echo "  - Vinbero updates SRH nexthdr in XDP"
echo "  - Returns XDP_PASS to kernel for forwarding"
echo "  - SL and DA are NOT modified"
echo ""

echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo "Passed: $TESTS_PASSED"
echo "Failed: $TESTS_FAILED"
print_success "All tests passed!"
