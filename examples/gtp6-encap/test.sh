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
ns_router1="${TOPO_NS_PREFIX}router1"
ns_router3="${TOPO_NS_PREFIX}router3"

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

# Start Vinbero on router1
print_info "Starting Vinbero on $ns_router1..."
ip netns exec "$ns_router1" ${VINBEROD_BIN} -c "${SCRIPT_DIR}/vinbero_router1.yaml" > /tmp/vinbero_gtp6_r1.log 2>&1 &
PIDS="$! $PIDS"
sleep 2

# Start Vinbero on router3
print_info "Starting Vinbero on $ns_router3..."
ip netns exec "$ns_router3" ${VINBEROD_BIN} -c "${SCRIPT_DIR}/vinbero_router3.yaml" > /tmp/vinbero_gtp6_r3.log 2>&1 &
PIDS="$! $PIDS"
sleep 2

# Forward: End.M.GTP6.D on router1 (GTP-U/IPv6 -> SRv6)
print_info "Registering End.M.GTP6.D on router1..."
ip netns exec "$ns_router1" ${VINBERO_BIN} -s http://127.0.0.1:8082 sid create \
  --trigger-prefix fc00:1::1/128 --action END_M_GTP6_D --args-offset 7 > /dev/null

# Forward: End.M.GTP6.E on router3 (SRv6 -> GTP-U/IPv6)
print_info "Registering End.M.GTP6.E on router3..."
ip netns exec "$ns_router3" ${VINBERO_BIN} -s http://127.0.0.1:8083 sid create \
  --trigger-prefix fc00:3::3/128 --action END_M_GTP6_E \
  --src-addr fc00:3::3 --dst-addr fc00:100::1 --args-offset 7 > /dev/null

print_success "All entries registered"

print_info "Listing router1 SID entries:"
ip netns exec "$ns_router1" ${VINBERO_BIN} -s http://127.0.0.1:8082 sid list
echo ""

print_info "Listing router3 SID entries:"
ip netns exec "$ns_router3" ${VINBERO_BIN} -s http://127.0.0.1:8083 sid list
echo ""

print_success "Test completed! Full GTP-U E2E testing requires GTP-U traffic generators."
