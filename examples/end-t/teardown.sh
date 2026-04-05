#!/bin/bash
# examples/end-t/teardown.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

EXAMPLE_NAME="$(basename "$SCRIPT_DIR")"
export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-${EXAMPLE_NAME}-}"

source "${SCRIPT_DIR}/../common/topologies/three_router.sh"

echo "=========================================="
echo "Tearing down SRv6 End.T environment"
echo "=========================================="

print_info "Stopping Vinbero processes..."
pkill -f "vinbero.*end-t" 2>/dev/null || true
sleep 1

teardown_three_router_topology

echo ""
echo "=========================================="
print_success "Cleanup complete!"
echo "=========================================="
