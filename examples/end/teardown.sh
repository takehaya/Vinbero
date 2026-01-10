#!/bin/bash
# examples/end/teardown.sh
# Teardown End operation demonstration environment

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Set namespace prefix for this example (must match setup.sh)
# Default: use directory name (e.g., "end" -> "end-")
EXAMPLE_NAME="$(basename "$SCRIPT_DIR")"
export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-${EXAMPLE_NAME}-}"

source "${SCRIPT_DIR}/../common/topologies/three_router.sh"

echo "=========================================="
echo "Tearing down SRv6 End environment"
echo "=========================================="

# Kill Vinbero if running
print_info "Stopping Vinbero processes..."
pkill -f "vinbero.*vinbero_router2.yaml" 2>/dev/null || true
sleep 1

# Teardown topology
teardown_three_router_topology

echo ""
echo "=========================================="
print_success "Cleanup complete!"
echo "=========================================="
