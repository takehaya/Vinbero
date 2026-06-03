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

# Teardown topology. vinberod is started and stopped within test.sh (its EXIT
# trap fires even on an aborted run), so teardown only removes the namespaces.
# A broad "pkill -f vinbero..." here would kill a sibling example's daemon
# during parallel CI runs that share the same config filename.
teardown_three_router_topology

echo ""
echo "=========================================="
print_success "Cleanup complete!"
echo "=========================================="
