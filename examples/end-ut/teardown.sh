#!/bin/bash
# examples/end-ut/teardown.sh
# Teardown uT (NEXT-C-SID) demonstration environment

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-ut-}"

source "${SCRIPT_DIR}/../common/topologies/three_router.sh"

echo "=========================================="
echo "Tearing down SRv6 uT environment"
echo "=========================================="

# vinberod is started and stopped within test.sh (its EXIT trap fires even
# on an aborted run), so teardown only removes the namespaces.
teardown_three_router_topology

echo ""
echo "=========================================="
print_success "Cleanup complete!"
echo "=========================================="
