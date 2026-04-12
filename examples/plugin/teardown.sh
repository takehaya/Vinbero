#!/bin/bash
# examples/plugin/teardown.sh

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

EXAMPLE_NAME="$(basename "$SCRIPT_DIR")"
export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-${EXAMPLE_NAME}-}"

source "${SCRIPT_DIR}/../common/topologies/three_router.sh"

# Kill any leftover vinbero processes
pkill -f "vinberod.*vinbero_config.yaml" 2>/dev/null || true
sleep 1

teardown_three_router_topology

# Clean up compiled plugin
rm -f /tmp/plugin_counter.o
