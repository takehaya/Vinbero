#!/bin/bash
# examples/end-am/teardown.sh
# Cleanup End.AM demonstration environment

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-am-}"

source "${SCRIPT_DIR}/../common/topologies/three_router.sh"

# The service namespace is extra to the base topology.
delete_netns "${TOPO_NS_PREFIX}svc" 2>/dev/null || true

teardown_three_router_topology
