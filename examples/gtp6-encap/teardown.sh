#!/bin/bash
# examples/gtp6-encap/teardown.sh
set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-gtp6-}"
source "${SCRIPT_DIR}/../common/topologies/three_router.sh"
teardown_three_router_topology
