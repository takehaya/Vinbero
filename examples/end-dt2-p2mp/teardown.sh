#!/bin/bash
set -eu
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-p2m-}"
source "${SCRIPT_DIR}/../common/topologies/four_router.sh"
teardown_four_router_topology
