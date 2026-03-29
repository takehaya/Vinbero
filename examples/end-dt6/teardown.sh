#!/bin/bash
# examples/end-dt6/teardown.sh

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-dt6-}"

source "${SCRIPT_DIR}/../common/topologies/three_router.sh"

teardown_three_router_topology
