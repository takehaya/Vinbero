#!/bin/bash
# examples/end-an/teardown.sh
# Cleanup End.AN demonstration environment

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-an-}"

source "${SCRIPT_DIR}/../common/topologies/three_router.sh"

teardown_three_router_topology
