#!/bin/bash
# examples/end-dx2v/teardown.sh

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-dx2v-}"

source "${SCRIPT_DIR}/../common/topologies/three_router.sh"

teardown_three_router_topology
# The daemons' state files (their L2 headend circuits).
rm -f /tmp/vinbero_end_dx2v_*_state.json
