#!/bin/bash
set -eu
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-p2m-}"
source "${SCRIPT_DIR}/../common/topologies/four_router.sh"
teardown_four_router_topology
# The daemons' state files (their L2 headend circuits).
rm -f /tmp/vinbero_end_dt2_p2mp_*_state.json
