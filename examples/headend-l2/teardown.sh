#!/bin/bash
# examples/headend-l2/teardown.sh
# Cleanup H.Encaps.L2 demonstration environment

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Set namespace prefix (must match setup.sh)
# Note: Linux interface names are limited to 15 chars, so use short prefix "hl2-"
export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-hl2-}"

source "${SCRIPT_DIR}/../common/topologies/three_router.sh"

teardown_three_router_topology
