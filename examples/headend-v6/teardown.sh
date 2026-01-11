#!/bin/bash
# examples/headend-v6/teardown.sh
# Cleanup H.Encaps IPv6 demonstration environment

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Set namespace prefix (must match setup.sh)
# Note: Linux interface names are limited to 15 chars, so use short prefix "hv6-"
export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-hv6-}"

source "${SCRIPT_DIR}/../common/topologies/three_router.sh"

teardown_three_router_topology
