#!/bin/bash
# sdk/examples/plugin-acl-prefix/teardown.sh

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMMON_DIR="${SCRIPT_DIR}/../../../examples/common"

export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-plgacl-}"

source "${COMMON_DIR}/topologies/three_router.sh"

# Kill any leftover vinbero processes
pkill -f "vinberod.*plugin-acl-prefix" 2>/dev/null || true
sleep 1

teardown_three_router_topology

# Clean up compiled plugin
make -C "${SCRIPT_DIR}" clean >/dev/null 2>&1 || true
