#!/bin/bash
# examples/headend-ecmp/teardown.sh
# Cleanup the headend ECMP demonstration environment

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Set namespace prefix (must match setup.sh)
export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-hec-}"

source "${SCRIPT_DIR}/../common/netns.sh"

for ns in host1 host2 router1 router2a router2b router3; do
    delete_netns "${TOPO_NS_PREFIX}${ns}"
done

echo "Teardown complete"
