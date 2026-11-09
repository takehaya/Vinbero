#!/bin/bash
# examples/device-attach/teardown.sh

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
rm -f /tmp/vinbero_device_attach_state.json
export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-dva-}"
exec "${SCRIPT_DIR}/../end-dt4/teardown.sh"
