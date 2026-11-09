#!/bin/bash
# examples/device-attach/setup.sh
# Same topology as end-dt4 (router3 decapsulates End.DT4 into vrf100), under
# its own namespace prefix. test.sh attaches the uplink at runtime.

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-dva-}"
exec "${SCRIPT_DIR}/../end-dt4/setup.sh"
