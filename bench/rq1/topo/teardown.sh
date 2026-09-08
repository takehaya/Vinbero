#!/bin/bash
# bench/rq1/topo/teardown.sh
# Remove the RQ1 topology. Deleting the namespaces also detaches any XDP
# program still attached to their interfaces, which would otherwise block a
# later attach.

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# REPO_ROOT is overridable so this can run from a snapshot of the directory,
# which is how a long measurement avoids reading a file that may be edited.
REPO_ROOT="${REPO_ROOT:-$(cd "${SCRIPT_DIR}/../../.." && pwd)}"
source "${REPO_ROOT}/examples/common/netns.sh"

export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-rq1-}"

for suffix in src rt pea peb; do
    delete_netns "${TOPO_NS_PREFIX}${suffix}"
done
