#!/bin/bash
# examples/bum-ecmp-underlay/teardown.sh
set -eu
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/netns.sh"
for ns in becmp-ce becmp-pe becmp-rt; do
    delete_netns "$ns"
done
# The daemons' state files (their L2 headend circuits).
rm -f /tmp/vinbero_bum_ecmp_underlay_*_state.json
