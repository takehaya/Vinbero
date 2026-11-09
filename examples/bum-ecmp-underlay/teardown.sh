#!/bin/bash
# examples/bum-ecmp-underlay/teardown.sh
set -eu
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/netns.sh"
for ns in becmp-ce becmp-pe becmp-rt; do
    delete_netns "$ns"
done
