#!/bin/bash
# examples/end-dt2m-multihomed/teardown.sh
set -eu
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/test_utils.sh"
source "${SCRIPT_DIR}/../common/netns.sh"

check_root

for ns in mh-host1 mh-host2 mh-pe1 mh-pe2 mh-pe3 mh-p; do
    delete_netns "$ns"
done
print_success "End.DT2M multi-homed topology removed"
