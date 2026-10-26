#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
source "$EXAMPLE_DIR/../common/netns.sh"
check_root

for ns in "${NAMESPACES[@]}"; do
    if [[ -n "$(ip netns pids "$ns" 2>/dev/null)" ]]; then
        print_error "$ns still has processes; stop its test before teardown"
        exit 1
    fi
done
for ns in "${NAMESPACES[@]}"; do delete_netns "$ns"; done
