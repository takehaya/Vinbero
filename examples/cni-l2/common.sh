#!/usr/bin/env bash
# Shared variables for setup.sh, test.sh and teardown.sh.
# shellcheck disable=SC2034
export LC_ALL=C

EXAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$EXAMPLE_DIR/../.." && pwd)"
source "$EXAMPLE_DIR/../common/test_utils.sh"

PE1=cnil2-pe1
PE2=cnil2-pe2
POD1=cnil2-pod1   # tenant-l2, PE1
POD1B=cnil2-pod1b # tenant-l2, PE1
PODS=cnil2-pods   # tenant-l2, PE1, silent (never sends)
POD1X=cnil2-pod1x # tenant-l2b, PE1 (same subnet/MAC as tenant-l2)
POD2=cnil2-pod2   # tenant-l2, PE2
POD2X=cnil2-pod2x # tenant-l2b, PE2
NAMESPACES=("$PE1" "$PE2" "$POD1" "$POD1B" "$PODS" "$POD1X" "$POD2" "$POD2X")
VINBEROD_BIN="$REPO_ROOT/out/bin/vinberod"
VINBERO_BIN="$REPO_ROOT/out/bin/vinbero"
CNI_BIN="$REPO_ROOT/out/bin/vinbero-cni"

ctl() {
    local ns=$1
    shift
    timeout 15 ip netns exec "$ns" "$VINBERO_BIN" -s http://127.0.0.1:8085 "$@"
}

wait_for() {
    local description=$1
    shift
    for ((attempt = 0; attempt < 40; attempt++)); do
        if "$@" >/dev/null 2>&1; then
            print_success "$description"
            return 0
        fi
        sleep 1
    done
    print_error "Timed out: $description"
    return 1
}
