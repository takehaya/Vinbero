#!/usr/bin/env bash
# Shared variables are consumed by setup.sh, test.sh and teardown.sh.
# shellcheck disable=SC2034
export LC_ALL=C

EXAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$EXAMPLE_DIR/../.." && pwd)"
source "$EXAMPLE_DIR/../common/test_utils.sh"

PE1=cnil3-pe1
PE2=cnil3-pe2
POD1=cnil3-pod1   # on PE1
POD1B=cnil3-pod1b # on PE1
POD2=cnil3-pod2   # on PE2
# tenant-b uses tenant-a's subnets: POD1X gets POD1's address, POD2X POD2's.
POD1X=cnil3-pod1x # on PE1
POD2X=cnil3-pod2x # on PE2
NAMESPACES=("$PE1" "$PE2" "$POD1" "$POD1B" "$POD2" "$POD1X" "$POD2X")
VINBEROD_BIN="$REPO_ROOT/out/bin/vinberod"
VINBERO_BIN="$REPO_ROOT/out/bin/vinbero"
CNI_BIN="$REPO_ROOT/out/bin/vinbero-cni"

ctl() {
    local ns=$1
    shift
    timeout 15 ip netns exec "$ns" "$VINBERO_BIN" -s http://127.0.0.1:8084 "$@"
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
