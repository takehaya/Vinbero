#!/usr/bin/env bash
# Shared variables are consumed by setup.sh, test.sh and teardown.sh.
# shellcheck disable=SC2034
export LC_ALL=C

EXAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$EXAMPLE_DIR/../.." && pwd)"
source "$EXAMPLE_DIR/../common/test_utils.sh"

HOST1=cpdp-host1
PE1=cpdp-pe1
PE2=cpdp-pe2
HOST2=cpdp-host2
NAMESPACES=("$HOST1" "$PE1" "$PE2" "$HOST2")
VINBEROD_BIN="$REPO_ROOT/out/bin/vinberod"
VINBERO_BIN="$REPO_ROOT/out/bin/vinbero"
WASM="$REPO_ROOT/sdk/examples/cplane-custom-behavior/plugin.wasm"
PLUGIN="$REPO_ROOT/sdk/examples/plugin-custom-behavior/plugin.o"

ctl() {
    local ns=$1
    shift
    timeout 15 ip netns exec "$ns" "$VINBERO_BIN" -s http://127.0.0.1:8082 "$@"
}

wait_for() {
    local description=$1
    shift
    for ((attempt = 0; attempt < 30; attempt++)); do
        if "$@" >/dev/null 2>&1; then
            print_success "$description"
            return 0
        fi
        sleep 1
    done
    print_error "Timed out: $description"
    return 1
}
