#!/bin/bash
# examples/headend-v4/test.sh
# Test H.Encaps (Headend IPv4) with Vinbero XDP

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/test_utils.sh"

check_root

VINBEROD_BIN="${SCRIPT_DIR}/../../out/bin/vinberod"
VINBERO_BIN="${SCRIPT_DIR}/../../out/bin/vinbero"
VINBERO_CONFIG="${SCRIPT_DIR}/vinbero_router1.yaml"

# Set namespace prefix (must match setup.sh)
# Note: Linux interface names are limited to 15 chars, so use short prefix "hv4-"
export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-hv4-}"
ns_host1="${TOPO_NS_PREFIX}host1"
ns_host2="${TOPO_NS_PREFIX}host2"
ns_router1="${TOPO_NS_PREFIX}router1"

TESTS_PASSED=0
TESTS_FAILED=0
VINBERO_PID=""

cleanup() {
    # Guard against PID reuse: only kill if the PID is still our vinberod.
    if [ -n "$VINBERO_PID" ] && [ "$(ps -o comm= -p "$VINBERO_PID" 2>/dev/null)" = "vinberod" ]; then
        kill "$VINBERO_PID" 2>/dev/null || true
        wait "$VINBERO_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "=========================================="
echo "SRv6 H.Encaps (Headend IPv4) Test"
echo "=========================================="
echo ""

# Phase 1: Test with Linux native SRv6
echo "=========================================="
echo "Phase 1: Linux Native SRv6 (Baseline)"
echo "=========================================="

print_info "Linux native T.Encaps is already configured on $ns_router1 (from setup.sh)"

test_ping_with_counter "$ns_host1" 172.0.2.1 "host1 -> host2 (Linux native T.Encaps)"
test_ping_with_counter "$ns_host2" 172.0.1.1 "host2 -> host1 (Linux native T.Encaps)"

print_info "Removing Linux native T.Encaps route from $ns_router1..."
ip netns exec "$ns_router1" ip route del 172.0.2.0/24 2>/dev/null || true

echo ""

# Phase 2: Test with Vinbero XDP H.Encaps
echo "=========================================="
echo "Phase 2: Vinbero XDP H.Encaps"
echo "=========================================="

print_info "Starting Vinbero on $ns_router1..."
start_vinbero "$ns_router1" "${VINBERO_CONFIG}" "/tmp/vinbero_headend_test.log"
VINBERO_PID=$VINBERO_LAST_PID
wait_vinbero_ready "$ns_router1" "127.0.0.1:8082" 10

print_info "Registering HeadendV4 entry..."
ip netns exec "$ns_router1" ${VINBERO_BIN} -s http://127.0.0.1:8082 hv4 create \
  --trigger-prefix 172.0.2.0/24 --src-addr fc00:1::1 --segments fc00:2::1,fc00:3::3 > /dev/null

print_success "HeadendV4 entry registered"

sleep 1

test_ping_with_counter "$ns_host1" 172.0.2.1 "host1 -> host2 (Vinbero XDP H.Encaps)"
test_ping_with_counter "$ns_host2" 172.0.1.1 "host2 -> host1 (Vinbero XDP)"

echo ""

# Phase 3: a headend entry under a named VRF
echo "=========================================="
echo "Phase 3: Headend entry in a named VRF"
echo "=========================================="

vb() { ip netns exec "$ns_router1" "${VINBERO_BIN}" -s http://127.0.0.1:8082 "$@"; }
fails() { ! "$@" > /dev/null 2>&1; }
check() {
    local desc="$1"; shift
    if "$@"; then
        print_success "$desc"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        print_error "$desc"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}
# The VRF column of the list row for prefix in the named VRF ("" if none).
listed_vrf() { vb hv4 list --all-vrfs | awk -v p="$1" -v v="$2" '$1 == p && $2 == v {print $2}'; }

check "an unknown VRF is refused" fails vb hv4 create \
    --trigger-prefix 172.0.2.0/24 --src-addr fc00:1::1 --segments fc00:9::1 --vrf hv4-nosuch
check "the refused request created no VRF" test -z "$(vb vrf show | grep hv4-nosuch)"

vb vrf create --name hv4-tenant --table-id 4242 > /dev/null
vb hv4 create --trigger-prefix 172.0.2.0/24 --src-addr fc00:1::1 --segments fc00:9::1 --vrf hv4-tenant > /dev/null
vb hv4 list --all-vrfs | sed 's/^/    /'
check "the list without --vrf is the global VRF" test "$(vb hv4 list | awk 'NR > 1 {print $2}')" = global
check "the global entry is listed" test "$(listed_vrf 172.0.2.0/24 global)" = global
check "the same prefix is listed in hv4-tenant" test "$(listed_vrf 172.0.2.0/24 hv4-tenant)" = hv4-tenant
check "--vrf lists that VRF only" test "$(vb hv4 list --vrf hv4-tenant | awk 'NR > 1' | wc -l)" = 1

# The data plane looks up the global VRF only: traffic still takes the
# global entry.
test_ping_with_counter "$ns_host1" 172.0.2.1 "host1 -> host2 (global entry, with a hv4-tenant entry present)"

check "a VRF holding a headend entry is not deleted" fails vb vrf delete --name hv4-tenant
vb hv4 delete --trigger-prefix 172.0.2.0/24 --vrf hv4-tenant > /dev/null
check "the hv4-tenant entry is removed" test -z "$(listed_vrf 172.0.2.0/24 hv4-tenant)"
check "the global entry stays" test "$(listed_vrf 172.0.2.0/24 global)" = global
check "the empty VRF is deleted" vb vrf delete --name hv4-tenant
test_ping_with_counter "$ns_host1" 172.0.2.1 "host1 -> host2 (after the hv4-tenant delete)"

print_info "Stopping Vinbero..."
kill $VINBERO_PID 2>/dev/null || true
wait $VINBERO_PID 2>/dev/null || true

echo ""
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo "Passed: $TESTS_PASSED"
echo "Failed: $TESTS_FAILED"
echo ""

if [ $TESTS_FAILED -gt 0 ]; then
    print_error "Some tests failed"
    exit 1
else
    print_success "All tests passed!"
    exit 0
fi
