#!/bin/bash
# sdk/examples/plugin-acl-prefix/test.sh
# Prefix-ACL plugin end-to-end test.
#
# Exercises the BTF-driven plugin_aux_json path with the
# vinbero_ipv6_prefix_t typedef: the same plugin slot receives two
# different rules via aux, one matching the outer src (drops) and one
# with a non-matching prefix (passes).

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${SCRIPT_DIR}/../../.."
COMMON_DIR="${REPO_ROOT}/examples/common"

source "${COMMON_DIR}/test_utils.sh"
check_root

VINBEROD_BIN="${REPO_ROOT}/out/bin/vinberod"
VINBERO_BIN="${REPO_ROOT}/out/bin/vinbero"
VINBERO_CONFIG="${SCRIPT_DIR}/vinbero_config.yaml"
PLUGIN_OBJ="${SCRIPT_DIR}/plugin.o"
PLUGIN_INDEX=33

export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-plgacl-}"

ns_host1="${TOPO_NS_PREFIX}host1"
ns_router1="${TOPO_NS_PREFIX}router1"
ns_router2="${TOPO_NS_PREFIX}router2"
ns_router3="${TOPO_NS_PREFIX}router3"
ns_host2="${TOPO_NS_PREFIX}host2"

VINBERO_PID=""

cleanup() {
    if [ -n "$VINBERO_PID" ] && ps -p "$VINBERO_PID" > /dev/null 2>&1; then
        kill "$VINBERO_PID" 2>/dev/null || true
        wait "$VINBERO_PID" 2>/dev/null || true
    fi
    make -C "${SCRIPT_DIR}" clean >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "=========================================="
echo "SRv6 Prefix-ACL Plugin Example"
echo "=========================================="
echo ""

# ==========================================
# Phase 1: Compile the plugin
# ==========================================
print_info "Compiling plugin via make -C ${SCRIPT_DIR}"
make -C "${SCRIPT_DIR}" clean
make -C "${SCRIPT_DIR}"
if [ ! -f "${PLUGIN_OBJ}" ]; then
    print_error "Plugin compilation failed"
    exit 1
fi
print_success "Plugin compiled: ${PLUGIN_OBJ}"

# ==========================================
# Phase 2: Start Vinbero on router2
# ==========================================
print_info "Removing Linux native SRv6 route from router1 (will drive the tunnel manually)..."
ip netns exec "$ns_router1" ip -6 route del fc00:3::/64 2>/dev/null || true

print_info "Starting Vinbero on router2..."
start_vinbero "$ns_router2" "${VINBERO_CONFIG}" "/tmp/vinbero_plugin_acl_prefix.log"
VINBERO_PID=$VINBERO_LAST_PID
wait_vinbero_ready "$ns_router2" "127.0.0.1:8083" 10

# ==========================================
# Phase 3: Register the plugin
# ==========================================
print_info "Registering plugin at slot ${PLUGIN_INDEX}..."
ip netns exec "$ns_router2" ${VINBERO_BIN} -s http://127.0.0.1:8083 \
    plugin register \
    --type endpoint \
    --index ${PLUGIN_INDEX} \
    --prog "${PLUGIN_OBJ}" \
    --program plugin_acl_prefix
print_success "Plugin registered at slot ${PLUGIN_INDEX}"

# ==========================================
# Phase 4: Create two SIDs backed by the same plugin slot, each with
#          a different aux rule. The BTF encoder converts the JSON
#          prefix string into the packed sid_aux_entry layout.
# ==========================================
print_info "Creating SID fc00:2::33/128 → DROP rule (deny fc00:12::/64)..."
ip netns exec "$ns_router2" ${VINBERO_BIN} -s http://127.0.0.1:8083 \
    sid create --trigger-prefix fc00:2::33/128 --action ${PLUGIN_INDEX} \
    --plugin-aux-json '{"deny_src": "fc00:12::/64", "action": 1}'

print_info "Creating SID fc00:2::34/128 → PASS rule (deny fc00:99::/64, no match)..."
ip netns exec "$ns_router2" ${VINBERO_BIN} -s http://127.0.0.1:8083 \
    sid create --trigger-prefix fc00:2::34/128 --action ${PLUGIN_INDEX} \
    --plugin-aux-json '{"deny_src": "fc00:99::/64", "action": 1}'

# ==========================================
# Phase 5: Two encap routes on router1 — one per SID.
# ==========================================
ip netns exec "$ns_router1" ip -6 route replace fc00:3::33 \
    encap seg6 mode encap segs fc00:2::33,fc00:3::33 dev "${TOPO_NS_PREFIX}rt1rt2"
ip netns exec "$ns_router1" ip -6 route replace fc00:3::34 \
    encap seg6 mode encap segs fc00:2::34,fc00:3::34 dev "${TOPO_NS_PREFIX}rt1rt2"

print_success "Both SIDs and routes configured"

# ==========================================
# Phase 6: Send traffic & verify
# ==========================================
echo ""
echo "=========================================="
echo "Testing Prefix-ACL"
echo "=========================================="
PASSED=0
FAILED=0

# Baseline: capture current stats. stats reset so this run's numbers
# are self-contained.
ip netns exec "$ns_router2" ${VINBERO_BIN} -s http://127.0.0.1:8083 stats reset || true
ip netns exec "$ns_router2" ${VINBERO_BIN} -s http://127.0.0.1:8083 stats slot reset --type endpoint || true

# Send 3 probes through the DROP SID. Outer src after router1 encap is
# fc00:12::1 — inside deny_src fc00:12::/64, so the plugin drops.
print_info "Sending 3 probes through fc00:2::33 (should DROP)..."
ip netns exec "$ns_host1" ping6 -c 3 -W 2 fc00:3::33 > /dev/null 2>&1 || true

# Send 3 probes through the PASS SID. deny_src fc00:99::/64 does not
# match the outer src, so the plugin passes.
print_info "Sending 3 probes through fc00:2::34 (should PASS)..."
ip netns exec "$ns_host1" ping6 -c 3 -W 2 fc00:3::34 > /dev/null 2>&1 || true

print_info "Global stats:"
ip netns exec "$ns_router2" ${VINBERO_BIN} -s http://127.0.0.1:8083 stats show

print_info "Per-slot stats:"
SLOT_OUT=$(ip netns exec "$ns_router2" ${VINBERO_BIN} -s http://127.0.0.1:8083 \
    stats slot show --type endpoint --plugin-only)
echo "$SLOT_OUT"
SLOT_PACKETS=$(echo "$SLOT_OUT" | awk -v slot="${PLUGIN_INDEX}" '$2 == slot { print $4; exit }')
if [ -z "$SLOT_PACKETS" ] || [ "$SLOT_PACKETS" -lt 2 ]; then
    print_error "plugin slot ${PLUGIN_INDEX} only saw ${SLOT_PACKETS:-0} packets; expected at least 2"
    FAILED=$((FAILED + 1))
else
    print_success "plugin invoked ${SLOT_PACKETS} times across both SIDs"
    PASSED=$((PASSED + 1))
fi

# DROP verification: global DROP counter should be >= 1 (at least one
# probe from the fc00:2::33 set was dropped). Non-SRv6 background
# traffic (NDP) can bump PASS but never DROP, so this is tight enough.
DROP_PACKETS=$(ip netns exec "$ns_router2" ${VINBERO_BIN} -s http://127.0.0.1:8083 \
    stats show | awk '$1 == "DROP" { print $2 }')
if [ -z "$DROP_PACKETS" ] || [ "$DROP_PACKETS" -eq 0 ]; then
    print_error "expected DROP counter to be non-zero (deny_src should have matched)"
    FAILED=$((FAILED + 1))
else
    print_success "DROP counter=${DROP_PACKETS} — deny_src matched as expected"
    PASSED=$((PASSED + 1))
fi

echo ""
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo "Passed: $PASSED"
echo "Failed: $FAILED"
if [ $FAILED -eq 0 ]; then
    print_success "All tests passed!"
else
    print_error "$FAILED test(s) failed"
    exit 1
fi

print_info "Stopping Vinbero..."
kill "$VINBERO_PID" 2>/dev/null || true
wait "$VINBERO_PID" 2>/dev/null || true
VINBERO_PID=""
