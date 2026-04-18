#!/bin/bash
# sdk/examples/plugin-counter/test.sh
# Plugin extension example: packet counter plugin
#
# Demonstrates:
#   1. Compiling a custom BPF plugin
#   2. Registering it via CLI (vinbero plugin register)
#   3. Creating a SID that dispatches to the plugin
#   4. Verifying the plugin processes packets

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
PLUGIN_INDEX=32

export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-plgcnt-}"

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
echo "SRv6 Plugin Extension Example"
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
# Phase 2: Start Vinbero
# ==========================================
print_info "Removing Linux native SRv6 from router1 (will use Vinbero on router2)..."
ip netns exec "$ns_router1" ip -6 route del fc00:3::/64 2>/dev/null || true

print_info "Starting Vinbero on router2..."
start_vinbero "$ns_router2" "${VINBERO_CONFIG}" "/tmp/vinbero_plugin_test.log"
VINBERO_PID=$VINBERO_LAST_PID
wait_vinbero_ready "$ns_router2" "127.0.0.1:8082" 10

# ==========================================
# Phase 3: Register Plugin
# ==========================================
print_info "Registering plugin at slot ${PLUGIN_INDEX}..."
ip netns exec "$ns_router2" ${VINBERO_BIN} -s http://127.0.0.1:8082 \
    plugin register \
    --type endpoint \
    --index ${PLUGIN_INDEX} \
    --prog "${PLUGIN_OBJ}" \
    --program plugin_counter
print_success "Plugin registered at slot ${PLUGIN_INDEX}"

# ==========================================
# Phase 4: Create SID pointing to plugin
# ==========================================
print_info "Creating SID fc00:2::32/128 → plugin (action=${PLUGIN_INDEX})..."

# Create an End function at router2's normal SID for baseline routing
ip netns exec "$ns_router2" ${VINBERO_BIN} -s http://127.0.0.1:8082 \
    sid create --trigger-prefix fc00:2::1/128 --action END

# Create the plugin SID — action=32 dispatches to our plugin at slot 32.
# Note: END_BPF resolves to enum value 16, not slot 32. Use the raw numeric
# index so the tail call goes to the correct PROG_ARRAY slot.
ip netns exec "$ns_router2" ${VINBERO_BIN} -s http://127.0.0.1:8082 \
    sid create --trigger-prefix fc00:2::32/128 --action ${PLUGIN_INDEX}

# Update the route on router1 to use the plugin SID
ip netns exec "$ns_router1" ip -6 route add fc00:3::/64 \
    encap seg6 mode encap segs fc00:2::32,fc00:3::3 dev "${TOPO_NS_PREFIX}rt1rt2"

print_success "SID and route configured"

# ==========================================
# Phase 5: Send Traffic & Verify
# ==========================================
echo ""
echo "=========================================="
echo "Testing Plugin"
echo "=========================================="

PASSED=0
FAILED=0

# Test: send IPv6 packets from host1 that trigger router1's seg6 encap rule.
# The reply never comes back (router2 kernel doesn't own fc00:2::32) so the
# verification below reads plugin_counter_map directly via bpftool instead.
print_info "Sending traffic from host1 towards fc00:3::3 (triggers SRv6 encap at router1)..."
ip netns exec "$ns_host1" ping6 -c 3 -W 2 fc00:3::3 > /dev/null 2>&1 || true

# stats_map is vinbero's global per-action counter across the XDP entry.
# Plugin invocations land here too, but so does unrelated traffic (NDP /
# RA / MLD), so the numbers won't exactly match plugin invocations.
print_info "stats_map (global per-action; includes non-plugin traffic):"
ip netns exec "$ns_router2" ${VINBERO_BIN} -s http://127.0.0.1:8082 stats show

# Per-slot invocation counter, plugin-only view. This is the canonical
# ground truth: vinbero increments slot_stats_endpoint[32] exactly once
# per plugin body execution via tailcall_epilogue.
print_info "stats slot show --type endpoint --plugin-only:"
SLOT_OUT=$(ip netns exec "$ns_router2" ${VINBERO_BIN} -s http://127.0.0.1:8082 \
    stats slot show --type endpoint --plugin-only)
echo "$SLOT_OUT"
SLOT_PACKETS=$(echo "$SLOT_OUT" | awk -v slot="${PLUGIN_INDEX}" '$2 == slot { print $4; exit }')
if [ -z "$SLOT_PACKETS" ] || [ "$SLOT_PACKETS" -eq 0 ]; then
    print_error "slot_stats_endpoint[${PLUGIN_INDEX}] is zero — plugin was never invoked"
    FAILED=$((FAILED + 1))
else
    print_success "plugin invoked $SLOT_PACKETS times (slot=${PLUGIN_INDEX})"
    PASSED=$((PASSED + 1))
fi

# plugin_counter_map is the plugin's private per-CPU counter — a second
# independent check against bpftool.
print_info "plugin_counter_map (plugin-private, read via bpftool):"
MAP_ID=$(ip netns exec "$ns_router2" bpftool map show 2>/dev/null \
    | awk '/name plugin_counter/ { sub(":","",$1); print $1; exit }')
if [ -n "$MAP_ID" ]; then
    COUNTER_TOTAL=$(ip netns exec "$ns_router2" bpftool map dump id "$MAP_ID" 2>/dev/null \
        | grep -Eo '"value": [0-9]+' | awk '{ s += $2 } END { print s+0 }')
    print_info "plugin_counter_map total=${COUNTER_TOTAL}"
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
