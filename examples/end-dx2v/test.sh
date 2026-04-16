#!/bin/bash
# examples/end-dx2v/test.sh
# Test End.DX2V with Vinbero XDP (VLAN cross-connect)
# Verifies that different VLANs are correctly cross-connected to output ports

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/test_utils.sh"

check_root

VINBEROD_BIN="${SCRIPT_DIR}/../../out/bin/vinberod"
VINBERO_BIN="${SCRIPT_DIR}/../../out/bin/vinbero"
VINBERO_CONFIG_RT1="${SCRIPT_DIR}/vinbero_router1.yaml"
VINBERO_CONFIG_RT3="${SCRIPT_DIR}/vinbero_router3.yaml"

export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-dx2v-}"
ns_host1="${TOPO_NS_PREFIX}host1"
ns_host2="${TOPO_NS_PREFIX}host2"
ns_router1="${TOPO_NS_PREFIX}router1"
ns_router3="${TOPO_NS_PREFIX}router3"

TESTS_PASSED=0
TESTS_FAILED=0
VINBERO_PID_RT1=""
VINBERO_PID_RT3=""

cleanup() {
    if [ -n "$VINBERO_PID_RT1" ] && ps -p "$VINBERO_PID_RT1" > /dev/null 2>&1; then
        kill "$VINBERO_PID_RT1" 2>/dev/null || true
        wait "$VINBERO_PID_RT1" 2>/dev/null || true
    fi
    if [ -n "$VINBERO_PID_RT3" ] && ps -p "$VINBERO_PID_RT3" > /dev/null 2>&1; then
        kill "$VINBERO_PID_RT3" 2>/dev/null || true
        wait "$VINBERO_PID_RT3" 2>/dev/null || true
    fi
}
trap cleanup EXIT

test_ping_with_counter() {
    local ns=$1
    local target=$2
    local desc=$3
    local interface=${4:-}

    print_info "Testing: $desc"
    local ping_cmd="ping -c 3 -W 2 $target"
    if [ -n "$interface" ]; then
        ping_cmd="ping -c 3 -W 2 -I $interface $target"
    fi

    if ip netns exec $ns $ping_cmd > /dev/null 2>&1; then
        print_success "$desc: PASS"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        print_error "$desc: FAIL"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

# Helper: run vinbero CLI inside a network namespace
vbctl_rt1() { ip netns exec "$ns_router1" ${VINBERO_BIN} -s http://127.0.0.1:8082 "$@"; }
vbctl_rt3() { ip netns exec "$ns_router3" ${VINBERO_BIN} -s http://127.0.0.1:8083 "$@"; }

echo "=========================================="
echo "SRv6 End.DX2V (VLAN Cross-connect) Test"
echo "=========================================="
echo ""

# Phase 1: Baseline with Linux native End.DX2
echo "=========================================="
echo "Phase 1: Linux Native Baseline (End.DX2)"
echo "=========================================="

# Start Vinbero on router1 for H.Encaps.L2 (forward path)
print_info "Starting Vinbero on $ns_router1 (H.Encaps.L2)..."
start_vinbero "$ns_router1" "${VINBERO_CONFIG_RT1}" "/tmp/vinbero_dx2v_rt1.log"
VINBERO_PID_RT1=$VINBERO_LAST_PID
wait_vinbero_ready "$ns_router1" "127.0.0.1:8082" 10

# Register H.Encaps.L2 on router1 for VLAN 100 (forward path)
print_info "Registering HeadendL2 on router1 for VLAN 100..."
vbctl_rt1 hl2 create \
  --interface "${TOPO_NS_PREFIX}rt1h1" \
  --vlan-id 100 \
  --src-addr fc00:1::1 \
  --segments fc00:2::1,fc00:3::3

# Register H.Encaps.L2 on router1 for VLAN 200 (forward path)
print_info "Registering HeadendL2 on router1 for VLAN 200..."
vbctl_rt1 hl2 create \
  --interface "${TOPO_NS_PREFIX}rt1h1" \
  --vlan-id 200 \
  --src-addr fc00:1::1 \
  --segments fc00:2::1,fc00:3::3

# Start Vinbero on router3 for return path H.Encaps.L2
print_info "Starting Vinbero on $ns_router3..."
start_vinbero "$ns_router3" "${VINBERO_CONFIG_RT3}" "/tmp/vinbero_dx2v_rt3.log"
VINBERO_PID_RT3=$VINBERO_LAST_PID
wait_vinbero_ready "$ns_router3" "127.0.0.1:8083" 10

# Register H.Encaps.L2 on router3 for VLAN 100 (return path)
print_info "Registering HeadendL2 on router3 for VLAN 100..."
vbctl_rt3 hl2 create \
  --interface "${TOPO_NS_PREFIX}rt3h2" \
  --vlan-id 100 \
  --src-addr fc00:3::3 \
  --segments fc00:2::2,fc00:1::2

# Register H.Encaps.L2 on router3 for VLAN 200 (return path)
print_info "Registering HeadendL2 on router3 for VLAN 200..."
vbctl_rt3 hl2 create \
  --interface "${TOPO_NS_PREFIX}rt3h2" \
  --vlan-id 200 \
  --src-addr fc00:3::3 \
  --segments fc00:2::2,fc00:1::2

sleep 1

# Baseline test with Linux native End.DX2
test_ping_with_counter "$ns_host1" 172.16.100.2 "VLAN 100: host1 -> host2 (End.DX2 baseline)" "${TOPO_NS_PREFIX}h1rt1.100"
test_ping_with_counter "$ns_host1" 172.16.200.2 "VLAN 200: host1 -> host2 (End.DX2 baseline)" "${TOPO_NS_PREFIX}h1rt1.200"

echo ""

# Phase 2: Replace End.DX2 with End.DX2V (Vinbero)
echo "=========================================="
echo "Phase 2: Vinbero XDP End.DX2V"
echo "=========================================="

# Remove Linux native End.DX2
print_info "Removing Linux native End.DX2 from router3..."
ip netns exec "$ns_router3" ip -6 route del local fc00:3::3/128 2>/dev/null || true

# Create VLAN table entries on router3
print_info "Creating VLAN table entries on router3..."
vbctl_rt3 vlan-table create \
  --table-id 1 \
  --vlan-id 100 \
  --interface "${TOPO_NS_PREFIX}rt3h2"
print_success "VLAN 100 -> ${TOPO_NS_PREFIX}rt3h2"

vbctl_rt3 vlan-table create \
  --table-id 1 \
  --vlan-id 200 \
  --interface "${TOPO_NS_PREFIX}rt3h2"
print_success "VLAN 200 -> ${TOPO_NS_PREFIX}rt3h2"

# Register End.DX2V SID on router3
print_info "Registering End.DX2V SID on router3 (table_id=1)..."
vbctl_rt3 sid create \
  --trigger-prefix fc00:3::3/128 \
  --action END_DX2V \
  --table-id 1
print_success "End.DX2V SID registered"

sleep 1

# Test VLAN 100 cross-connect
test_ping_with_counter "$ns_host1" 172.16.100.2 "VLAN 100: host1 -> host2 (End.DX2V)" "${TOPO_NS_PREFIX}h1rt1.100"

# Test VLAN 200 cross-connect
test_ping_with_counter "$ns_host1" 172.16.200.2 "VLAN 200: host1 -> host2 (End.DX2V)" "${TOPO_NS_PREFIX}h1rt1.200"

echo ""

# Phase 3: Verify VLAN table via API
echo "=========================================="
echo "Phase 3: VLAN Table Verification"
echo "=========================================="

print_info "Checking VLAN table on router3..."
vlan_response=$(vbctl_rt3 --json vlan-table list --table-id 1)
print_info "VLAN table response: $vlan_response"

if echo "$vlan_response" | grep -q '"vlanId"'; then
    entry_count=$(echo "$vlan_response" | grep -c '"vlanId"')
    print_success "VLAN table API: PASS ($entry_count entries found)"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    print_error "VLAN table API: FAIL (no entries found)"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

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
