#!/bin/bash
# examples/headend-l2/test.sh
# Test H.Encaps.L2 (Headend L2VPN) with Vinbero XDP

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/test_utils.sh"

check_root

VINBEROD_BIN="${SCRIPT_DIR}/../../out/bin/vinberod"
VINBERO_BIN="${SCRIPT_DIR}/../../out/bin/vinbero"
VINBERO_CONFIG_RT1="${SCRIPT_DIR}/vinbero_router1.yaml"
VINBERO_CONFIG_RT3="${SCRIPT_DIR}/vinbero_router3.yaml"

# Set namespace prefix (must match setup.sh)
export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-hl2-}"
ns_host1="${TOPO_NS_PREFIX}host1"
ns_host2="${TOPO_NS_PREFIX}host2"
ns_router1="${TOPO_NS_PREFIX}router1"
ns_router3="${TOPO_NS_PREFIX}router3"

TESTS_PASSED=0
TESTS_FAILED=0
VINBERO_PID_RT1=""
VINBERO_PID_RT3=""

# Cleanup function
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

# Test ping with counter
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

echo "=========================================="
echo "SRv6 H.Encaps.L2 (Headend L2VPN) Test"
echo "=========================================="
echo ""

# Check if setup was done
if ! ip netns list | grep -q "${TOPO_NS_PREFIX}router1"; then
    print_error "Topology not set up. Run ./setup.sh first."
    exit 1
fi

# Check if VLAN interface exists
if ! ip netns exec "$ns_host1" ip link show "${TOPO_NS_PREFIX}h1rt1.100" > /dev/null 2>&1; then
    print_error "VLAN interface not found. Run ./setup.sh first."
    exit 1
fi

# Phase 1: Start Vinbero on both routers
echo "=========================================="
echo "Phase 1: Starting Vinbero on router1 and router3"
echo "=========================================="

print_info "Starting Vinbero on $ns_router1..."
ip netns exec "$ns_router1" ${VINBEROD_BIN} -c ${VINBERO_CONFIG_RT1} > /tmp/vinbero_hl2_rt1.log 2>&1 &
VINBERO_PID_RT1=$!
sleep 2

if ! ps -p $VINBERO_PID_RT1 > /dev/null; then
    print_error "Vinbero failed to start on router1"
    cat /tmp/vinbero_hl2_rt1.log
    exit 1
fi
print_success "Vinbero started on router1 (PID: $VINBERO_PID_RT1)"

print_info "Starting Vinbero on $ns_router3..."
ip netns exec "$ns_router3" ${VINBEROD_BIN} -c ${VINBERO_CONFIG_RT3} > /tmp/vinbero_hl2_rt3.log 2>&1 &
VINBERO_PID_RT3=$!
sleep 2

if ! ps -p $VINBERO_PID_RT3 > /dev/null; then
    print_error "Vinbero failed to start on router3"
    cat /tmp/vinbero_hl2_rt3.log
    exit 1
fi
print_success "Vinbero started on router3 (PID: $VINBERO_PID_RT3)"

echo ""

# Phase 2: Register HeadendL2 entries
echo "=========================================="
echo "Phase 2: Register HeadendL2 entries"
echo "=========================================="

# Forward path: router1 encapsulates VLAN 100 traffic towards host2
print_info "Registering HeadendL2 entry on router1 (forward path)..."
if ! ip netns exec "$ns_router1" ${VINBERO_BIN} -s http://127.0.0.1:8082 hl2 create \
  --interface "${TOPO_NS_PREFIX}rt1h1" --vlan-id 100 --src-addr fc00:1::1 \
  --segments fc00:2::1,fc00:3::3; then
    print_error "Failed to register HeadendL2 entry on router1"
    exit 1
fi
print_success "Router1 HeadendL2: VLAN 100 -> [fc00:2::1, fc00:3::3]"

# Return path: router3 encapsulates VLAN 100 traffic towards host1
print_info "Registering HeadendL2 entry on router3 (return path)..."
if ! ip netns exec "$ns_router3" ${VINBERO_BIN} -s http://127.0.0.1:8083 hl2 create \
  --interface "${TOPO_NS_PREFIX}rt3h2" --vlan-id 100 --src-addr fc00:3::3 \
  --segments fc00:2::2,fc00:1::2; then
    print_error "Failed to register HeadendL2 entry on router3"
    exit 1
fi
print_success "Router3 HeadendL2: VLAN 100 -> [fc00:2::2, fc00:1::2]"

sleep 1
echo ""

# Phase 3: Test L2VPN connectivity
echo "=========================================="
echo "Phase 3: Vinbero XDP H.Encaps.L2 Connectivity"
echo "=========================================="

test_ping_with_counter "$ns_host1" 172.16.100.2 "host1 -> host2 via L2VPN (Vinbero H.Encaps.L2)" "${TOPO_NS_PREFIX}h1rt1.100"

echo ""

# Phase 4: HeadendL2 API Tests
echo "=========================================="
echo "Phase 4: HeadendL2 API Tests"
echo "=========================================="

print_info "Testing HeadendL2List API..."
list_response=$(ip netns exec "$ns_router1" ${VINBERO_BIN} -s http://127.0.0.1:8082 --json hl2 list)

if echo "$list_response" | grep -q '"vlan_id":100'; then
    print_success "HeadendL2List API: PASS (VLAN 100 entry found)"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    print_error "HeadendL2List API: FAIL (VLAN 100 entry not found)"
    print_info "Response: $list_response"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

print_info "Testing HeadendL2Get API..."
get_response=$(ip netns exec "$ns_router1" ${VINBERO_BIN} -s http://127.0.0.1:8082 --json hl2 list)

if echo "$get_response" | grep -q '"src_addr":"fc00:1::1"'; then
    print_success "HeadendL2Get API: PASS (correct src_addr)"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    print_error "HeadendL2Get API: FAIL"
    print_info "Response: $get_response"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

echo ""

# Phase 5: HeadendL2 Delete Test
echo "=========================================="
echo "Phase 5: HeadendL2 Delete Test"
echo "=========================================="

print_info "Testing HeadendL2Delete API..."
if ip netns exec "$ns_router1" ${VINBERO_BIN} -s http://127.0.0.1:8082 hl2 delete \
  --interface "${TOPO_NS_PREFIX}rt1h1" --vlan-id 100; then
    print_success "HeadendL2Delete API: PASS"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    print_error "HeadendL2Delete API: FAIL"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# Verify deletion
list_after=$(ip netns exec "$ns_router1" ${VINBERO_BIN} -s http://127.0.0.1:8082 --json hl2 list)

if echo "$list_after" | grep -q '"vlan_id":100'; then
    print_error "Entry still exists after deletion: FAIL"
    TESTS_FAILED=$((TESTS_FAILED + 1))
else
    print_success "Entry removed after deletion: PASS"
    TESTS_PASSED=$((TESTS_PASSED + 1))
fi

print_info "Stopping Vinbero instances..."
kill $VINBERO_PID_RT1 2>/dev/null || true
wait $VINBERO_PID_RT1 2>/dev/null || true
VINBERO_PID_RT1=""
kill $VINBERO_PID_RT3 2>/dev/null || true
wait $VINBERO_PID_RT3 2>/dev/null || true
VINBERO_PID_RT3=""

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
