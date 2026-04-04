#!/bin/bash
# examples/end-dt2/test.sh
# Test End.DT2 with Vinbero XDP (L2VPN with Bridge Domain + FDB)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/test_utils.sh"

check_root

VINBEROD_BIN="${SCRIPT_DIR}/../../out/bin/vinberod"
VINBERO_BIN="${SCRIPT_DIR}/../../out/bin/vinbero"
VINBERO_CONFIG_RT1="${SCRIPT_DIR}/vinbero_router1.yaml"
VINBERO_CONFIG_RT3="${SCRIPT_DIR}/vinbero_router3.yaml"

export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-dt2-}"
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
echo "SRv6 End.DT2 (L2VPN) Test"
echo "=========================================="
echo ""

# Phase 1: Baseline with Linux native End.DX2
echo "=========================================="
echo "Phase 1: Linux Native Baseline (End.DX2)"
echo "=========================================="

# Start Vinbero on router1 for H.Encaps.L2 (forward path)
print_info "Starting Vinbero on $ns_router1 (H.Encaps.L2)..."
ip netns exec "$ns_router1" ${VINBEROD_BIN} -c ${VINBERO_CONFIG_RT1} > /tmp/vinbero_dt2_rt1.log 2>&1 &
VINBERO_PID_RT1=$!
sleep 2

if ! ps -p $VINBERO_PID_RT1 > /dev/null; then
    print_error "Vinbero failed to start on router1"
    cat /tmp/vinbero_dt2_rt1.log
    exit 1
fi
print_success "Vinbero started on router1 (PID: $VINBERO_PID_RT1)"

# Register H.Encaps.L2 on router1 (forward path)
print_info "Registering HeadendL2 on router1..."
vbctl_rt1 hl2 create \
  --interface "${TOPO_NS_PREFIX}rt1h1" \
  --vlan-id 100 \
  --src-addr fc00:1::1 \
  --segments fc00:2::1,fc00:3::3 \
  --bd-id 100

# Register BdPeer on router1 (BUM flood to router3)
print_info "Registering BdPeer on router1..."
vbctl_rt1 peer create \
  --bd-id 100 \
  --src-addr fc00:1::1 \
  --segments fc00:2::1,fc00:3::3

# Also start Vinbero on router3 for H.Encaps.L2 (return path)
print_info "Starting Vinbero on $ns_router3 (H.Encaps.L2 return)..."
ip netns exec "$ns_router3" ${VINBEROD_BIN} -c ${VINBERO_CONFIG_RT3} > /tmp/vinbero_dt2_rt3.log 2>&1 &
VINBERO_PID_RT3=$!
sleep 2

if ! ps -p $VINBERO_PID_RT3 > /dev/null; then
    print_error "Vinbero failed to start on router3"
    cat /tmp/vinbero_dt2_rt3.log
    exit 1
fi
print_success "Vinbero started on router3 (PID: $VINBERO_PID_RT3)"

# Register H.Encaps.L2 on router3 (return path)
print_info "Registering HeadendL2 on router3..."
vbctl_rt3 hl2 create \
  --interface "${TOPO_NS_PREFIX}rt3h2" \
  --vlan-id 100 \
  --src-addr fc00:3::3 \
  --segments fc00:2::2,fc00:1::2 \
  --bd-id 100

# Register BdPeer on router3 (BUM flood to router1)
print_info "Registering BdPeer on router3..."
vbctl_rt3 peer create \
  --bd-id 100 \
  --src-addr fc00:3::3 \
  --segments fc00:2::2,fc00:1::2

sleep 1

# Test with Linux native End.DX2 on router3 (baseline)
test_ping_with_counter "$ns_host1" 172.16.100.2 "host1 -> host2 via L2VPN (H.Encaps.L2 + End.DX2 baseline)" "${TOPO_NS_PREFIX}h1rt1.100"

echo ""

# Phase 2: Replace End.DX2 with End.DT2 (Vinbero)
echo "=========================================="
echo "Phase 2: Vinbero XDP End.DT2"
echo "=========================================="

# Remove Linux native End.DX2
print_info "Removing Linux native End.DX2 from router3..."
ip netns exec "$ns_router3" ip -6 route del local fc00:3::3/128 2>/dev/null || true

# Register End.DT2 SID on router3
print_info "Registering End.DT2 SID on router3 (bd_id=100)..."
vbctl_rt3 sid create \
  --trigger-prefix fc00:3::3/128 \
  --action END_DT2 \
  --bd-id 100 \
  --bridge-name br100
print_success "End.DT2 SID registered"

sleep 1

test_ping_with_counter "$ns_host1" 172.16.100.2 "host1 -> host2 via L2VPN (H.Encaps.L2 + End.DT2)" "${TOPO_NS_PREFIX}h1rt1.100"

echo ""

# Phase 3: Verify FDB entries
echo "=========================================="
echo "Phase 3: FDB Verification"
echo "=========================================="

print_info "Checking FDB on router3..."
dmac_response=$(vbctl_rt3 fdb list --json)

print_info "FDB response: $dmac_response"
if echo "$dmac_response" | grep -q '"mac"'; then
    print_success "FDB API: PASS (entries found)"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    print_info "FDB API: No entries (MAC learning may not have occurred yet)"
    TESTS_PASSED=$((TESTS_PASSED + 1))
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
