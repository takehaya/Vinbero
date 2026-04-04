#!/bin/bash
# examples/end-dt2-p2mp/test.sh
# Test End.DT2 P2MP: BUM flood to multiple PEs + bridge multi-port flood

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/test_utils.sh"

check_root

VINBEROD_BIN="${SCRIPT_DIR}/../../out/bin/vinberod"
VINBERO_BIN="${SCRIPT_DIR}/../../out/bin/vinbero"

export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-p2m-}"
ns_host1="${TOPO_NS_PREFIX}host1"
ns_host2="${TOPO_NS_PREFIX}host2"
ns_host3="${TOPO_NS_PREFIX}host3"
ns_host4="${TOPO_NS_PREFIX}host4"
ns_router1="${TOPO_NS_PREFIX}router1"
ns_router3="${TOPO_NS_PREFIX}router3"
ns_router4="${TOPO_NS_PREFIX}router4"

TESTS_PASSED=0
TESTS_FAILED=0
VINBERO_PID_PE1=""
VINBERO_PID_PE2=""
VINBERO_PID_PE3=""

cleanup() {
    for pid_var in VINBERO_PID_PE1 VINBERO_PID_PE2 VINBERO_PID_PE3; do
        local pid="${!pid_var}"
        if [ -n "$pid" ] && ps -p "$pid" > /dev/null 2>&1; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
}
trap cleanup EXIT

test_ping_with_counter() {
    local ns=$1 target=$2 desc=$3 interface=${4:-}
    print_info "Testing: $desc"
    local ping_cmd="ping -c 3 -W 2 $target"
    [ -n "$interface" ] && ping_cmd="ping -c 3 -W 2 -I $interface $target"
    if ip netns exec $ns $ping_cmd > /dev/null 2>&1; then
        print_success "$desc: PASS"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        print_error "$desc: FAIL"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

# CLI helpers
vbctl_pe1() { ip netns exec "$ns_router1" ${VINBERO_BIN} -s http://127.0.0.1:8082 "$@"; }
vbctl_pe2() { ip netns exec "$ns_router3" ${VINBERO_BIN} -s http://127.0.0.1:8083 "$@"; }
vbctl_pe3() { ip netns exec "$ns_router4" ${VINBERO_BIN} -s http://127.0.0.1:8084 "$@"; }

echo "=========================================="
echo "SRv6 End.DT2 P2MP (L2VPN) Test"
echo "=========================================="
echo ""

# ==========================================
# Start all Vinbero instances
# ==========================================
print_info "Starting PE1 (router1)..."
ip netns exec "$ns_router1" ${VINBEROD_BIN} -c ${SCRIPT_DIR}/vinbero_pe1.yaml > /tmp/vinbero_p2mp_pe1.log 2>&1 &
VINBERO_PID_PE1=$!

print_info "Starting PE2 (router3)..."
ip netns exec "$ns_router3" ${VINBEROD_BIN} -c ${SCRIPT_DIR}/vinbero_pe2.yaml > /tmp/vinbero_p2mp_pe2.log 2>&1 &
VINBERO_PID_PE2=$!

print_info "Starting PE3 (router4)..."
ip netns exec "$ns_router4" ${VINBEROD_BIN} -c ${SCRIPT_DIR}/vinbero_pe3.yaml > /tmp/vinbero_p2mp_pe3.log 2>&1 &
VINBERO_PID_PE3=$!

sleep 2

for entry in "PE1:VINBERO_PID_PE1:/tmp/vinbero_p2mp_pe1.log" \
             "PE2:VINBERO_PID_PE2:/tmp/vinbero_p2mp_pe2.log" \
             "PE3:VINBERO_PID_PE3:/tmp/vinbero_p2mp_pe3.log"; do
    IFS=: read -r name pid_var log <<< "$entry"
    if ! ps -p "${!pid_var}" > /dev/null 2>&1; then
        print_error "$name failed to start"
        cat "$log"
        exit 1
    fi
    print_success "$name started (PID: ${!pid_var})"
done

# ==========================================
# Phase 1: Configure all PEs
# ==========================================
echo ""
echo "=========================================="
echo "Phase 1: Configure P2MP L2VPN"
echo "=========================================="

# PE1: H.Encaps.L2 + BdPeer to PE2 and PE3
print_info "Configuring PE1 (H.Encaps.L2 + BUM flood to PE2, PE3)..."
vbctl_pe1 hl2 create \
  --interface "${TOPO_NS_PREFIX}rt1h1" --vlan-id 100 \
  --src-addr fc00:1::1 --segments fc00:2::1,fc00:3::3 --bd-id 100

vbctl_pe1 peer create --bd-id 100 --src-addr fc00:1::1 --segments fc00:2::1,fc00:3::3
vbctl_pe1 peer create --bd-id 100 --src-addr fc00:1::1 --segments fc00:2::1,fc00:4::4

# PE2: End.DT2 + H.Encaps.L2 (return) + BdPeer
print_info "Configuring PE2 (End.DT2 + return path)..."
vbctl_pe2 sid create \
  --trigger-prefix fc00:3::3/128 --action END_DT2 --bd-id 100 --bridge-name br100

vbctl_pe2 hl2 create \
  --interface "${TOPO_NS_PREFIX}rt3h2" --vlan-id 100 \
  --src-addr fc00:3::3 --segments fc00:2::2,fc00:1::2 --bd-id 100
vbctl_pe2 hl2 create \
  --interface "${TOPO_NS_PREFIX}rt3h3" --vlan-id 100 \
  --src-addr fc00:3::3 --segments fc00:2::2,fc00:1::2 --bd-id 100

vbctl_pe2 peer create --bd-id 100 --src-addr fc00:3::3 --segments fc00:2::2,fc00:1::2

# PE3: End.DT2 + H.Encaps.L2 (return) + BdPeer
print_info "Configuring PE3 (End.DT2 + return path)..."
vbctl_pe3 sid create \
  --trigger-prefix fc00:4::4/128 --action END_DT2 --bd-id 100 --bridge-name br100

vbctl_pe3 hl2 create \
  --interface "${TOPO_NS_PREFIX}rt4h4" --vlan-id 100 \
  --src-addr fc00:4::4 --segments fc00:2::2,fc00:1::2 --bd-id 100

vbctl_pe3 peer create --bd-id 100 --src-addr fc00:4::4 --segments fc00:2::2,fc00:1::2

sleep 1
print_success "All PEs configured"

# ==========================================
# Phase 2: BUM P2MP flood test
# ==========================================
echo ""
echo "=========================================="
echo "Phase 2: BUM P2MP Flood Test"
echo "=========================================="
print_info "host1 sends ARP broadcast. Expect host2, host3 (PE2), and host4 (PE3) to receive."

# host1 → host2 (PE2, port 1)
test_ping_with_counter "$ns_host1" 172.16.100.2 \
  "host1 -> host2 (PE2 port1) via BUM flood" "${TOPO_NS_PREFIX}h1rt1.100"

# host1 → host3 (PE2, port 2 = bridge multi-port flood)
test_ping_with_counter "$ns_host1" 172.16.100.3 \
  "host1 -> host3 (PE2 port2, bridge multi-port)" "${TOPO_NS_PREFIX}h1rt1.100"

# host1 → host4 (PE3 = separate PE via BUM flood)
test_ping_with_counter "$ns_host1" 172.16.100.4 \
  "host1 -> host4 (PE3) via BUM flood" "${TOPO_NS_PREFIX}h1rt1.100"

# ==========================================
# Phase 3: Bridge multi-port flood (local)
# ==========================================
echo ""
echo "=========================================="
echo "Phase 3: Bridge Multi-Port Flood (PE2)"
echo "=========================================="
print_info "host2 and host3 are on the same bridge (br100 on PE2). They should communicate locally."

test_ping_with_counter "$ns_host2" 172.16.100.3 \
  "host2 -> host3 (same bridge on PE2)" "${TOPO_NS_PREFIX}h2rt3.100"

# ==========================================
# Phase 4: FDB verification
# ==========================================
echo ""
echo "=========================================="
echo "Phase 4: FDB Verification"
echo "=========================================="

print_info "FDB on PE1:"
vbctl_pe1 fdb list

print_info "FDB on PE2:"
vbctl_pe2 fdb list

print_info "FDB on PE3:"
vbctl_pe3 fdb list

# ==========================================
# Summary
# ==========================================
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
