#!/bin/bash
# examples/end-dt2-p2mp/test.sh
# Test End.DT2 P2MP: BUM flood to multiple PEs + bridge multi-port flood
#
# BUM_MODE=tc (default) or xdp selects settings.l2.bum_mode for all PEs.

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
ns_router2="${TOPO_NS_PREFIX}router2"
ns_router3="${TOPO_NS_PREFIX}router3"
ns_router4="${TOPO_NS_PREFIX}router4"
BUM_MODE="${BUM_MODE:-tc}"

TESTS_PASSED=0
TESTS_FAILED=0
VINBERO_PID_PE1=""
VINBERO_PID_PE2=""
VINBERO_PID_PE3=""

cleanup() {
    rm -f /tmp/vinbero_p2mp_pe*_bum.yaml /tmp/vinbero_p2mp_bum_*.pcap
    for pid_var in VINBERO_PID_PE1 VINBERO_PID_PE2 VINBERO_PID_PE3; do
        local pid="${!pid_var}"
        if [ -n "$pid" ] && ps -p "$pid" > /dev/null 2>&1; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
}
trap cleanup EXIT

# CLI helpers
vbctl_pe1() { ip netns exec "$ns_router1" ${VINBERO_BIN} -s http://127.0.0.1:8082 "$@"; }
vbctl_pe2() { ip netns exec "$ns_router3" ${VINBERO_BIN} -s http://127.0.0.1:8083 "$@"; }
vbctl_pe3() { ip netns exec "$ns_router4" ${VINBERO_BIN} -s http://127.0.0.1:8084 "$@"; }

echo "=========================================="
echo "SRv6 End.DT2 P2MP (L2VPN) Test (BUM_MODE=${BUM_MODE})"
echo "=========================================="
echo ""

# ==========================================
# Start all Vinbero instances
# ==========================================
print_info "Starting PE1 (router1)..."
start_vinbero "$ns_router1" "$(bum_mode_config "${SCRIPT_DIR}/vinbero_pe1.yaml" /tmp/vinbero_p2mp_pe1_bum.yaml)" "/tmp/vinbero_p2mp_pe1.log"
VINBERO_PID_PE1=$VINBERO_LAST_PID
wait_vinbero_ready "$ns_router1" "127.0.0.1:8082" 10

print_info "Starting PE2 (router3)..."
start_vinbero "$ns_router3" "$(bum_mode_config "${SCRIPT_DIR}/vinbero_pe2.yaml" /tmp/vinbero_p2mp_pe2_bum.yaml)" "/tmp/vinbero_p2mp_pe2.log"
VINBERO_PID_PE2=$VINBERO_LAST_PID
wait_vinbero_ready "$ns_router3" "127.0.0.1:8083" 10

print_info "Starting PE3 (router4)..."
start_vinbero "$ns_router4" "$(bum_mode_config "${SCRIPT_DIR}/vinbero_pe3.yaml" /tmp/vinbero_p2mp_pe3_bum.yaml)" "/tmp/vinbero_p2mp_pe3.log"
VINBERO_PID_PE3=$VINBERO_LAST_PID
wait_vinbero_ready "$ns_router4" "127.0.0.1:8084" 10

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
# Phase 5: BUM copy accounting
# ==========================================
echo ""
echo "=========================================="
echo "Phase 5: BUM copies per PE (BUM_MODE=${BUM_MODE})"
echo "=========================================="

stats_counter() {
    local fn="$1" name="$2"
    $fn stats show 2>/dev/null | awk -v n="$name" '$1 == n {print $2; exit}'
}

expect_eq() {
    local desc="$1" got="$2" want="$3"
    if [ "$got" = "$want" ]; then
        print_success "$desc (got $got)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        print_error "$desc (got '$got', want $want)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

expect_nonzero() {
    local desc="$1" got="$2"
    if [ -n "$got" ] && [ "$got" -gt 0 ] 2>/dev/null; then
        print_success "$desc (got $got)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        print_error "$desc (got '$got', want > 0)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

# bum_round <tag> <want_pe2> <want_pe3>: host1 sends one broadcast frame;
# count its copies on P's links towards PE2/PE3 (one SRv6 copy per PE), at
# the local hosts (one each), and back at host1 (none). Captures sit on
# namespaces without XDP so a redirect cannot hide a frame from tcpdump.
bum_round() {
    local tag="$1" want_pe2="$2" want_pe3="$3" pids=() pcap
    local caps=(
        "$ns_router2:${TOPO_NS_PREFIX}rt2rt3:pe2"
        "$ns_router2:${TOPO_NS_PREFIX}rt2rt4:pe3"
        "$ns_host2:${TOPO_NS_PREFIX}h2rt3:host2"
        "$ns_host3:${TOPO_NS_PREFIX}h3rt3:host3"
        "$ns_host4:${TOPO_NS_PREFIX}h4rt4:host4"
        "$ns_host1:${TOPO_NS_PREFIX}h1rt1:host1"
    )
    for c in "${caps[@]}"; do
        IFS=: read -r ns ifc name <<< "$c"
        bum_capture_start "$ns" "$ifc" "/tmp/vinbero_p2mp_bum_${tag}_${name}.pcap"
        pids+=("$CAPTURE_PID")
    done
    sleep 1
    bum_marker_send "$ns_host1" "${TOPO_NS_PREFIX}h1rt1.100" "$tag"
    sleep 1
    kill "${pids[@]}" 2>/dev/null || true
    wait "${pids[@]}" 2>/dev/null || true

    expect_eq "[$tag] SRv6 copies towards PE2" "$(bum_marker_count "/tmp/vinbero_p2mp_bum_${tag}_pe2.pcap" "$tag")" "$want_pe2"
    expect_eq "[$tag] SRv6 copies towards PE3" "$(bum_marker_count "/tmp/vinbero_p2mp_bum_${tag}_pe3.pcap" "$tag")" "$want_pe3"
    expect_eq "[$tag] copies at host2" "$(bum_marker_count "/tmp/vinbero_p2mp_bum_${tag}_host2.pcap" "$tag")" "$want_pe2"
    expect_eq "[$tag] copies at host3" "$(bum_marker_count "/tmp/vinbero_p2mp_bum_${tag}_host3.pcap" "$tag")" "$want_pe2"
    expect_eq "[$tag] copies at host4" "$(bum_marker_count "/tmp/vinbero_p2mp_bum_${tag}_host4.pcap" "$tag")" "$want_pe3"
    # host1's capture holds the one frame it sent; anything more came back.
    expect_eq "[$tag] frames seen at host1 (own frame only)" "$(bum_marker_count "/tmp/vinbero_p2mp_bum_${tag}_host1.pcap" "$tag")" 1
}

vbctl_pe1 stats reset > /dev/null 2>&1 || true
vbctl_pe2 stats reset > /dev/null 2>&1 || true
vbctl_pe3 stats reset > /dev/null 2>&1 || true

bum_round "vbbum-both-1" 1 1

if [ "$BUM_MODE" = "xdp" ]; then
    expect_nonzero "PE1 BUM_XDP_FLOOD" "$(stats_counter vbctl_pe1 BUM_XDP_FLOOD)"
    expect_nonzero "PE1 BUM_EGRESS_TX" "$(stats_counter vbctl_pe1 BUM_EGRESS_TX)"
    expect_eq "PE1 BUM_UPLINK_MISMATCH" "$(stats_counter vbctl_pe1 BUM_UPLINK_MISMATCH)" 0
    expect_eq "PE1 BUM_XDP_FALLBACK" "$(stats_counter vbctl_pe1 BUM_XDP_FALLBACK)" 0
    expect_nonzero "PE2 BUM_XDP_LOCAL_FLOOD" "$(stats_counter vbctl_pe2 BUM_XDP_LOCAL_FLOOD)"
    expect_nonzero "PE3 BUM_XDP_LOCAL_FLOOD" "$(stats_counter vbctl_pe3 BUM_XDP_LOCAL_FLOOD)"
else
    expect_eq "PE1 BUM_XDP_FLOOD stays 0 in tc mode" "$(stats_counter vbctl_pe1 BUM_XDP_FLOOD)" 0
fi

print_info "Runtime peer changes on PE1..."
vbctl_pe1 peer delete --bd-id 100
bum_round "vbbum-none" 0 0
# Re-create in the original order so each peer gets its old slot back (the
# remote MACs learned earlier still point at those slots).
vbctl_pe1 peer create --bd-id 100 --src-addr fc00:1::1 --segments fc00:2::1,fc00:3::3
bum_round "vbbum-pe2" 1 0
vbctl_pe1 peer create --bd-id 100 --src-addr fc00:1::1 --segments fc00:2::1,fc00:4::4
bum_round "vbbum-both-2" 1 1

test_ping_with_counter "$ns_host1" 172.16.100.4 \
  "host1 -> host4 after peer re-create" "${TOPO_NS_PREFIX}h1rt1.100"

# The data plane learns host1's MAC on PE1's AC in both modes; in xdp mode
# the learner also reports it to the control plane (no bridge involved).
host1_mac=$(ip netns exec "$ns_host1" cat "/sys/class/net/${TOPO_NS_PREFIX}h1rt1.100/address")
if vbctl_pe1 fdb list | grep -qi "$host1_mac"; then
    print_success "PE1 fdb_map holds host1's MAC $host1_mac"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    print_error "PE1 fdb_map lacks host1's MAC $host1_mac"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
if [ "$BUM_MODE" = "xdp" ]; then
    if grep -q "XDP learned local MAC.*${host1_mac}" /tmp/vinbero_p2mp_pe1.log; then
        print_success "PE1 control plane received the XDP learning event for $host1_mac"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        print_error "PE1 control plane never saw an XDP learning event for $host1_mac"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
fi

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
