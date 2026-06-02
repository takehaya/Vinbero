#!/bin/bash
# examples/gtp6-drop-in/test.sh
# Test End.M.GTP6.D.Di (Drop-In) with Vinbero XDP

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/test_utils.sh"

check_root

VINBEROD_BIN="${SCRIPT_DIR}/../../out/bin/vinberod"
VINBERO_BIN="${SCRIPT_DIR}/../../out/bin/vinbero"

export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-gtdi-}"
ns_host1="${TOPO_NS_PREFIX}host1"
ns_router1="${TOPO_NS_PREFIX}router1"

TESTS_PASSED=0
TESTS_FAILED=0
PIDS=""

cleanup() {
    for pid in $PIDS; do
        kill $pid 2>/dev/null || true
        wait $pid 2>/dev/null || true
    done
}
trap cleanup EXIT

echo "=========================================="
echo "SRv6 GTP-U/IPv6 Drop-In (End.M.GTP6.D.Di) Test"
echo "=========================================="
echo ""

print_info "Starting Vinbero on $ns_router1..."
start_vinbero "$ns_router1" "${SCRIPT_DIR}/vinbero_router1.yaml" "/tmp/vinbero_gtdi_r1.log"
PIDS="$VINBERO_LAST_PID $PIDS"
wait_vinbero_ready "$ns_router1" "127.0.0.1:8082" 10

# Drop-In does not use args_offset (no Args.Mob.Session encoding)
print_info "Registering End.M.GTP6.D.Di on router1..."
ip netns exec "$ns_router1" ${VINBERO_BIN} -s http://127.0.0.1:8082 sid create \
  --trigger-prefix fc00:1::1/128 --action END_M_GTP6_D_DI > /dev/null

print_success "Entry registered"
TESTS_PASSED=$((TESTS_PASSED + 1))

ip netns exec "$ns_router1" ${VINBERO_BIN} -s http://127.0.0.1:8082 sid list
echo ""

# Phase 2: data-plane test. End.M.GTP6.D.Di recognises a GTP-U tunnel carried
# inside an SRv6 packet and hands it to the kernel SRv6 stack *unmodified*
# (XDP_PASS, no rewrite -- SL/DA unchanged). There is therefore no transformed
# packet to capture; instead we read the per-slot invocation counter, which only
# increments when the Di tail-call program actually runs on a matched packet.
echo "=========================================="
echo "Phase 2: SRv6+GTP-U Data-plane Test"
echo "=========================================="

if ! python3 -c "from scapy.all import IPv6, UDP, IP, ICMP, send, conf, raw; from scapy.contrib.gtp import GTPHeader, GTPPDUSessionContainer; from scapy.layers.inet6 import IPv6ExtHdrSegmentRouting" 2>/dev/null; then
    print_info "scapy not installed, skipping data-plane test"
    print_info "Install with: apt-get install -y python3-scapy"
    print_success "Entry registration test passed (data-plane test skipped)"
    exit 0
fi

# End.M.GTP6.D.Di per-slot packet counter, via the shipped CLI (vbctl stats slot
# show prints one row per non-zero tail-call slot: MAP SLOT NAME PACKETS BYTES).
# Match by name so it is robust to slot renumbering; echoes nothing (-> 0) until
# the slot has been hit.
di_slot_count() {
    ip netns exec "$ns_router1" ${VINBERO_BIN} -s http://127.0.0.1:8082 \
        stats slot show --type endpoint 2>/dev/null \
        | awk '$3 == "End.M.GTP6.D.Di" { print $4 }'
}

before=$(di_slot_count); before=${before:-0}  # slot absent until first hit -> 0
print_info "Sending SRv6+GTP-U to the Di SID (fc00:1::1)..."
ip netns exec "$ns_host1" python3 "${SCRIPT_DIR}/send_srv6_gtpu.py" \
    --sid fc00:1::1 --next-seg fc00:3::3 --teid 0xAABBCCDD --qfi 5 --count 3
sleep 1
after=$(di_slot_count); after=${after:-0}

# The counter increments only when the SRv6 localsid dispatch matched the Di SID
# and ran the Di tail-call program on the packet -- it proves the data-plane path
# reached End.M.GTP6.D.Di. (Di is a no-op XDP_PASS, so there is no transform or
# drop to observe beyond this; the slot delta is the signal.)
print_info "End.M.GTP6.D.Di invocations: ${before} -> ${after}"
if [ "${after:-0}" -gt "${before:-0}" ]; then
    print_success "End.M.GTP6.D.Di PASS: the Di program ran on $((after - before)) matched SRv6 packets and passed them to the kernel"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    print_error "End.M.GTP6.D.Di FAIL: the Di program did not run on the sent packets (delta $((after - before)))"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

echo ""
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo "Passed: $TESTS_PASSED"
echo "Failed: $TESTS_FAILED"
if [ $TESTS_FAILED -gt 0 ]; then
    print_error "Some tests failed"
    exit 1
else
    print_success "All tests passed!"
    exit 0
fi
