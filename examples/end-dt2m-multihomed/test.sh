#!/bin/bash
# examples/end-dt2m-multihomed/test.sh
# End-to-end test for RFC 9252 Split-Horizon + Static DF election.
#
# Phase C: host1 ARP broadcast must not loop back via the other PE
#          (STATS_SPLIT_HORIZON_TX increments on both PE1 and PE2).
# Phase D: with DF=PE1, a forced BUM into PE2 drops (STATS_NON_DF_DROP).

set -eu
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/test_utils.sh"

check_root

VINBEROD_BIN="${SCRIPT_DIR}/../../out/bin/vinberod"
VINBERO_BIN="${SCRIPT_DIR}/../../out/bin/vinbero"

NS_H1="mh-host1" NS_H2="mh-host2"
NS_PE1="mh-pe1" NS_PE2="mh-pe2" NS_PE3="mh-pe3"
BIND_PE1="127.0.0.1:18101"
BIND_PE2="127.0.0.1:18102"
BIND_PE3="127.0.0.1:18103"

ESI="01:00:00:00:00:00:00:00:00:01"
PE1_SRC="fc00:1::1"
PE2_SRC="fc00:2::2"
PE3_SRC="fc00:3::3"

VINBERO_PID_PE1="" VINBERO_PID_PE2="" VINBERO_PID_PE3=""
TESTS_PASSED=0
TESTS_FAILED=0

cleanup() {
    for pid_var in VINBERO_PID_PE1 VINBERO_PID_PE2 VINBERO_PID_PE3; do
        local pid="${!pid_var}"
        [ -n "$pid" ] && ps -p "$pid" > /dev/null 2>&1 && kill "$pid" 2>/dev/null || true
        [ -n "$pid" ] && wait "$pid" 2>/dev/null || true
    done
}
trap cleanup EXIT

vbctl_pe1() { ip netns exec "$NS_PE1" "${VINBERO_BIN}" -s "http://${BIND_PE1}" "$@"; }
vbctl_pe2() { ip netns exec "$NS_PE2" "${VINBERO_BIN}" -s "http://${BIND_PE2}" "$@"; }
vbctl_pe3() { ip netns exec "$NS_PE3" "${VINBERO_BIN}" -s "http://${BIND_PE3}" "$@"; }

# stats_counter <vbctl_fn> <counter_name>
stats_counter() {
    local fn="$1" name="$2"
    $fn stats show 2>/dev/null | awk -v n="$name" '$1 == n {print $2; exit}'
}

assert_nonzero() {
    local desc="$1" val="$2"
    if [ -n "$val" ] && [ "$val" -gt 0 ] 2>/dev/null; then
        print_success "$desc (got $val)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        print_error "$desc (got '${val}', want > 0)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

# ================================================
# Start vinberod
# ================================================
print_info "Launching PE1/PE2/PE3 vinberod in parallel..."
start_vinbero "$NS_PE1" "${SCRIPT_DIR}/vinbero_pe1.yaml" /tmp/vinbero_dt2m_pe1.log
VINBERO_PID_PE1=$VINBERO_LAST_PID
start_vinbero "$NS_PE2" "${SCRIPT_DIR}/vinbero_pe2.yaml" /tmp/vinbero_dt2m_pe2.log
VINBERO_PID_PE2=$VINBERO_LAST_PID
start_vinbero "$NS_PE3" "${SCRIPT_DIR}/vinbero_pe3.yaml" /tmp/vinbero_dt2m_pe3.log
VINBERO_PID_PE3=$VINBERO_LAST_PID

wait_vinbero_ready "$NS_PE1" "$BIND_PE1" 10
wait_vinbero_ready "$NS_PE2" "$BIND_PE2" 10
wait_vinbero_ready "$NS_PE3" "$BIND_PE3" 10

# ================================================
# Configure ES / BdPeers / HeadendL2 / SID
# ================================================
echo ""
print_info "Configuring ES-1 (local-attached on PE1 + PE2)..."
vbctl_pe1 es create --esi "$ESI" --local-attached --local-pe "$PE1_SRC" --mode ALL_ACTIVE
vbctl_pe2 es create --esi "$ESI" --local-attached --local-pe "$PE2_SRC" --mode ALL_ACTIVE
# PE3 registers ES-1 as remote (not local-attached) so its BdPeer ESI is known.
vbctl_pe3 es create --esi "$ESI" --mode ALL_ACTIVE

print_info "Configuring HeadendL2 + BdPeers..."
# PE1 End.DT2M endpoint (flood BUM into br100 after split-horizon/DF gate)
vbctl_pe1 sid create --trigger-prefix "${PE1_SRC}/128" --action END_DT2M --bd-id 100 --bridge-name br100
# PE1 -> PE2 (ES-1), PE3 (--esi ties this BD to ES-1 for source split-horizon & DF check)
vbctl_pe1 hl2 create --interface mh-pe1h1 --vlan-id 100 \
    --src-addr "$PE1_SRC" --segments "fc00:99::1,$PE2_SRC" --bd-id 100 --esi "$ESI"
vbctl_pe1 peer create --bd-id 100 --src-addr "$PE1_SRC" --segments "fc00:99::1,$PE2_SRC" --esi "$ESI"
vbctl_pe1 peer create --bd-id 100 --src-addr "$PE1_SRC" --segments "fc00:99::1,$PE3_SRC"

# PE2 End.DT2M endpoint
vbctl_pe2 sid create --trigger-prefix "${PE2_SRC}/128" --action END_DT2M --bd-id 100 --bridge-name br100
# PE2 -> PE1 (ES-1), PE3
vbctl_pe2 hl2 create --interface mh-pe2h1 --vlan-id 100 \
    --src-addr "$PE2_SRC" --segments "fc00:99::1,$PE1_SRC" --bd-id 100 --esi "$ESI"
vbctl_pe2 peer create --bd-id 100 --src-addr "$PE2_SRC" --segments "fc00:99::1,$PE1_SRC" --esi "$ESI"
vbctl_pe2 peer create --bd-id 100 --src-addr "$PE2_SRC" --segments "fc00:99::1,$PE3_SRC"

# PE3 egress: End.DT2M -> bridge br100
vbctl_pe3 sid create --trigger-prefix "${PE3_SRC}/128" --action END_DT2M --bd-id 100 --bridge-name br100
# Return path from PE3 to PE1 (unicast) and PE2 (unicast, shared ES-1 endpoint)
vbctl_pe3 hl2 create --interface mh-pe3h2 --vlan-id 100 \
    --src-addr "$PE3_SRC" --segments "fc00:99::1,$PE1_SRC" --bd-id 100
vbctl_pe3 peer create --bd-id 100 --src-addr "$PE3_SRC" --segments "fc00:99::1,$PE1_SRC" --esi "$ESI"
vbctl_pe3 peer create --bd-id 100 --src-addr "$PE3_SRC" --segments "fc00:99::1,$PE2_SRC" --esi "$ESI"

sleep 1
print_success "PE1/PE2/PE3 configured"

# Reset counters so each phase is measured from zero.
vbctl_pe1 stats reset > /dev/null
vbctl_pe2 stats reset > /dev/null
vbctl_pe3 stats reset > /dev/null

# ================================================
# Phase C: Split-Horizon TX (both PEs see the same broadcast)
# ================================================
echo ""
echo "=========================================="
echo "Phase C: Split-Horizon TX filter"
echo "=========================================="
print_info "Sending pings to trigger ARP broadcast from host1..."
# Capture inbound traffic on the PE2 side of host1's veth. Any ARP whose
# sender is host1's own MAC arriving INbound is a loopback (split-horizon
# miss); split-horizon should make this count zero.
HOST1_MAC_ADDR=02:00:00:00:00:01
LOOPBACK_PCAP=/tmp/dt2m_loopback.pcap
ip netns exec "$NS_H1" timeout 4 tcpdump -i mh-h1pe2 -Q in -p -nn -w "$LOOPBACK_PCAP" \
    "ether src $HOST1_MAC_ADDR and arp" > /dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 0.3
ip netns exec "$NS_H1" ping -c 3 -W 1 -I mh-h1-v100 172.16.100.2 > /dev/null 2>&1 || true
wait "$TCPDUMP_PID" 2>/dev/null || true

pe1_tx=$(stats_counter vbctl_pe1 SPLIT_HORIZON_TX)
pe2_tx=$(stats_counter vbctl_pe2 SPLIT_HORIZON_TX)
assert_nonzero "PE1 STATS_SPLIT_HORIZON_TX > 0" "${pe1_tx:-0}"
assert_nonzero "PE2 STATS_SPLIT_HORIZON_TX > 0" "${pe2_tx:-0}"

loopback_count=$(ip netns exec "$NS_H1" tcpdump -nn -r "$LOOPBACK_PCAP" 2>/dev/null | wc -l)
if [ "$loopback_count" -eq 0 ]; then
    print_success "pcap: 0 self-source ARP frames returned to host1 via PE2 (no loopback)"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    print_error "pcap: $loopback_count loopback ARP frames returned to host1 (split-horizon miss)"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
rm -f "$LOOPBACK_PCAP"

print_info "Reachability: host1 -> host2 (unicast overlay)"
if ip netns exec "$NS_H1" ping -c 3 -W 2 -I mh-h1-v100 172.16.100.2 > /dev/null 2>&1; then
    print_success "host1 -> host2 ping succeeded"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    print_error "host1 -> host2 ping failed"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# ================================================
# Phase D: Static DF election
# ================================================
echo ""
echo "=========================================="
echo "Phase D: Static DF election"
echo "=========================================="
print_info "Electing PE1 as DF for ES-1..."
vbctl_pe1 es df-set --esi "$ESI" --pe "$PE1_SRC"
vbctl_pe2 es df-set --esi "$ESI" --pe "$PE1_SRC"

vbctl_pe2 stats reset > /dev/null

print_info "Sending BUM from host2 so PE3 floods to both PE1 and PE2..."
ip netns exec "$NS_H2" ping -c 3 -W 1 -I mh-h2pe3.100 172.16.100.1 > /dev/null 2>&1 || true
sleep 1

pe2_nondf=$(stats_counter vbctl_pe2 NON_DF_DROP)
assert_nonzero "PE2 NON_DF_DROP > 0 (PE1 is DF)" "${pe2_nondf:-0}"

print_info "Swapping DF to PE2..."
vbctl_pe1 es df-set --esi "$ESI" --pe "$PE2_SRC"
vbctl_pe2 es df-set --esi "$ESI" --pe "$PE2_SRC"
vbctl_pe1 stats reset > /dev/null

ip netns exec "$NS_H2" ping -c 3 -W 1 -I mh-h2pe3.100 172.16.100.1 > /dev/null 2>&1 || true
sleep 1

pe1_nondf=$(stats_counter vbctl_pe1 NON_DF_DROP)
assert_nonzero "PE1 NON_DF_DROP > 0 (PE2 is DF)" "${pe1_nondf:-0}"

# ================================================
# Summary
# ================================================
echo ""
echo "=========================================="
echo "Summary: passed=$TESTS_PASSED failed=$TESTS_FAILED"
echo "=========================================="
echo ""
print_info "PE1 stats:"
vbctl_pe1 stats show || true
print_info "PE2 stats:"
vbctl_pe2 stats show || true
print_info "PE3 stats:"
vbctl_pe3 stats show || true

[ "$TESTS_FAILED" -eq 0 ]
