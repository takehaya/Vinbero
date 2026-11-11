#!/bin/bash
# examples/end-dt2m-multihomed/test.sh
# End-to-end test for RFC 9252 Split-Horizon + Static DF election.
#
# Phase C: host1 ARP broadcast must not loop back via the other PE
#          (STATS_SPLIT_HORIZON_TX increments on both PE1 and PE2).
# Phase D: with DF=PE1, a forced BUM into PE2 drops (STATS_NON_DF_DROP).
#
# BUM_MODE=tc (default), xdp or xdp-native (xdp in native XDP) selects
# settings.l2.bum_mode for all PEs. On a kernel where vinberod falls back
# from xdp to tc replication, the xdp run checks the fallback instead.

set -eu
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/test_utils.sh"

check_root

# A state file left by an earlier run would bring its L2 headend circuits back.
rm -f /tmp/vinbero_end_dt2m_multihomed_*_state.json

VINBEROD_BIN="${SCRIPT_DIR}/../../out/bin/vinberod"
VINBERO_BIN="${SCRIPT_DIR}/../../out/bin/vinbero"

NS_H1="mh-host1" NS_H2="mh-host2"
NS_PE1="mh-pe1" NS_PE2="mh-pe2" NS_PE3="mh-pe3" NS_P="mh-p"
BUM_MODE="${BUM_MODE:-tc}"
BIND_PE1="127.0.0.1:18101"
BIND_PE2="127.0.0.1:18102"
BIND_PE3="127.0.0.1:18103"

ESI="01:00:00:00:00:00:00:00:00:01"
PE1_SRC="fc00:1::1"
PE2_SRC="fc00:2::2"
PE3_SRC="fc00:3::3"
HOST1_MAC="02:00:00:00:00:01" # matches setup.sh
VLAN_IF_H1="mh-h1-v100"       # matches setup.sh

VINBERO_PID_PE1="" VINBERO_PID_PE2="" VINBERO_PID_PE3=""
TESTS_PASSED=0
TESTS_FAILED=0

cleanup() {
    rm -f /tmp/vinbero_dt2m_pe*_bum.yaml /tmp/vinbero_dt2m_bum_*.pcap* /tmp/vinbero_dt2m_pe1_base.yaml
    for pid_var in VINBERO_PID_PE1 VINBERO_PID_PE2 VINBERO_PID_PE3; do
        local pid="${!pid_var}"
        # Guard against PID reuse: only kill if the PID is still our vinberod.
        [ -n "$pid" ] && [ "$(ps -o comm= -p "$pid" 2>/dev/null)" = "vinberod" ] && kill "$pid" 2>/dev/null || true
        [ -n "$pid" ] && wait "$pid" 2>/dev/null || true
    done
    rm -rf "$PE1_PIN_DIR"
    umount "$PE1_BPFFS" 2>/dev/null || true
    rmdir "$PE1_BPFFS" 2>/dev/null || true
}
trap cleanup EXIT

# PE1 pins its maps, so its SID and BD peers outlive the daemon; Phase E
# kills it and brings the Ethernet Segment and the L2 headend circuit back
# from its state file. `ip netns exec` mounts a fresh /sys, so the pins go on
# a bpffs of their own.
PE1_BPFFS=/run/vinbero_dt2m_mh_bpffs
PE1_PIN_DIR=$PE1_BPFFS/pe1
mkdir -p "$PE1_BPFFS"
mountpoint -q "$PE1_BPFFS" || mount -t bpf bpf "$PE1_BPFFS"
rm -rf "$PE1_PIN_DIR"
sed -e '/^settings:/a\  pin_maps:' \
    -e '/^settings:/a\    enabled: true' \
    -e "/^settings:/a\\    path: ${PE1_PIN_DIR}" \
    "${SCRIPT_DIR}/vinbero_pe1.yaml" > /tmp/vinbero_dt2m_pe1_base.yaml

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
bum_native_prepare "$NS_H1" "$NS_H2" "$NS_PE1" "$NS_PE2" "$NS_PE3" "$NS_P"
print_info "Launching PE1/PE2/PE3 vinberod in parallel (BUM_MODE=${BUM_MODE})..."
start_vinbero "$NS_PE1" "$(bum_mode_config /tmp/vinbero_dt2m_pe1_base.yaml /tmp/vinbero_dt2m_pe1_bum.yaml)" /tmp/vinbero_dt2m_pe1.log
VINBERO_PID_PE1=$VINBERO_LAST_PID
start_vinbero "$NS_PE2" "$(bum_mode_config "${SCRIPT_DIR}/vinbero_pe2.yaml" /tmp/vinbero_dt2m_pe2_bum.yaml)" /tmp/vinbero_dt2m_pe2.log
VINBERO_PID_PE2=$VINBERO_LAST_PID
start_vinbero "$NS_PE3" "$(bum_mode_config "${SCRIPT_DIR}/vinbero_pe3.yaml" /tmp/vinbero_dt2m_pe3_bum.yaml)" /tmp/vinbero_dt2m_pe3.log
VINBERO_PID_PE3=$VINBERO_LAST_PID

wait_vinbero_ready "$NS_PE1" "$BIND_PE1" 10
wait_vinbero_ready "$NS_PE2" "$BIND_PE2" 10
wait_vinbero_ready "$NS_PE3" "$BIND_PE3" 10
BUM_EFFECTIVE=$(bum_effective_mode /tmp/vinbero_dt2m_pe1.log)
print_info "BUM replication runs in mode ${BUM_EFFECTIVE}"

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
LOOPBACK_PCAP=$(mktemp --suffix=.pcap)
trap 'rm -f "$LOOPBACK_PCAP"' RETURN 2>/dev/null || true
# Zero is only meaningful if tcpdump was listening for the whole window, so
# wait for it before sending.
capture_start "$NS_H1" mh-h1pe2 "$LOOPBACK_PCAP" -Q in "ether src $HOST1_MAC and arp"
TCPDUMP_PID=$CAPTURE_PID
ip netns exec "$NS_H1" ping -c 3 -W 1 -I mh-h1-v100 172.16.100.2 > /dev/null 2>&1 || true
kill "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true

pe1_tx=$(stats_counter vbctl_pe1 SPLIT_HORIZON_TX)
pe2_tx=$(stats_counter vbctl_pe2 SPLIT_HORIZON_TX)
assert_nonzero "PE1 STATS_SPLIT_HORIZON_TX > 0" "${pe1_tx:-0}"
assert_nonzero "PE2 STATS_SPLIT_HORIZON_TX > 0" "${pe2_tx:-0}"

loopback_count=$(capture_count "$LOOPBACK_PCAP")
if [ "$loopback_count" -eq 0 ]; then
    print_success "pcap: 0 self-source ARP frames returned to host1 via PE2 (no loopback)"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    print_error "pcap: $loopback_count loopback ARP frames returned to host1 (split-horizon miss)"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
rm -f "$LOOPBACK_PCAP" "$LOOPBACK_PCAP.log"

print_info "Reachability: host1 -> host2 (unicast overlay)"
if ip netns exec "$NS_H1" ping -c 3 -W 2 -I mh-h1-v100 172.16.100.2 > /dev/null 2>&1; then
    print_success "host1 -> host2 ping succeeded"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    print_error "host1 -> host2 ping failed"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

assert_eq() {
    local desc="$1" got="$2" want="$3"
    if [ "$got" = "$want" ]; then
        print_success "$desc (got $got)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        print_error "$desc (got '${got}', want $want)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

# One broadcast from host1 reaches PE1 and PE2 (the shared CE floods both
# legs). Each PE must send exactly one SRv6 copy, to PE3 only: the peer on
# ES-1 is split-horizon filtered. Count on P, which runs no XDP.
print_info "Counting the SRv6 copies of one host1 broadcast on P..."
TAG="vbbum-mh-1"
pids=()
for ifc in mh-ppe1 mh-ppe2 mh-ppe3; do
    capture_start "$NS_P" "$ifc" "/tmp/vinbero_dt2m_bum_${ifc}.pcap"
    pids+=("$CAPTURE_PID")
done
sleep 1
bum_marker_send "$NS_H1" "$VLAN_IF_H1" "$TAG"
sleep 1
kill "${pids[@]}" 2>/dev/null || true
wait "${pids[@]}" 2>/dev/null || true
assert_eq "SRv6 copies towards PE3 (one from PE1, one from PE2)" \
    "$(bum_marker_count /tmp/vinbero_dt2m_bum_mh-ppe3.pcap "$TAG")" 2
# Each PE's uplink capture also carries the copy it sends to PE3, so the
# frames seen there must be exactly that one: nothing came back from the
# other ES-1 PE.
assert_eq "frames on P-PE1 (PE1's own copy only, none towards PE1)" \
    "$(bum_marker_count /tmp/vinbero_dt2m_bum_mh-ppe1.pcap "$TAG")" 1
assert_eq "frames on P-PE2 (PE2's own copy only, none towards PE2)" \
    "$(bum_marker_count /tmp/vinbero_dt2m_bum_mh-ppe2.pcap "$TAG")" 1

if [ "$BUM_EFFECTIVE" = "tc-fallback" ]; then
    assert_nonzero "PE1 BUM_XDP_FALLBACK > 0 (tc replication in place of xdp)" "$(stats_counter vbctl_pe1 BUM_XDP_FALLBACK)"
    assert_eq "PE1 BUM_XDP_FLOOD" "$(stats_counter vbctl_pe1 BUM_XDP_FLOOD)" 0
fi
if [ "$BUM_EFFECTIVE" = "xdp" ]; then
    assert_nonzero "PE1 BUM_XDP_FLOOD > 0" "$(stats_counter vbctl_pe1 BUM_XDP_FLOOD)"
    assert_nonzero "PE1 BUM_EGRESS_TX > 0" "$(stats_counter vbctl_pe1 BUM_EGRESS_TX)"
    assert_nonzero "PE2 BUM_EGRESS_TX > 0" "$(stats_counter vbctl_pe2 BUM_EGRESS_TX)"
    assert_eq "PE1 BUM_XDP_FALLBACK" "$(stats_counter vbctl_pe1 BUM_XDP_FALLBACK)" 0
    if grep -q "XDP learned local MAC.*${HOST1_MAC}" /tmp/vinbero_dt2m_pe1.log; then
        print_success "PE1 control plane received the XDP learning event for host1"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        print_error "PE1 control plane never saw an XDP learning event for host1"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
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

# A broadcast from host2 reaches host1 exactly once: through PE2 (the DF),
# never through PE1. Captured inbound on host1's two legs.
TAG="vbbum-mh-df"
pids=()
for ifc in mh-h1pe1 mh-h1pe2; do
    capture_start "$NS_H1" "$ifc" "/tmp/vinbero_dt2m_bum_${ifc}.pcap" -Q in
    pids+=("$CAPTURE_PID")
done
sleep 1
bum_marker_send "$NS_H2" mh-h2pe3.100 "$TAG"
sleep 1
kill "${pids[@]}" 2>/dev/null || true
wait "${pids[@]}" 2>/dev/null || true
assert_eq "host1 copies via PE1 (non-DF)" "$(bum_marker_count /tmp/vinbero_dt2m_bum_mh-h1pe1.pcap "$TAG")" 0
assert_eq "host1 copies via PE2 (DF)" "$(bum_marker_count /tmp/vinbero_dt2m_bum_mh-h1pe2.pcap "$TAG")" 1

if [ "$BUM_EFFECTIVE" = "xdp" ]; then
    # The DF floods host2's BUM to host1 from XDP, not through br100.
    assert_nonzero "PE2 BUM_XDP_LOCAL_FLOOD > 0 (DF floods from XDP)" \
        "$(stats_counter vbctl_pe2 BUM_XDP_LOCAL_FLOOD)"
fi

# ================================================
# Phase E: PE1 crashes and comes back
# ================================================
# Nothing is configured again. ES-1, with the DF set above, and the L2
# headend circuit come back from PE1's state file; esi_map is not pinned,
# and the pinned headend_l2_map goes while PE1 is down, so neither can come
# from anywhere else. The End.DT2M SID and the BD peers come from the pinned
# maps.
echo ""
echo "=========================================="
echo "Phase E: PE1 killed and started again"
echo "=========================================="
kill -KILL "$VINBERO_PID_PE1" 2>/dev/null || true
wait "$VINBERO_PID_PE1" 2>/dev/null || true
rm -f "$PE1_PIN_DIR/headend_l2_map"
start_vinbero "$NS_PE1" "$(bum_mode_config /tmp/vinbero_dt2m_pe1_base.yaml /tmp/vinbero_dt2m_pe1_bum.yaml)" \
    /tmp/vinbero_dt2m_pe1_restart.log
VINBERO_PID_PE1=$VINBERO_LAST_PID
wait_vinbero_ready "$NS_PE1" "$BIND_PE1" 15
if grep -q "Ethernet Segments restored from the state file" /tmp/vinbero_dt2m_pe1_restart.log &&
    vbctl_pe1 es list | grep -F "$ESI" | grep -qF "$PE2_SRC"; then
    print_success "PE1 restored ES-1 with PE2 as its DF"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    print_error "PE1 did not restore ES-1 with its DF"
    vbctl_pe1 es list || true
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
if vbctl_pe1 --json hl2 list | grep -q '"esi": "'"$ESI"'"'; then
    print_success "PE1 restored its L2 headend circuit on ES-1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    print_error "PE1 did not restore its L2 headend circuit on ES-1"
    vbctl_pe1 hl2 list || true
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# PE1 is still the non-DF: host2's broadcast reaches host1 through PE2 only.
TAG="vbbum-mh-restart-df"
pids=()
for ifc in mh-h1pe1 mh-h1pe2; do
    capture_start "$NS_H1" "$ifc" "/tmp/vinbero_dt2m_bum_${ifc}.pcap" -Q in
    pids+=("$CAPTURE_PID")
done
sleep 1
bum_marker_send "$NS_H2" mh-h2pe3.100 "$TAG"
sleep 1
kill "${pids[@]}" 2>/dev/null || true
wait "${pids[@]}" 2>/dev/null || true
assert_eq "after the restart: host1 copies via PE1 (non-DF)" "$(bum_marker_count /tmp/vinbero_dt2m_bum_mh-h1pe1.pcap "$TAG")" 0
assert_eq "after the restart: host1 copies via PE2 (DF)" "$(bum_marker_count /tmp/vinbero_dt2m_bum_mh-h1pe2.pcap "$TAG")" 1
assert_nonzero "after the restart: PE1 NON_DF_DROP > 0" "$(stats_counter vbctl_pe1 NON_DF_DROP)"

# Split horizon still holds: PE1 sends host1's broadcast to PE3 only.
TAG="vbbum-mh-restart-sh"
capture_start "$NS_P" mh-ppe1 "/tmp/vinbero_dt2m_bum_mh-ppe1.pcap"
pid=$CAPTURE_PID
sleep 1
bum_marker_send "$NS_H1" "$VLAN_IF_H1" "$TAG"
sleep 1
kill "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true
assert_eq "after the restart: frames on P-PE1 (PE1's copy to PE3 only)" \
    "$(bum_marker_count /tmp/vinbero_dt2m_bum_mh-ppe1.pcap "$TAG")" 1

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
