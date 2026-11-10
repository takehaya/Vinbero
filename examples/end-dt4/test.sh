#!/bin/bash
# examples/end-dt4/test.sh
# Test End.DT4 with Vinbero XDP (VRF-aware FIB lookup)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/test_utils.sh"

check_root

VINBEROD_BIN="${SCRIPT_DIR}/../../out/bin/vinberod"
VINBERO_BIN="${SCRIPT_DIR}/../../out/bin/vinbero"
VINBERO_CONFIG="${SCRIPT_DIR}/vinbero_router3.yaml"

export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-dt4-}"
ns_host1="${TOPO_NS_PREFIX}host1"
ns_host2="${TOPO_NS_PREFIX}host2"
ns_router3="${TOPO_NS_PREFIX}router3"

TESTS_PASSED=0
TESTS_FAILED=0
VINBERO_PID=""

cleanup() {
    # Guard against PID reuse: only kill if the PID is still our vinberod.
    if [ -n "$VINBERO_PID" ] && [ "$(ps -o comm= -p "$VINBERO_PID" 2>/dev/null)" = "vinberod" ]; then
        kill "$VINBERO_PID" 2>/dev/null || true
        wait "$VINBERO_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# check <description> <command...>: tallies a PASS when the command succeeds.
check() {
    local desc=$1; shift
    if "$@" > /dev/null 2>&1; then
        print_success "$desc: PASS"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        print_error "$desc: FAIL"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

# check_not <description> <command...>: tallies a PASS when the command fails.
check_not() {
    local desc=$1; shift
    if "$@" > /dev/null 2>&1; then
        print_error "$desc: FAIL"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    else
        print_success "$desc: PASS"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    fi
}

# counters: prints "<End.DT4 runs> <XDP_PASS> <XDP_DROP>" from router3's
# slot and action counters (needs settings.enable_stats), or nothing when
# they cannot be read. End.DT4 is endpoint slot 8.
counters() {
    local api=(ip netns exec "$ns_router3" "$VINBERO_BIN" -s http://127.0.0.1:8082 --json)
    local dt4 pass drop
    dt4=$("${api[@]}" stats slot show --type endpoint --all 2>/dev/null |
        jq -er '.[] | select(.slot == 8) | (.packets // 0)' 2>/dev/null) || return 0
    pass=$("${api[@]}" stats show 2>/dev/null |
        jq -er '.[] | select(.name == "PASS") | (.packets // 0)' 2>/dev/null) || return 0
    drop=$("${api[@]}" stats show 2>/dev/null |
        jq -er '.[] | select(.name == "DROP") | (.packets // 0)' 2>/dev/null) || return 0
    echo "$dt4 $pass $drop"
}

# check_counters <description> <condition> <command...>: runs the command
# and tallies whether the counter deltas it caused satisfy the arithmetic
# condition, which can use dt4, pass and drop (e.g. 'dt4 == 0 && pass >= 3').
# Unreadable counters are a FAIL, not an abort.
check_counters() {
    local desc=$1 cond=$2; shift 2
    print_info "Testing: $desc"
    local before after
    before=$(counters)
    "$@" > /dev/null 2>&1 || true
    after=$(counters)
    if [ -z "$before" ] || [ -z "$after" ]; then
        print_error "$desc: FAIL (counters unreadable)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 0
    fi
    local b0 b1 b2 a0 a1 a2
    read -r b0 b1 b2 <<< "$before"
    read -r a0 a1 a2 <<< "$after"
    local dt4=$((a0 - b0)) pass=$((a1 - b1)) drop=$((a2 - b2))
    local seen="End.DT4 runs $dt4, XDP_PASS +$pass, XDP_DROP +$drop"
    # The condition names dt4, pass and drop, which (( )) reads as the locals.
    if (( $cond )); then
        print_success "$desc: PASS ($seen)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        print_error "$desc: FAIL ($seen)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

echo "=========================================="
echo "SRv6 End.DT4 (VRF) Test"
echo "=========================================="
echo ""

# Phase 1: Test with Linux native SRv6
echo "=========================================="
echo "Phase 1: Linux Native SRv6 (Baseline)"
echo "=========================================="

print_info "Linux native End.DT4 vrftable 100 is configured on $ns_router3"

test_ping_with_counter "$ns_host1" 172.0.2.1 "host1 -> host2 (Linux native End.DT4 VRF)"
test_ping_with_counter "$ns_host2" 172.0.1.1 "host2 -> host1 (Linux native)"

print_info "Removing Linux native End.DT4 route from $ns_router3..."
ip netns exec "$ns_router3" ip -6 route del local fc00:3::3/128 2>/dev/null || true

echo ""

# Phase 2: Test with Vinbero XDP End.DT4
echo "=========================================="
echo "Phase 2: Vinbero XDP End.DT4 (VRF)"
echo "=========================================="

print_info "Starting Vinbero on $ns_router3..."
# A previous run's state would adopt vrf100 at start (Phase 4 does that).
rm -f /tmp/vinbero_end_dt4_state.json
start_vinbero "$ns_router3" "${VINBERO_CONFIG}" "/tmp/vinbero_end_dt4_test.log"
VINBERO_PID=$VINBERO_LAST_PID
wait_vinbero_ready "$ns_router3" "127.0.0.1:8082" 10

print_info "Registering SidFunction (End.DT4) entry with vrf_name=vrf100..."
ip netns exec "$ns_router3" ${VINBERO_BIN} -s http://127.0.0.1:8082 sid create \
  --trigger-prefix fc00:3::3/128 --action END_DT4 --vrf-name vrf100 > /dev/null

print_success "SidFunction (End.DT4) entry registered"

sleep 1

# Pre-resolve NDP between routers (required for bpf_fib_lookup)
print_info "Pre-resolving NDP..."
ip netns exec "$ns_router3" ping6 -c 1 -W 1 fc00:23::2 > /dev/null 2>&1 || true

test_ping_with_counter "$ns_host1" 172.0.2.1 "host1 -> host2 (Vinbero XDP End.DT4 VRF)"
test_ping_with_counter "$ns_host2" 172.0.1.1 "host2 -> host1 (return path, native baseline)"

echo ""

# Phase 3: a tenant AC cannot address the SID
echo "=========================================="
echo "Phase 3: SID from a tenant AC"
echo "=========================================="

# Only Vinbero may hold the SID: a kernel seg6local route for it would
# decapsulate whatever XDP passes on.
check_not "no kernel route for the SID left on $ns_router3" \
  sh -c "ip netns exec '$ns_router3' ip -6 route show table all | grep -q 'fc00:3::3.*seg6local'"

# host2 encapsulates its traffic to host1 straight to router3's End.DT4 SID,
# the way a tenant host would try to reach a SID directly. The outer packet
# enters router3 on the host-facing port, untagged or with a VLAN 5 tag
# that has no AC.
print_info "Steering host2 -> host1 straight to the SID fc00:3::3..."
h2if="${TOPO_NS_PREFIX}h2rt3"
rt3h2_mac=$(ip netns exec "$ns_router3" cat "/sys/class/net/${TOPO_NS_PREFIX}rt3h2/address")
ip netns exec "$ns_host2" ip -6 addr add fc00:99::2/128 dev lo
ip netns exec "$ns_host2" ip -6 route add fc00:3::3/128 dev "$h2if"
ip netns exec "$ns_host2" ip -6 neigh replace fc00:3::3 lladdr "$rt3h2_mac" dev "$h2if" nud permanent
ip netns exec "$ns_host2" ip route add 172.0.1.1/32 encap seg6 mode encap segs fc00:3::3 dev "$h2if"
ip netns exec "$ns_host2" ethtool -K "$h2if" txvlan off > /dev/null 2>&1 || true
ip netns exec "$ns_host2" ip link add link "$h2if" name "$h2if.5" type vlan id 5
ip netns exec "$ns_host2" ip link set "$h2if.5" up
ip netns exec "$ns_host2" ip -6 neigh replace fc00:3::3 lladdr "$rt3h2_mac" dev "$h2if.5" nud permanent
send_untagged() { ip netns exec "$ns_host2" ping -c 3 -W 1 172.0.1.1; }
send_tagged() {
    ip netns exec "$ns_host2" ip -6 route replace fc00:3::3/128 dev "$h2if.5"
    ip netns exec "$ns_host2" ping -c 3 -W 1 172.0.1.1
    ip netns exec "$ns_host2" ip -6 route replace fc00:3::3/128 dev "$h2if"
}

# Without an AC the port is in the global VRF, and End.DT4 decapsulates
# host2's packets. (They go no further: vrf100 reaches host1 through a
# kernel seg6 route, which the XDP FIB lookup does not follow.)
check_counters "host2 -> SID with the port in the global VRF (End.DT4 runs)" \
  'dt4 >= 3' send_untagged

print_info "Classifying the host-facing port into vrf100 (vbctl vrf ac-add)..."
ip netns exec "$ns_router3" "$VINBERO_BIN" -s http://127.0.0.1:8082 vrf ac-add \
  --vrf vrf100 --interface "${TOPO_NS_PREFIX}rt3h2" > /dev/null

# From the tenant AC the SID table is not looked up: the packets reach XDP,
# miss the headend table and are passed to the kernel without End.DT4.
check_counters "host2 -> SID from the vrf100 AC (passed on, End.DT4 does not run)" \
  'dt4 == 0 && pass >= 3' send_untagged
# A tag with no AC on a port whose untagged side is a tenant AC is not
# underlay: with no circuit configured for it, it is dropped before L3.
check_counters "host2 -> SID with an unknown VLAN tag (dropped, End.DT4 does not run)" \
  'dt4 == 0 && drop >= 3' send_tagged

ip netns exec "$ns_host2" ip route del 172.0.1.1/32
ip netns exec "$ns_host2" ip link del "$h2if.5"
# The uplink has no AC, so it stays in the global VRF and keeps reaching the SID.
test_ping_with_counter "$ns_host1" 172.0.2.1 "host1 -> host2 with the AC (SID from the underlay)"
test_ping_with_counter "$ns_host2" 172.0.1.1 "host2 -> host1 with the AC (ordinary tenant path)"

echo ""

# Phase 4: the kernel side of the VRF
echo "=========================================="
echo "Phase 4: the kernel VRF table"
echo "=========================================="

# host2 now encapsulates its traffic to host1 to router1's End.DX4 SID
# (fc00:1::1), a remote PE's SID that router3 has only in its main table.
# The packet enters router3 on the enslaved vrf100 port, XDP has no entry
# for it and passes it on, and the kernel looks it up in vrf100's table.
print_info "Steering host2 -> host1 to the remote SID fc00:1::1..."
ip netns exec "$ns_host2" ip -6 route replace fc00:1::1/128 dev "$h2if"
ip netns exec "$ns_host2" ip -6 neigh replace fc00:1::1 lladdr "$rt3h2_mac" dev "$h2if" nud permanent
ip netns exec "$ns_host2" ip route replace 172.0.1.1/32 encap seg6 mode encap segs fc00:1::1 dev "$h2if"

# vrf100 was made with `ip link add`, so its table has no route of last
# resort yet and a miss goes on to the main table.
test_ping_with_counter "$ns_host2" 172.0.1.1 \
  "host2 -> remote SID before Vinbero manages vrf100 (falls through to the main table)"

print_info "Adopting vrf100 (vbctl vrf create)..."
ip netns exec "$ns_router3" "$VINBERO_BIN" -s http://127.0.0.1:8082 vrf create \
  --name vrf100 --table-id 100 > /dev/null
for af in 4 6; do
    check "vrf100's table ends in an IPv$af unreachable default" \
      sh -c "ip netns exec '$ns_router3' ip -$af route show table 100 | grep -q '^unreachable default'"
done

check_not "host2 -> remote SID with vrf100 managed (stopped in the VRF table)" \
  ip netns exec "$ns_host2" ping -c 3 -W 1 172.0.1.1
ip netns exec "$ns_host2" ip route del 172.0.1.1/32

# The return path's kernel seg6 route in table 100 needs the same main-table
# lookup for its outer header, so Vinbero takes over the encapsulation. The
# packet comes from the vrf100 AC, and its outer header is looked up in the
# main table.
print_info "Encapsulating host2 -> host1 with Vinbero (hv4 create)..."
ip netns exec "$ns_router3" "$VINBERO_BIN" -s http://127.0.0.1:8082 hv4 create \
  --trigger-prefix 172.0.1.0/24 --src-addr fc00:3::3 --segments fc00:2::2,fc00:1::1 > /dev/null
test_ping_with_counter "$ns_host2" 172.0.1.1 "host2 -> host1 (Vinbero H.Encaps from the vrf100 AC)"
test_ping_with_counter "$ns_host1" 172.0.2.1 "host1 -> host2 (End.DT4 into the managed vrf100)"

# The encapsulation's underlay next hop (router2, through a static route) is
# a neighbour Vinbero keeps resolved. Without that, a missing entry would
# never come back: XDP hands the packet to the kernel to resolve it, and the
# kernel drops it at vrf100's unreachable default before soliciting. Only
# host2's own pings run below; there is no BGP session or other traffic.
uplink="${TOPO_NS_PREFIX}rt3rt2"
r3neigh() { ip netns exec "$ns_router3" ip -6 neigh show "$1" dev "$uplink"; }
# eventually_ping <description>: host2 -> host1 succeeds within 20 s.
eventually_ping() {
    local desc=$1 i
    print_info "Testing: $desc"
    for i in $(seq 1 20); do
        if ip netns exec "$ns_host2" ping -c 1 -W 1 172.0.1.1 > /dev/null 2>&1; then
            print_success "$desc: PASS (try $i)"
            TESTS_PASSED=$((TESTS_PASSED + 1))
            return 0
        fi
    done
    print_error "$desc: FAIL"
    TESTS_FAILED=$((TESTS_FAILED + 1))
}
check "router3 keeps router2 (fc00:23::2) as a managed neighbour" \
  sh -c "ip netns exec '$ns_router3' ip -6 neigh show fc00:23::2 dev '$uplink' | grep -Eq 'managed|extern_learn'"
ip netns exec "$ns_router3" ip -6 neigh del fc00:23::2 dev "$uplink" 2>/dev/null || true
print_info "router3's neighbour for router2 after the delete: $(r3neigh fc00:23::2 | tr '\n' ' ')"
eventually_ping "host2 -> host1 after router3's neighbour entry for router2 was deleted"

# Move the route to another address of router2: the next hop changes, and
# its neighbour entry does not exist yet.
ip netns exec "${TOPO_NS_PREFIX}router2" ip -6 addr add fc00:23::3/64 dev "${TOPO_NS_PREFIX}rt2rt3" nodad
ip netns exec "$ns_router3" ip -6 neigh del fc00:23::3 dev "$uplink" 2>/dev/null || true
ip netns exec "$ns_router3" ip -6 route replace fc00:2::/64 via fc00:23::3 dev "$uplink"
eventually_ping "host2 -> host1 after the next hop moved to fc00:23::3"
check "router3 keeps the new next hop (fc00:23::3) as a managed neighbour" \
  sh -c "ip netns exec '$ns_router3' ip -6 neigh show fc00:23::3 dev '$uplink' | grep -Eq 'managed|extern_learn'"

print_info "Stopping Vinbero..."
kill $VINBERO_PID 2>/dev/null || true
wait $VINBERO_PID 2>/dev/null || true
rm -f /tmp/vinbero_end_dt4_state.json

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
