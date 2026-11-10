#!/bin/bash
# examples/bum-ecmp-underlay/test.sh
# BUM over an ECMP underlay: a PE with two uplinks floods towards peers
# routed over a multipath route. Each peer gets exactly one copy, on the
# uplink the data plane's FIB lookup picks for it, and keeps getting one as
# the underlay changes.
#
# BUM_MODE=tc (default), xdp or xdp-native (xdp in native XDP) selects
# settings.l2.bum_mode. On a kernel where vinberod falls back from xdp to
# tc replication, the xdp run checks the fallback instead.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/test_utils.sh"

check_root

VINBEROD_BIN="${SCRIPT_DIR}/../../out/bin/vinberod"
VINBERO_BIN="${SCRIPT_DIR}/../../out/bin/vinbero"

ns_ce=becmp-ce
ns_pe=becmp-pe
ns_rt=becmp-rt
ac=becmp-ac
BUM_MODE="${BUM_MODE:-tc}"
SRC=fc00:1::1
GW1=fd00:a::2
GW2=fd00:b::2
TMP=/tmp/vinbero_becmp
# Copies of one marker frame are counted, so a peer shows up on a capture
# under its outer IPv6 destination.
NUM_PEERS=8
SEND_IF=becmp-c0.100
PE_LOG=/tmp/vinbero_becmp_pe.log

TESTS_PASSED=0
TESTS_FAILED=0
VINBERO_PID=""

stop_vinbero() {
    if [ -n "$VINBERO_PID" ] && ps -p "$VINBERO_PID" > /dev/null 2>&1; then
        kill "$VINBERO_PID" 2>/dev/null || true
        wait "$VINBERO_PID" 2>/dev/null || true
    fi
    VINBERO_PID=""
}
cleanup() {
    stop_vinbero
    rm -rf "$TMP"
}
trap cleanup EXIT
mkdir -p "$TMP"

vbctl() { ip netns exec "$ns_pe" ${VINBERO_BIN} -s http://127.0.0.1:8085 "$@"; }
pe() { ip netns exec "$ns_pe" "$@"; }

stats_counter() {
    vbctl stats show 2>/dev/null | awk -v n="$1" '$1 == n {print $2; exit}'
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

# wait_neigh <gw> <dev>: until the PE has resolved the gateway, or 30 s.
wait_neigh() {
    local i
    for i in $(seq 60); do
        pe ip -6 neigh show to "$1" dev "$2" 2>/dev/null | grep -qE 'REACHABLE|STALE|DELAY|PROBE' && return 0
        sleep 0.5
    done
    print_error "neighbour $1 on $2 not resolved"
    return 1
}

resolve_neighs() {
    # A ping so tc mode has them too: only xdp mode's devmap sync manages
    # the slots' next hops.
    pe ping -c1 -W1 -I becmp-up1 "$GW1" > /dev/null 2>&1 || true
    pe ping -c1 -W1 -I becmp-up2 "$GW2" > /dev/null 2>&1 || true
    wait_neigh "$GW1" becmp-up1
    wait_neigh "$GW2" becmp-up2
}

# pick_peers: PEERS gets $NUM_PEERS locators that between them use both
# uplinks. The kernel's multipath hash is random per boot, so a fixed list
# could land on one uplink; the kernel names each candidate's uplink.
pick_peers() {
    PEERS=()
    local n1=0 n2=0 i dev seg
    for i in $(seq 1 256); do
        seg=$(printf 'fc00:100:%x::1' "$i")
        dev=$(pe ip -6 route get "$seg" from "$SRC" iif "$ac" 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p')
        if [ "$dev" = becmp-up1 ] && [ "$n1" -lt $((NUM_PEERS / 2)) ]; then
            PEERS+=("$seg"); n1=$((n1 + 1))
        elif [ "$dev" = becmp-up2 ] && [ "$n2" -lt $((NUM_PEERS / 2)) ]; then
            PEERS+=("$seg"); n2=$((n2 + 1))
        fi
        [ "${#PEERS[@]}" -eq "$NUM_PEERS" ] && return 0
    done
    print_error "256 candidate peers did not cover both uplinks (got $n1 and $n2)"
    exit 1
}

configure_vinbero() {
    vbctl hl2 create --interface "$ac" --vlan-id 100 \
        --src-addr "$SRC" --segments "${PEERS[0]}" --bd-id 100 > /dev/null
    local seg
    for seg in "${PEERS[@]}"; do
        vbctl peer create --bd-id 100 --src-addr "$SRC" --segments "$seg" > /dev/null
    done
}

# start_mode <mode>: vinberod in that BUM mode, configured.
start_mode() {
    local mode="$1"
    stop_vinbero
    print_info "Starting vinberod in BUM mode ${mode}..."
    local cfg
    cfg=$(BUM_MODE="$mode" bum_mode_config "${SCRIPT_DIR}/vinbero_pe.yaml" "$TMP/pe_${mode}.yaml")
    start_vinbero "$ns_pe" "$cfg" "$PE_LOG"
    VINBERO_PID=$VINBERO_LAST_PID
    wait_vinbero_ready "$ns_pe" "127.0.0.1:8085" 15
    BUM_EFFECTIVE=$(BUM_MODE="$mode" bum_effective_mode "$PE_LOG")
    print_info "BUM replication runs in mode ${BUM_EFFECTIVE}"
    configure_vinbero
    resolve_neighs
    sleep 1
    vbctl stats reset > /dev/null 2>&1 || true
}

# round <tag>: host sends one broadcast frame; prints one line
# "<peer> <uplink> <copies>" per peer the frame reached, from captures on
# the transit router's two ports (a namespace with no XDP program).
round() {
    local tag="$1" pcap1="$TMP/${tag}_up1.pcap" pcap2="$TMP/${tag}_up2.pcap" pid1 pid2
    capture_start "$ns_rt" becmp-d1 "$pcap1"
    pid1=$CAPTURE_PID
    capture_start "$ns_rt" becmp-d2 "$pcap2"
    pid2=$CAPTURE_PID
    sleep 0.3
    bum_marker_send "$ns_ce" "$SEND_IF" "$tag"
    sleep 0.7
    kill "$pid1" "$pid2" 2>/dev/null || true
    wait "$pid1" "$pid2" 2>/dev/null || true
    python3 - "$pcap1" "$pcap2" "$tag" <<'PY'
import socket, struct, sys
tag = sys.argv[3].encode()
seen = {}
for uplink, path in (("up1", sys.argv[1]), ("up2", sys.argv[2])):
    data = open(path, "rb").read()
    off = 24
    while off + 16 <= len(data):
        incl = struct.unpack("<I", data[off + 8:off + 12])[0]
        off += 16
        frame = data[off:off + incl]
        off += incl
        if tag in frame and len(frame) >= 54 and frame[12:14] == b"\x86\xdd":
            dst = socket.inet_ntop(socket.AF_INET6, frame[38:54])
            key = (dst, uplink)
            seen[key] = seen.get(key, 0) + 1
for (dst, up), n in sorted(seen.items()):
    print(dst, up, n)
PY
}

# check_delivery <desc> <round output>: every peer got exactly one copy.
check_delivery() {
    local desc="$1" out="$2" seg
    expect_eq "[$desc] peers reached" "$(echo "$out" | awk 'NF==3' | awk '{print $1}' | sort -u | wc -l | tr -d ' ')" "$NUM_PEERS"
    for seg in "${PEERS[@]}"; do
        expect_eq "[$desc] copies for $seg" "$(echo "$out" | awk -v p="$seg" '$1==p {n+=$3} END {print n+0}')" 1
    done
}

# settle_round <desc> [traffic]: wait for the rebuild that follows a change
# (traffic=1 first sends a frame: a change with no netlink event is only
# seen once a copy is dropped), then a fresh round must reach every peer
# with no new drop.
settle_round() {
    local desc="$1" traffic="${2:-0}" tag="$3" output
    if [ "$traffic" = 1 ]; then
        bum_marker_send "$ns_ce" "$SEND_IF" "vbsac-$RANDOM"
    fi
    sleep 3
    local before=""
    if [ "$BUM_EFFECTIVE" = xdp ]; then
        before="$(stats_counter BUM_UPLINK_MISMATCH)/$(stats_counter BUM_EGRESS_NO_NEIGH)"
    fi
    output=$(round "$tag")
    check_delivery "$desc" "$output"
    if [ "$BUM_EFFECTIVE" = xdp ]; then
        expect_eq "[$desc] no new drop" "$(stats_counter BUM_UPLINK_MISMATCH)/$(stats_counter BUM_EGRESS_NO_NEIGH)" "$before"
    fi
}

echo "=========================================="
echo "BUM over an ECMP underlay (BUM_MODE=${BUM_MODE})"
echo "=========================================="

bum_native_prepare "$ns_ce" "$ns_pe" "$ns_rt"

pick_peers
print_info "Peers: ${PEERS[*]}"

# The tc-mode path of each peer, which the xdp modes must reproduce.
start_mode tc
tc_out=$(round vbbase-tc)
check_delivery "tc baseline" "$tc_out"
echo "$tc_out" | awk 'NF==3 {print $1, $2}' > "$TMP/paths_tc.txt"
expect_eq "[tc baseline] both uplinks used" "$(awk '{print $2}' "$TMP/paths_tc.txt" | sort -u | wc -l | tr -d ' ')" 2

if [ "$BUM_MODE" != tc ]; then
    start_mode "$BUM_MODE"
    mode_out=$(round vbbase-mode)
    check_delivery "$BUM_MODE baseline" "$mode_out"
    echo "$mode_out" | awk 'NF==3 {print $1, $2}' > "$TMP/paths_mode.txt"
    expect_eq "[$BUM_MODE baseline] same per-peer path as tc" "$(diff "$TMP/paths_tc.txt" "$TMP/paths_mode.txt" | wc -l | tr -d ' ')" 0
    if [ "$BUM_EFFECTIVE" = xdp ]; then
        expect_eq "BUM_UPLINK_MISMATCH" "$(stats_counter BUM_UPLINK_MISMATCH)" 0
        expect_eq "BUM_EGRESS_NO_NEIGH" "$(stats_counter BUM_EGRESS_NO_NEIGH)" 0
        expect_eq "BUM_PLAN_STALE" "$(stats_counter BUM_PLAN_STALE)" 0
        expect_eq "BUM_XDP_FALLBACK" "$(stats_counter BUM_XDP_FALLBACK)" 0
        for gw_dev in "$GW1 becmp-up1" "$GW2 becmp-up2"; do
            read -r gw dev <<< "$gw_dev"
            expect_eq "next hop $gw is a managed neighbour" \
                "$(pe ip -6 neigh show to "$gw" dev "$dev" | grep -c managed)" 1
        done
    fi
fi

echo ""
echo "=========================================="
echo "Underlay changes (running ${BUM_EFFECTIVE})"
echo "=========================================="

print_info "Moving the route to a nexthop-object group..."
pe ip nexthop add id 11 via "$GW1" dev becmp-up1
pe ip nexthop add id 12 via "$GW2" dev becmp-up2
pe ip nexthop add id 100 group 11/12
pe ip -6 route replace fc00:100::/32 nhid 100
settle_round "nexthop group" 0 vbchg-group

print_info "Weight change..."
# A weight that moves nearly every peer off the second uplink.
pe ip nexthop replace id 100 group 11,100/12
settle_round "group weight 100:1" 0 vbchg-weight
pe ip nexthop replace id 100 group 11/12

print_info "Member delete (nexthop event only)..."
settle_round "group back to 1:1" 0 vbchg-even
pe ip nexthop del id 12
settle_round "member removed" 0 vbchg-del
pe ip nexthop add id 12 via "$GW2" dev becmp-up2
pe ip nexthop replace id 100 group 11/12
settle_round "member added back" 0 vbchg-add

print_info "Uplink admin down and up..."
pe ip link set becmp-up2 down
settle_round "uplink down" 0 vbchg-down
pe ip link set becmp-up2 up
pe ip addr replace fd00:b::1/64 dev becmp-up2 nodad
sleep 0.5
pe ping -c1 -W1 -I becmp-up2 "$GW2" > /dev/null 2>&1 || true
pe ip nexthop add id 12 via "$GW2" dev becmp-up2
pe ip nexthop replace id 100 group 11/12
settle_round "uplink back up" 0 vbchg-up

# A gateway that stops answering: its neighbour goes FAILED and the
# hash-threshold group leaves it out. No netlink event says so; in xdp mode
# a dropped copy starts the rebuild.
print_info "Gateway neighbour goes FAILED..."
ip -n "$ns_rt" addr del "$GW2/64" dev becmp-d2
pe ip -6 neigh replace "$GW2" dev becmp-up2 nud failed managed extern_learn
sleep 0.2
settle_round "gateway FAILED" 1 vbchg-failed
print_info "Gateway answers again..."
ip -n "$ns_rt" addr add "$GW2/64" dev becmp-d2 nodad
# The entry stays managed: the kernel retries it on its own, with no
# traffic to resolve it.
wait_neigh "$GW2" becmp-up2
settle_round "gateway back" 1 vbchg-back

log_count() { grep -c "$1" "$PE_LOG" || true; }

# expect_more <desc> <got> <before>: the counter rose.
expect_more() {
    if [ "$2" -gt "$3" ] 2>/dev/null; then
        print_success "$1 (from $3 to $2)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        print_error "$1 (from '$3' to '$2')"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

# Both cases are about the devmaps, so a run replicating in tc has no use
# for them.
if [ "$BUM_EFFECTIVE" = xdp ]; then
    echo ""
    echo "=========================================="
    echo "ACs that disagree: the BD falls back to tc"
    echo "=========================================="
    vbctl hl2 create --interface becmp-ac2 --vlan-id 100 \
        --src-addr "$SRC" --segments "${PEERS[0]}" --bd-id 100 > /dev/null
    flood_before=$(stats_counter BUM_XDP_FLOOD)
    settle_round "second AC, still xdp" 0 vbsplit-agree
    expect_more "[second AC] replicated in xdp" "$(stats_counter BUM_XDP_FLOOD)" "$flood_before"

    # The second AC's table sends every peer over the uplink the first AC
    # does not use for the first peer, so at least that peer disagrees.
    first_dev=$(pe ip -6 route get "${PEERS[0]}" from "$SRC" iif "$ac" | sed -n 's/.* dev \([^ ]*\).*/\1/p')
    if [ "$first_dev" = becmp-up1 ]; then
        other_dev=becmp-up2 other_gw=$GW2 other_up=up2
    else
        other_dev=becmp-up1 other_gw=$GW1 other_up=up1
    fi
    warned_before=$(log_count "replicates BUM in tc mode")
    pe ip -6 route add fc00:100::/32 via "$other_gw" dev "$other_dev" table 100
    pe ip -6 rule add iif becmp-ac2 lookup 100 pref 100
    sleep 1.5
    expect_eq "[split] the fallback is warned about once" "$(log_count "replicates BUM in tc mode")" "$((warned_before + 1))"

    # The tc path drops a copy whose next hop is unresolved, so the fallback
    # must keep the second AC's next hop resolved with no other traffic.
    pe ip -6 neigh del "$other_gw" dev "$other_dev"
    pe ip -6 route add fc00:ffe::/64 dev lo # any event: the rebuild
    wait_neigh "$other_gw" "$other_dev"
    expect_eq "[split] the second AC's next hop is a managed neighbour" \
        "$(pe ip -6 neigh show to "$other_gw" dev "$other_dev" | grep -c managed)" 1
    pe ip -6 route del fc00:ffe::/64 dev lo
    sleep 0.5

    flood_before=$(stats_counter BUM_XDP_FLOOD)
    fallback_before=$(stats_counter BUM_XDP_FALLBACK)
    check_delivery "split, frame from the first AC" "$(round vbsplit-ac1)"
    SEND_IF=becmp-c1.100
    from_ac2=$(round vbsplit-ac2)
    SEND_IF=becmp-c0.100
    check_delivery "split, frame from the second AC" "$from_ac2"
    expect_eq "[split] the second AC's copies use its own table" \
        "$(echo "$from_ac2" | awk -v u="$other_up" 'NF==3 && $2!=u' | wc -l | tr -d ' ')" 0
    expect_eq "[split] nothing replicated in xdp" "$(stats_counter BUM_XDP_FLOOD)" "$flood_before"
    expect_more "[split] BUM_XDP_FALLBACK" "$(stats_counter BUM_XDP_FALLBACK)" "$fallback_before"

    recovered_before=$(log_count "replicates BUM in xdp mode again")
    pe ip -6 rule del iif becmp-ac2 lookup 100 pref 100
    pe ip -6 route del fc00:100::/32 table 100
    flood_before=$(stats_counter BUM_XDP_FLOOD)
    settle_round "ACs agree again" 0 vbsplit-back
    expect_more "[ACs agree] replicated in xdp again" "$(stats_counter BUM_XDP_FLOOD)" "$flood_before"
    expect_eq "[ACs agree] the recovery is logged" "$(log_count "replicates BUM in xdp mode again")" "$((recovered_before + 1))"
    vbctl hl2 delete --interface becmp-ac2 --vlan-id 100 > /dev/null
    sleep 0.5

    echo ""
    echo "=========================================="
    echo "A slot left out comes back with no event"
    echo "=========================================="
    # forwarding off makes the AC's lookups fail (FWD_DISABLED). Toggling it
    # on a device with an address also adds or removes an anycast route, so
    # the AC goes without IPv6 addresses here and the fix sends no event.
    pe sysctl -qw net.ipv6.conf.becmp-ac.disable_ipv6=1
    pe sysctl -qw net.ipv6.conf.becmp-ac.forwarding=0
    # The warnings only: the retries repeat the line at debug level.
    left_before=$(log_count "WARN.*slot left out")
    pe ip -6 route add fc00:fff::/64 dev lo # any event: the rebuild that finds out
    sleep 1.5
    expect_eq "[forwarding off] every slot left out, logged once" "$(log_count "WARN.*slot left out")" "$((left_before + NUM_PEERS))"
    expect_eq "[forwarding off] no copies" "$(round vbsysctl-off | awk 'NF==3' | wc -l | tr -d ' ')" 0

    back_before=$(log_count "flood slot is no longer left out")
    pe ip monitor route rule nexthop > "$TMP/events.txt" 2>/dev/null &
    monitor_pid=$!
    sleep 0.5
    pe sysctl -qw net.ipv6.conf.becmp-ac.forwarding=1
    # bumExcludedRetry is 30 s.
    for _ in $(seq 90); do
        [ "$(log_count "flood slot is no longer left out")" -ge "$((back_before + NUM_PEERS))" ] && break
        sleep 0.5
    done
    expect_eq "[forwarding on] every slot came back" "$(log_count "flood slot is no longer left out")" "$((back_before + NUM_PEERS))"
    kill "$monitor_pid" 2>/dev/null || true
    wait "$monitor_pid" 2>/dev/null || true
    expect_eq "[forwarding on] no route, rule or nexthop event" "$(wc -l < "$TMP/events.txt" | tr -d ' ')" 0
    check_delivery "forwarding back on" "$(round vbsysctl-on)"
    pe ip -6 route del fc00:fff::/64 dev lo
    pe sysctl -qw net.ipv6.conf.becmp-ac.disable_ipv6=0
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
fi
print_success "All tests passed"
