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
    start_vinbero "$ns_pe" "$cfg" "/tmp/vinbero_becmp_pe.log"
    VINBERO_PID=$VINBERO_LAST_PID
    wait_vinbero_ready "$ns_pe" "127.0.0.1:8085" 15
    BUM_EFFECTIVE=$(BUM_MODE="$mode" bum_effective_mode /tmp/vinbero_becmp_pe.log)
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
    bum_capture_start "$ns_rt" becmp-d1 "$pcap1"
    pid1=$CAPTURE_PID
    bum_capture_start "$ns_rt" becmp-d2 "$pcap2"
    pid2=$CAPTURE_PID
    sleep 0.3
    bum_marker_send "$ns_ce" becmp-c0.100 "$tag"
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
        bum_marker_send "$ns_ce" becmp-c0.100 "vbsac-$RANDOM"
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
