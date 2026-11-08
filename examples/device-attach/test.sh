#!/bin/bash
# examples/device-attach/test.sh
# Attach and detach a device at runtime (DeviceService), check that it is
# attached again after a daemon restart, that vanished interfaces are
# dropped, and that bridge members added at runtime survive a restart.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/test_utils.sh"

check_root

VINBEROD_BIN="${SCRIPT_DIR}/../../out/bin/vinberod"
VINBERO_BIN="${SCRIPT_DIR}/../../out/bin/vinbero"
VINBERO_CONFIG="${SCRIPT_DIR}/vinbero_router3.yaml"
VINBERO_LOG="/tmp/vinbero_device_attach_test.log"
STATE_FILE="/tmp/vinbero_device_attach_state.json"
ADDR="127.0.0.1:8089"

export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-dva-}"
ns_host1="${TOPO_NS_PREFIX}host1"
ns_router3="${TOPO_NS_PREFIX}router3"
uplink="${TOPO_NS_PREFIX}rt3rt2"
downlink="${TOPO_NS_PREFIX}rt3h2"

TESTS_PASSED=0
TESTS_FAILED=0
VINBERO_PID=""

stop_daemon() {
    # Guard against PID reuse: only kill if the PID is still our vinberod.
    if [ -n "$VINBERO_PID" ] && [ "$(ps -o comm= -p "$VINBERO_PID" 2>/dev/null)" = "vinberod" ]; then
        kill "$VINBERO_PID" 2>/dev/null || true
        wait "$VINBERO_PID" 2>/dev/null || true
    fi
    VINBERO_PID=""
}
trap stop_daemon EXIT

start_daemon() {
    start_vinbero "$ns_router3" "$VINBERO_CONFIG" "$VINBERO_LOG"
    VINBERO_PID=$VINBERO_LAST_PID
    wait_vinbero_ready "$ns_router3" "$ADDR" 10
}

vbctl() {
    ip netns exec "$ns_router3" "$VINBERO_BIN" -s "http://${ADDR}" "$@"
}

r3() {
    ip netns exec "$ns_router3" "$@"
}

pass() { print_success "$1: PASS"; TESTS_PASSED=$((TESTS_PASSED + 1)); }
fail() { print_error "$1: FAIL"; TESTS_FAILED=$((TESTS_FAILED + 1)); }

# check <description> <command...>: tally whether the command succeeds.
check() {
    local desc=$1; shift
    if "$@" > /dev/null 2>&1; then pass "$desc"; else fail "$desc"; fi
}

# check_not <description> <command...>: tally whether the command fails.
check_not() {
    local desc=$1; shift
    if "$@" > /dev/null 2>&1; then fail "$desc"; else pass "$desc"; fi
}

ping_h2() {
    ip netns exec "$ns_host1" ping -c 2 -W 1 172.0.2.1
}

# device_source <name>: "config", "api", or "" when not attached.
device_source() {
    vbctl --json device list | jq -r --arg n "$1" \
        '.devices[]? | select(.name == $n) | if .config then "config" else "api" end'
}

has_xdp() {
    r3 ip link show dev "$1" | grep -q " xdp"
}

state_has_device() {
    jq -e --arg n "$1" '.devices[]? | select(.name == $n)' "$STATE_FILE"
}

master_of() {
    r3 ip -j link show dev "$1" | jq -r '.[0].master // ""'
}

add_sid() {
    vbctl sid create --trigger-prefix fc00:3::3/128 --action END_DT4 --vrf-name vrf100 > /dev/null
}

echo "=========================================="
echo "Runtime device attach"
echo "=========================================="

# Only Vinbero decapsulates from here on.
r3 ip -6 route del local fc00:3::3/128 2>/dev/null || true
rm -f "$STATE_FILE"

start_daemon
add_sid
r3 ping6 -c 1 -W 1 fc00:23::2 > /dev/null 2>&1 || true

check "config device listed with source config" test "$(device_source "$downlink")" = config
check_not "End.DT4 unreachable before the uplink is attached" ping_h2

check "device attach $uplink" vbctl device attach --name "$uplink"
check "End.DT4 reachable after attach" ping_h2
check "attached device listed with source api" test "$(device_source "$uplink")" = api
check "attached device recorded in the state file" state_has_device "$uplink"
check "re-attach in the same mode is idempotent" vbctl device attach --name "$uplink" --mode generic
check_not "re-attach in another mode is refused" vbctl device attach --name "$uplink" --mode driver
check_not "detach of a config device is refused" vbctl device detach --name "$downlink"

# The front door applies to a runtime-attached device like to a config one.
check "AC for the downlink" vbctl vrf ac-add --vrf vrf100 --interface "$downlink"
check "default-deny" vbctl vrf policy --default-deny
check_not "End.DT4 dropped while the uplink has no AC" ping_h2
check "AC for the uplink" vbctl vrf ac-add --vrf global --interface "$uplink"
check "End.DT4 reachable with both ACs" ping_h2
check "default-deny off" vbctl vrf policy

check "device detach $uplink" vbctl device detach --name "$uplink"
check_not "End.DT4 unreachable after detach" ping_h2
check_not "XDP removed from the uplink" has_xdp "$uplink"
check_not "detached device removed from the state file" state_has_device "$uplink"
check_not "second detach reports not attached" vbctl device detach --name "$uplink"

echo ""
echo "=========================================="
echo "Restart reconcile"
echo "=========================================="

check "device attach $uplink" vbctl device attach --name "$uplink"
stop_daemon
check_not "XDP removed by the daemon shutdown" has_xdp "$uplink"
start_daemon
check "uplink attached again from the state file" test "$(device_source "$uplink")" = api
check "XDP back on the uplink" has_xdp "$uplink"
add_sid
check "End.DT4 reachable after the restart" ping_h2

echo ""
echo "=========================================="
echo "Vanished interfaces"
echo "=========================================="

r3 ip link add "${TOPO_NS_PREFIX}d0" type dummy
r3 ip link set "${TOPO_NS_PREFIX}d0" up
r3 ip link add "${TOPO_NS_PREFIX}d1" type dummy
r3 ip link set "${TOPO_NS_PREFIX}d1" up
check "attach a dummy in generic mode" vbctl device attach --name "${TOPO_NS_PREFIX}d0" --mode generic
check "attach a second dummy" vbctl device attach --name "${TOPO_NS_PREFIX}d1"
r3 ip link del "${TOPO_NS_PREFIX}d0"
check "detach of a deleted interface succeeds" vbctl device detach --name "${TOPO_NS_PREFIX}d0"
stop_daemon
r3 ip link del "${TOPO_NS_PREFIX}d1"
start_daemon
check "daemon starts with a vanished device in the state" kill -0 "$VINBERO_PID"
check "vanished device not listed" test -z "$(device_source "${TOPO_NS_PREFIX}d1")"
check_not "vanished device dropped from the state file" state_has_device "${TOPO_NS_PREFIX}d1"
check "uplink still attached" test "$(device_source "$uplink")" = api

echo ""
echo "=========================================="
echo "Bridge members added at runtime"
echo "=========================================="

br="${TOPO_NS_PREFIX}br0"
m0="${TOPO_NS_PREFIX}m0"
m1="${TOPO_NS_PREFIX}m1"
r3 ip link add "$m0" type dummy
r3 ip link add "$m1" type dummy
check "bridge attach" vbctl vrf bridge-attach --vrf l2dva --name "$br" --bd-id 10
check "member add $m0" vbctl vrf bridge-member-add --vrf l2dva --interface "$m0"
check "member add $m1" vbctl vrf bridge-member-add --vrf l2dva --interface "$m1"
check "member add is idempotent" vbctl vrf bridge-member-add --vrf l2dva --interface "$m0"
check "$m0 enslaved" test "$(master_of "$m0")" = "$br"
stop_daemon
# While the daemon is down: one port loses its master, the other is deleted.
r3 ip link set "$m0" nomaster
r3 ip link del "$m1"
start_daemon
check "$m0 enslaved again after the restart" test "$(master_of "$m0")" = "$br"
check "vanished member dropped" test "$(vbctl --json vrf show | jq -c '.vrfs[] | select(.name == "l2dva") | .bridge.members')" = "[\"$m0\"]"
check "member remove $m0" vbctl vrf bridge-member-remove --vrf l2dva --interface "$m0"
check "$m0 released" test -z "$(master_of "$m0")"
check "bridge detach" vbctl vrf bridge-detach --vrf l2dva
r3 ip link del "$m0" 2>/dev/null || true

stop_daemon

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
