#!/bin/bash
# examples/end-dt2m-multihomed/smoke_api.sh
# Smoke test for Phase B-D Ethernet Segment + BdPeer ESI APIs.
#
# Launches a single vinberod instance in an isolated namespace with a
# dummy interface (no real dataplane traffic), then exercises:
#   - vbctl es create/list/df-set/df-clear/delete
#   - vbctl bd-peer create --esi / list / delete
# Runs in <10s and does NOT require the full 5-namespace topology.

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/test_utils.sh"
source "${SCRIPT_DIR}/../common/netns.sh"

check_root

VINBEROD_BIN="${SCRIPT_DIR}/../../out/bin/vinberod"
VINBERO_BIN="${SCRIPT_DIR}/../../out/bin/vinbero"

NS="dt2m-smoke"
DUMMY_IF="dt2m-dum0"
CFG="/tmp/vinbero_smoke_api.yaml"
LOG="/tmp/vinbero_smoke_api.log"
BIND="127.0.0.1:18082"
VINBERO_PID=""

TESTS_PASSED=0
TESTS_FAILED=0

cleanup() {
    if [ -n "$VINBERO_PID" ] && ps -p "$VINBERO_PID" > /dev/null 2>&1; then
        kill "$VINBERO_PID" 2>/dev/null || true
        wait "$VINBERO_PID" 2>/dev/null || true
    fi
    ip netns del "$NS" 2>/dev/null || true
    rm -f "$CFG"
}
trap cleanup EXIT

assert_ok() {
    local desc="$1"; shift
    if "$@" > /tmp/smoke_last.out 2>&1; then
        print_success "$desc"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        print_error "$desc"
        cat /tmp/smoke_last.out
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

assert_grep() {
    local desc="$1" pattern="$2"; shift 2
    if "$@" 2>&1 | tee /tmp/smoke_last.out | grep -Eq -- "$pattern"; then
        print_success "$desc"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        print_error "$desc (pattern: $pattern)"
        cat /tmp/smoke_last.out
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

vbctl() { ip netns exec "$NS" "${VINBERO_BIN}" -s "http://${BIND}" "$@"; }

echo "=========================================="
echo "Ethernet Segment + BdPeer ESI API smoke"
echo "=========================================="

create_netns "$NS"
run ip netns exec "$NS" ip link add "$DUMMY_IF" type dummy
run ip netns exec "$NS" ip link set "$DUMMY_IF" up

cat > "$CFG" <<EOF
internal:
  devices:
    - $DUMMY_IF
  bpf:
    device_mode: generic
    verifier_log_level: 1
    verifier_log_size: 1073741823
  server:
    bind: "$BIND"
  logger:
    level: info
    format: text
    no_color: false
    add_caller: false

settings:
  entries:
    sid_function:
      capacity: 1024
    headendv4:
      capacity: 1024
    headendv6:
      capacity: 1024
EOF

print_info "Starting vinberod..."
start_vinbero "$NS" "$CFG" "$LOG"
VINBERO_PID=$VINBERO_LAST_PID
wait_vinbero_ready "$NS" "$BIND" 10

ESI="00:11:22:33:44:55:66:77:88:99"
PE1="fc00:1::1"
PE2="fc00:2::2"

# ----- Ethernet Segment CRUD -----
print_info "Phase 1: ES CRUD"

assert_ok "es create (local-attached PE1)" \
    vbctl es create --esi "$ESI" --local-attached --local-pe "$PE1" --mode ALL_ACTIVE

assert_grep "es list shows created ES" "$ESI" vbctl es list

# ----- Designated Forwarder election -----
print_info "Phase 2: DF set/clear"

assert_ok "df-set PE1 as DF" vbctl es df-set --esi "$ESI" --pe "$PE1"
assert_grep "es list shows PE1 as DF" "$PE1" vbctl es list

assert_ok "df-set PE2 as DF (swap)" vbctl es df-set --esi "$ESI" --pe "$PE2"
assert_grep "es list shows PE2 as DF" "$PE2" vbctl es list

assert_ok "df-clear" vbctl es df-clear --esi "$ESI"

# ----- BdPeer --esi round-trip -----
print_info "Phase 3: bd-peer create --esi"

assert_ok "bd-peer create with ESI" \
    vbctl bd-peer create --bd-id 100 --src-addr "$PE2" \
        --segments "fc00:2::1,$PE1" --esi "$ESI"

assert_grep "bd-peer list shows ESI" "$ESI" vbctl bd-peer list --bd-id 100

assert_ok "bd-peer delete" vbctl bd-peer delete --bd-id 100

# ----- ES delete -----
print_info "Phase 4: ES delete"

assert_ok "es delete" vbctl es delete --esi "$ESI"

out=$(vbctl es list 2>&1)
if echo "$out" | grep -q "$ESI"; then
    print_error "es list still shows deleted ES"
    TESTS_FAILED=$((TESTS_FAILED + 1))
else
    print_success "es list no longer shows ES after delete"
    TESTS_PASSED=$((TESTS_PASSED + 1))
fi

echo ""
echo "=========================================="
echo "Summary: passed=$TESTS_PASSED failed=$TESTS_FAILED"
echo "=========================================="

[ "$TESTS_FAILED" -eq 0 ]
