#!/usr/bin/env bash
# sr-policy-bgp-2site interop scenario assertions (Vinbero <-> Vinbero).
#
# Two Vinbero PEs exchange SR Policies edge-to-edge over BGP (SAFI 73) and
# steer their L3VPN traffic through a shared TE waypoint. It proves:
#   1. each PE LEARNED the peer's SR Policy over BGP (origin bgp), whose
#      transport segment is the waypoint End SID -- the SAFI 73 session and
#      the NLRI / Tunnel Encap decode both work;
#   2. each PE's color-100 VPN route resolves onto the learned policy (the
#      headend entry exists and the policy has an ACTIVE candidate);
#   3. data plane, both directions: ce-tokyo <-> ce-osaka ping, and the
#      steered packets detour through the waypoint (outer DA = the waypoint
#      End SID on the core<->waypoint link) -- a real BGP-signaled SR-TE path.
#
# Exit non-zero on the first failed assertion.
set -u

PE_TOKYO=clab-sr-policy-bgp-2site-pe-tokyo
PE_OSAKA=clab-sr-policy-bgp-2site-pe-osaka
WAYPOINT=clab-sr-policy-bgp-2site-waypoint
CE_TOKYO=clab-sr-policy-bgp-2site-ce-tokyo
CE_OSAKA=clab-sr-policy-bgp-2site-ce-osaka

TOKYO_LOOPBACK=2001:db8:ff::1
OSAKA_LOOPBACK=2001:db8:ff::2
WAYPOINT_SID=fd00:300:0:ee::1   # TE waypoint End SID (outer DA on the detour)
CE_TOKYO_ADDR=10.1.0.10
CE_OSAKA_ADDR=10.2.0.10

pass=0
fail=0
ok() { echo "  PASS: $1"; pass=$((pass + 1)); }
ng() { echo "  FAIL: $1"; fail=$((fail + 1)); }

dexec() { docker exec "$@"; }

retry()   { retry_n 30 "$@"; }
retry_n() {
    local n=$1; shift
    local i
    for i in $(seq 1 "$n"); do
        if "$@" >/dev/null 2>&1; then return 0; fi
        sleep 2
    done
    return 1
}

echo "=============================================="
echo " sr-policy-bgp-2site interop test (edge-to-edge SR Policy + TE)"
echo "=============================================="

# --- 1. Each PE learned the peer's SR Policy over BGP ----------------------
echo ""
echo "[1] SR Policy exchanged edge-to-edge (origin bgp)"
# pe-tokyo must have pe-osaka's policy {endpoint = osaka loopback}; pe-osaka
# must have pe-tokyo's. Both must carry the waypoint End SID and be origin bgp.
tokyo_has_osaka_policy() {
    dexec "$PE_TOKYO" vbctl sr-policy list 2>/dev/null | grep -q "$OSAKA_LOOPBACK" \
      && dexec "$PE_TOKYO" vbctl sr-policy list 2>/dev/null | grep -q "$WAYPOINT_SID" \
      && dexec "$PE_TOKYO" vbctl sr-policy list 2>/dev/null | grep -iq "bgp"
}
osaka_has_tokyo_policy() {
    dexec "$PE_OSAKA" vbctl sr-policy list 2>/dev/null | grep -q "$TOKYO_LOOPBACK" \
      && dexec "$PE_OSAKA" vbctl sr-policy list 2>/dev/null | grep -q "$WAYPOINT_SID" \
      && dexec "$PE_OSAKA" vbctl sr-policy list 2>/dev/null | grep -iq "bgp"
}
if retry tokyo_has_osaka_policy; then
    ok "pe-tokyo learned pe-osaka's SR Policy (origin bgp, transport $WAYPOINT_SID)"
    dexec "$PE_TOKYO" vbctl sr-policy list | sed 's/^/      /'
else
    ng "pe-tokyo did not learn pe-osaka's SR Policy"
    dexec "$PE_TOKYO" vbctl sr-policy list || true
fi
if retry osaka_has_tokyo_policy; then
    ok "pe-osaka learned pe-tokyo's SR Policy (origin bgp, transport $WAYPOINT_SID)"
else
    ng "pe-osaka did not learn pe-tokyo's SR Policy"
    dexec "$PE_OSAKA" vbctl sr-policy list || true
fi

# --- 2. Color routes resolve onto the learned policies ---------------------
echo ""
echo "[2] color routes resolve onto the learned policies"
if retry bash -c "docker exec $PE_TOKYO vbctl headend-v4 list 2>/dev/null | grep -q '10.2.0.0/24'" \
   && dexec "$PE_TOKYO" vbctl sr-policy list 2>/dev/null | grep -q '\*'; then
    ok "pe-tokyo: 10.2.0.0/24 in headend-v4 map, policy has an active candidate"
else
    ng "pe-tokyo: 10.2.0.0/24 not steered"
    dexec "$PE_TOKYO" vbctl headend-v4 list || true
fi
if retry bash -c "docker exec $PE_OSAKA vbctl headend-v4 list 2>/dev/null | grep -q '10.1.0.0/24'" \
   && dexec "$PE_OSAKA" vbctl sr-policy list 2>/dev/null | grep -q '\*'; then
    ok "pe-osaka: 10.1.0.0/24 in headend-v4 map, policy has an active candidate"
else
    ng "pe-osaka: 10.1.0.0/24 not steered"
    dexec "$PE_OSAKA" vbctl headend-v4 list || true
fi

# --- 3. Data plane: bidirectional, steered through the waypoint ------------
echo ""
echo "[3] Data plane (bidirectional TE through the waypoint)"
gate_waypoint() {
    dexec "$WAYPOINT" ip -6 route show "$WAYPOINT_SID" 2>/dev/null | grep -qi "seg6local"
}
if retry gate_waypoint; then
    echo "  gate: waypoint End SID ($WAYPOINT_SID) present"
else
    ng "gate: waypoint End SID never appeared"
fi

# Warm the ARP/NDP entries.
dexec "$PE_TOKYO" ping -c 1 -W 2 "$CE_TOKYO_ADDR" >/dev/null 2>&1 || true
dexec "$PE_OSAKA" ping -c 1 -W 2 "$CE_OSAKA_ADDR" >/dev/null 2>&1 || true

# steered_dir <container> <dst> "<label>": capture the waypoint End SID on
# the core<->waypoint link while pinging one direction; the outer DA being
# the waypoint SID proves that direction detours through the waypoint.
steered_dir() {
    local src_c=$1 dst=$2 label=$3
    if ! retry_n 45 bash -c "docker exec $src_c ping -c 2 -W 2 $dst >/dev/null 2>&1"; then
        ng "$label: ping failed"
        dexec "$src_c" ping -c 3 -W 2 "$dst" 2>&1 | sed 's/^/      /' || true
        return
    fi
    ok "$label: ping over the steered SRv6 path"
    local cap; cap=$(mktemp)
    dexec "$WAYPOINT" timeout 8 tcpdump -nli eth1 "ip6 and dst $WAYPOINT_SID" >"$cap" 2>/dev/null &
    local pid=$!
    sleep 1
    for _ in 1 2 3 4 5; do
        dexec "$src_c" ping -c 1 -W 2 "$dst" >/dev/null 2>&1
        sleep 1
    done
    wait "$pid" 2>/dev/null
    if grep -q "$WAYPOINT_SID" "$cap"; then
        ok "$label: outer DA = waypoint End SID $WAYPOINT_SID (TE detour confirmed)"
        sed 's/^/      /' "$cap" | head -1
    else
        ng "$label: no packet with outer DA $WAYPOINT_SID (not steered through waypoint)"
    fi
    rm -f "$cap"
}

steered_dir "$CE_TOKYO" "$CE_OSAKA_ADDR" "ce-tokyo -> ce-osaka"
steered_dir "$CE_OSAKA" "$CE_TOKYO_ADDR" "ce-osaka -> ce-tokyo"

echo ""
echo "=============================================="
echo " RESULT: $pass passed, $fail failed"
echo "=============================================="
[ "$fail" -eq 0 ] || exit 1
