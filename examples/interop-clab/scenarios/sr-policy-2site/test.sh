#!/usr/bin/env bash
# sr-policy-2site interop scenario assertions (Vinbero <-> FRR).
#
# Builds on l3vpn-2site and adds color-based SR Policy steering with a
# multi-hop service chain. It proves:
#   1. the iBGP session is ESTABLISHED;
#   2. the operator-defined TWO-segment SR Policy is installed
#      (vbctl sr-policy list shows [core End, FRR End]);
#   2b. vbctl bgp advertise-sr-policy runs in a real deployment (encode-path
#      smoke; FRR 10.2 does not receive SAFI 73, so reception is covered by
#      the gobgp e2e tests);
#   3. FRR's color-100 VPN route is received and the policy has an ACTIVE
#      candidate -- i.e. a colored route resolved onto the policy_id;
#   4. data plane: ce-tokyo -> ce-osaka rides the *steered chain*
#      (core End fd00:300:0:ee::1 -> FRR End fd00:200:0:ee::1 -> End.DT4
#      service SID), proven by the outer DA changing per hop on the wire;
#   5. negative: the return direction (ce-osaka -> ce-tokyo), which carries
#      no color and matches no policy, still forwards as a plain L3VPN;
#   6. the prober's probe rides the policy's transport chain: removing the
#      core waypoint's End SID flips the path down (while the PE itself
#      stays reachable), and restoring it brings the path back up.
#
# The data plane settles asynchronously, so every ping is gated on its
# preconditions and retried generously -- a slow settle cannot flake it.
#
# Exit non-zero on the first failed assertion.
set -u

PE_TOKYO=clab-sr-policy-2site-pe-tokyo   # Vinbero PE
PE_OSAKA=clab-sr-policy-2site-pe-osaka   # FRR PE
CORE=clab-sr-policy-2site-core           # SRv6 waypoint (core End)
CE_TOKYO=clab-sr-policy-2site-ce-tokyo
CE_OSAKA=clab-sr-policy-2site-ce-osaka

OSAKA_PREFIX=10.2.0.0/24      # ce-osaka subnet, advertised by FRR with color 100
CE_TOKYO_ADDR=10.1.0.10
CE_OSAKA_ADDR=10.2.0.10

VIN_LOOPBACK=2001:db8:ff::1   # pe-tokyo (Vinbero)
FRR_LOOPBACK=2001:db8:ff::2   # pe-osaka (FRR), = SR Policy endpoint
# Two-segment SR Policy transport list: core's End, then FRR's End. The
# packet must visit them in order before decap -- a real service chain.
CORE_SID=fd00:300:0:ee::1       # 1st segment: End on core (outer DA tokyo->core)
TRANSPORT_SID=fd00:200:0:ee::1  # 2nd segment: End on FRR (outer DA core->osaka)

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
echo " sr-policy-2site interop scenario test (Vinbero <-> FRR)"
echo "=============================================="

# --- 1. iBGP session ESTABLISHED -------------------------------------------
echo ""
echo "[1] iBGP session ESTABLISHED"
frr_established() {
    dexec "$PE_OSAKA" vtysh -c "show bgp summary json" 2>/dev/null \
      | python3 -c "import sys,json; d=json.load(sys.stdin); \
sys.exit(0 if d.get('ipv4Vpn',{}).get('peers',{}).get('$VIN_LOOPBACK',{}).get('state')=='Established' else 1)"
}
if retry frr_established; then
    ok "FRR sees peer $VIN_LOOPBACK Established (ipv4 vpn)"
else
    ng "FRR peer $VIN_LOOPBACK not Established"
    dexec "$PE_OSAKA" vtysh -c "show bgp summary" || true
fi

# --- 2. local SR Policy installed ------------------------------------------
echo ""
echo "[2] operator-defined SR Policy installed (two-segment chain)"
srp_has_local() {
    # The policy must carry BOTH transport segments (core End then FRR End).
    dexec "$PE_TOKYO" vbctl sr-policy list 2>/dev/null | grep -qi "$CORE_SID" \
      && dexec "$PE_TOKYO" vbctl sr-policy list 2>/dev/null | grep -qi "$TRANSPORT_SID"
}
if retry srp_has_local; then
    ok "vbctl sr-policy list shows the 2-segment policy ($CORE_SID -> $TRANSPORT_SID)"
    dexec "$PE_TOKYO" vbctl sr-policy list | sed 's/^/      /'
else
    ng "two-segment local SR Policy not found in vbctl sr-policy list"
    dexec "$PE_TOKYO" vbctl sr-policy list || true
fi

# --- 2b. advertise-sr-policy succeeds (encode-path smoke) -------------------
# The FRR peer here does not implement SAFI 73 reception, so this only
# confirms the advertise command/RPC/encode path runs in a real deployment
# (the receive/decode interop is covered by the gobgp e2e tests).
echo ""
echo "[2b] advertise-sr-policy encode-path smoke"
adv_ok() {
    dexec "$PE_TOKYO" vbctl bgp advertise-sr-policy \
      --color 100 --endpoint "$FRR_LOOPBACK" \
      --segments "$CORE_SID,$TRANSPORT_SID" \
      --distinguisher 1 --next-hop "$VIN_LOOPBACK" 2>/dev/null | grep -qi "advertised"
}
if retry adv_ok; then
    ok "vbctl bgp advertise-sr-policy advertised the SR Policy (encode path OK)"
else
    ng "vbctl bgp advertise-sr-policy did not report success"
    dexec "$PE_TOKYO" vbctl bgp advertise-sr-policy \
      --color 100 --endpoint "$FRR_LOOPBACK" --segments "$CORE_SID,$TRANSPORT_SID" \
      --distinguisher 1 --next-hop "$VIN_LOOPBACK" 2>&1 | sed 's/^/      /' || true
fi

# --- 3. FRR color route received + policy has an ACTIVE candidate ----------
echo ""
echo "[3] FRR -> Vinbero  (color-100 route resolves onto the policy)"
if retry bash -c "docker exec $PE_TOKYO vbctl headend-v4 list 2>/dev/null | grep -q '$OSAKA_PREFIX'"; then
    ok "FRR's $OSAKA_PREFIX installed in Vinbero headend-v4 map"
else
    ng "FRR's $OSAKA_PREFIX missing from Vinbero headend-v4 map"
    dexec "$PE_TOKYO" vbctl headend-v4 list || true
fi
srp_active() {
    dexec "$PE_TOKYO" vbctl sr-policy list 2>/dev/null | grep -q '\*'
}
if retry srp_active; then
    ok "SR Policy has an active candidate (color route resolved onto policy_id)"
else
    ng "SR Policy has no active candidate"
fi

# --- 4. Data plane: steered ce-tokyo -> ce-osaka ---------------------------
echo ""
echo "[4] Data plane  (steered path via transport End SID)"
gate_underlay() {
    dexec "$PE_TOKYO" ping6 -c 1 -W 2 -I "$VIN_LOOPBACK" "$FRR_LOOPBACK" >/dev/null 2>&1
}
gate_transport() {
    dexec "$PE_OSAKA" ip -6 route show "$TRANSPORT_SID" 2>/dev/null | grep -qi "seg6local"
}
gate_core() {
    dexec "$CORE" ip -6 route show "$CORE_SID" 2>/dev/null | grep -qi "seg6local"
}
retry gate_underlay || ng "gate: PE loopbacks not mutually reachable"
if retry gate_core; then
    echo "  gate: core waypoint End SID ($CORE_SID) present"
else
    ng "gate: core waypoint End SID never appeared"
fi
if retry gate_transport; then
    echo "  gate: FRR transport End SID ($TRANSPORT_SID) present"
else
    ng "gate: FRR transport End SID never appeared"
fi
dexec "$PE_TOKYO" ping -c 1 -W 2 "$CE_TOKYO_ADDR" >/dev/null 2>&1 || true
dexec "$PE_OSAKA" ip vrf exec vrf-cust ping -c 1 -W 2 "$CE_OSAKA_ADDR" >/dev/null 2>&1 || true

ce_tokyo_to_osaka() {
    dexec "$CE_TOKYO" ping -c 2 -W 2 "$CE_OSAKA_ADDR" >/dev/null 2>&1
}
if retry_n 45 ce_tokyo_to_osaka; then
    ok "ce-tokyo -> ce-osaka ping over the steered SRv6 path"
else
    ng "ce-tokyo -> ce-osaka ping failed"
    dexec "$CE_TOKYO" ping -c 3 -W 2 "$CE_OSAKA_ADDR" 2>&1 | sed 's/^/      /' || true
fi

# Chain proof: the steered packet must visit BOTH transport segments in
# order. Capture on the tokyo->core link (outer DA = core's End SID, the
# first segment) and on the core->osaka link (outer DA = FRR's End SID, the
# second segment, after core's End advanced the DA). Seeing the outer DA
# CHANGE from CORE_SID to TRANSPORT_SID across consecutive hops proves a
# real segment-by-segment service chain, not a single-hop detour.
cap_core=$(mktemp)
cap_osaka=$(mktemp)
dexec "$CORE" timeout 8 tcpdump -nli eth1 "ip6 and dst $CORE_SID" >"$cap_core" 2>/dev/null &
core_pid=$!
dexec "$PE_OSAKA" timeout 8 tcpdump -nli eth2 "ip6 and dst $TRANSPORT_SID" >"$cap_osaka" 2>/dev/null &
osaka_pid=$!
sleep 1
for _ in 1 2 3 4 5 6 7 8; do
    dexec "$CE_TOKYO" ping -c 1 -W 2 "$CE_OSAKA_ADDR" >/dev/null 2>&1
    sleep 1
done
wait "$core_pid" 2>/dev/null
wait "$osaka_pid" 2>/dev/null
if grep -q "$CORE_SID" "$cap_core"; then
    ok "hop 1: tokyo->core packet has outer DA = core End SID $CORE_SID"
    sed 's/^/      /' "$cap_core" | head -1
else
    ng "no packet with outer DA $CORE_SID on tokyo->core: first segment not imposed"
fi
if grep -q "$TRANSPORT_SID" "$cap_osaka"; then
    ok "hop 2: core->osaka packet has outer DA = FRR End SID $TRANSPORT_SID (chain advanced)"
    sed 's/^/      /' "$cap_osaka" | head -1
else
    ng "no packet with outer DA $TRANSPORT_SID on core->osaka: chain did not advance"
fi
rm -f "$cap_core" "$cap_osaka"

# --- 5. Negative: un-colored return path still forwards --------------------
echo ""
echo "[5] Negative  (no-color return path forwards as plain L3VPN)"
ce_osaka_to_tokyo() {
    dexec "$CE_OSAKA" ping -c 2 -W 2 "$CE_TOKYO_ADDR" >/dev/null 2>&1
}
if retry_n 45 ce_osaka_to_tokyo; then
    ok "ce-osaka -> ce-tokyo ping (un-colored, non-steered) still works"
else
    ng "ce-osaka -> ce-tokyo ping failed"
    dexec "$CE_OSAKA" ping -c 3 -W 2 "$CE_TOKYO_ADDR" 2>&1 | sed 's/^/      /' || true
fi

# --- 6. prober walks the policy transport chain ----------------------------
echo ""
echo "[6] prober probes THROUGH the steered transport chain"
# The probe embeds the policy's non-terminal transport (core's End) ahead
# of its terminal destination (FRR's loopback), mirroring the waypoints the
# XDP program composes for steered traffic. The transport's own terminal
# segment (FRR's End) is excluded: it lands on the endpoint node, whose
# Linux End refuses to forward to its own loopback, so keeping it would
# fail a healthy path forever. This is what makes a dead waypoint visible:
# plain PE-to-PE reachability stays perfect when core's End SID goes away,
# so a probe that went straight to the PE would keep reporting up while the
# steered traffic blackholes.
prober_json() {
    dexec "$PE_TOKYO" vbctl --json prober status 2>/dev/null
}
steered_path_state() {
    # $1 = "up" or "down": the state the FRR-loopback path must be in.
    prober_json | python3 -c "
import sys, json
d = json.load(sys.stdin)
if not d.get('enabled'):
    sys.exit(1)
paths = [p for p in d.get('paths') or [] if p.get('dst') == '$FRR_LOOPBACK']
if len(paths) != 1:
    sys.exit(1)
# A false 'up' is omitted from the JSON entirely (proto3 zero-value), so
# fold the absent key and false together before comparing.
sys.exit(0 if bool(paths[0].get('up')) == ('$1' == 'up') else 1)"
}
if retry steered_path_state up; then
    ok "prober reports the steered path up (probe rides the transport chain)"
else
    ng "prober does not report an up path toward $FRR_LOOPBACK"
    prober_json || true
fi

# Failure injection: remove the core waypoint's End SID. The underlay and
# the PE loopbacks stay reachable; only the segment chain is broken.
dexec "$CORE" ip -6 route del "$CORE_SID/128" >/dev/null 2>&1 || true
if retry_n 10 steered_path_state down; then
    ok "prober detects the dead waypoint (path down)"
else
    ng "prober kept the path up with the waypoint End SID removed"
    prober_json || true
fi
# The claim is transport-awareness, so prove the PE itself is STILL
# reachable while the path is down: a full underlay outage would flip the
# path down too, but then this plain loopback-to-loopback ping (which does
# not ride the segment chain) would fail with it.
if retry_n 5 gate_underlay; then
    ok "PE loopback stays reachable during the outage (only the chain is dead)"
else
    ng "PE loopback unreachable during the outage; the down state proves nothing"
fi

# Restore the waypoint and the path must come back.
dexec "$CORE" ip -6 route replace "$CORE_SID/128" encap seg6local action End dev eth2 >/dev/null 2>&1 || true
if retry_n 10 steered_path_state up; then
    ok "prober recovers the path after the waypoint returns"
else
    ng "path did not recover after restoring the waypoint End SID"
    prober_json || true
fi
if retry_n 15 ce_tokyo_to_osaka; then
    ok "steered data plane works again after recovery"
else
    ng "steered data plane broken after recovery"
fi

echo ""
echo "=============================================="
echo " RESULT: $pass passed, $fail failed"
echo "=============================================="
[ "$fail" -eq 0 ] || exit 1
