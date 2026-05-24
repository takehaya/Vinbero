#!/usr/bin/env bash
# sr-policy-2site interop scenario assertions (Vinbero <-> FRR).
#
# Builds on l3vpn-2site and adds color-based SR Policy steering. It proves:
#   1. the iBGP session is ESTABLISHED;
#   2. the operator-defined SR Policy is installed (vbctl sr-policy list);
#   3. FRR's color-100 VPN route is received and the policy has an ACTIVE
#      candidate -- i.e. a colored route resolved onto the policy_id;
#   4. data plane: ce-tokyo -> ce-osaka rides the *steered* path
#      (transport SID fd00:200:0:ee::1 -> End -> End.DT4 service SID), proven
#      by the transport End SID's packet counter incrementing;
#   5. negative: the return direction (ce-osaka -> ce-tokyo), which carries
#      no color and matches no policy, still forwards as a plain L3VPN.
#
# The data plane settles asynchronously, so every ping is gated on its
# preconditions and retried generously -- a slow settle cannot flake it.
#
# Exit non-zero on the first failed assertion.
set -u

PE_TOKYO=clab-sr-policy-2site-pe-tokyo   # Vinbero PE
PE_OSAKA=clab-sr-policy-2site-pe-osaka   # FRR PE
CE_TOKYO=clab-sr-policy-2site-ce-tokyo
CE_OSAKA=clab-sr-policy-2site-ce-osaka

OSAKA_PREFIX=10.2.0.0/24      # ce-osaka subnet, advertised by FRR with color 100
CE_TOKYO_ADDR=10.1.0.10
CE_OSAKA_ADDR=10.2.0.10

VIN_LOOPBACK=2001:db8:ff::1   # pe-tokyo (Vinbero)
FRR_LOOPBACK=2001:db8:ff::2   # pe-osaka (FRR), = SR Policy endpoint
TRANSPORT_SID=fd00:200:0:ee::1  # SR Policy transport hop (End SID on FRR)

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
echo "[2] operator-defined SR Policy installed"
srp_has_local() {
    dexec "$PE_TOKYO" vbctl sr-policy list 2>/dev/null | grep -qi "$TRANSPORT_SID"
}
if retry srp_has_local; then
    ok "vbctl sr-policy list shows the local policy (transport $TRANSPORT_SID)"
    dexec "$PE_TOKYO" vbctl sr-policy list | sed 's/^/      /'
else
    ng "local SR Policy not found in vbctl sr-policy list"
    dexec "$PE_TOKYO" vbctl sr-policy list || true
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
retry gate_underlay || ng "gate: PE loopbacks not mutually reachable"
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

# Steering proof: capture the encapsulated packet arriving at FRR and assert
# its OUTER IPv6 destination is the TRANSPORT SID. A non-steered route would
# encap straight to the service SID, so seeing the transport SID as the
# outer DA proves the SR Policy composed transport ahead of the service SID.
capfile=$(mktemp)
dexec "$PE_OSAKA" timeout 8 tcpdump -nli eth2 "ip6 and dst $TRANSPORT_SID" >"$capfile" 2>/dev/null &
cappid=$!
sleep 1
for _ in 1 2 3 4 5; do
    dexec "$CE_TOKYO" ping -c 1 -W 2 "$CE_OSAKA_ADDR" >/dev/null 2>&1
    sleep 1
done
wait "$cappid" 2>/dev/null
if grep -q "$TRANSPORT_SID" "$capfile"; then
    ok "steered packet seen with outer DA = transport SID $TRANSPORT_SID (steering confirmed)"
    sed 's/^/      /' "$capfile" | head -1
else
    ng "no packet with outer DA $TRANSPORT_SID observed: traffic not steered"
fi
rm -f "$capfile"

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

echo ""
echo "=============================================="
echo " RESULT: $pass passed, $fail failed"
echo "=============================================="
[ "$fail" -eq 0 ] || exit 1
