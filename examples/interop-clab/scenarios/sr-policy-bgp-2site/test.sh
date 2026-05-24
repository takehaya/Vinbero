#!/usr/bin/env bash
# sr-policy-bgp-2site interop scenario assertions (Vinbero <-> Vinbero <-> FRR).
#
# Like sr-policy-2site but the SR Policy is LEARNED OVER BGP (SAFI 73) from a
# separate controller (srctl) instead of being defined locally on the PE. It
# proves Vinbero's SR Policy receive/decode path over a real BGP session:
#   1. the iBGP VPN session with FRR is ESTABLISHED;
#   2. the PE LEARNED the SR Policy over BGP -- vbctl sr-policy list shows it
#      with ORIGIN bgp (not local), proving the SAFI 73 session and the
#      decode of the SR Policy NLRI + Tunnel Encap attribute;
#   3. FRR's color-100 VPN route resolves onto the BGP-learned policy (the
#      headend entry exists and the policy has an ACTIVE candidate);
#   4. data plane: ce-tokyo -> ce-osaka rides the steered path (outer DA =
#      transport SID fd00:200:0:ee::1), proven on the wire;
#   5. negative: the un-colored return direction still forwards as plain
#      L3VPN.
#
# Exit non-zero on the first failed assertion.
set -u

PE_TOKYO=clab-sr-policy-bgp-2site-pe-tokyo   # Vinbero PE under test
PE_OSAKA=clab-sr-policy-bgp-2site-pe-osaka   # FRR PE
SRCTL=clab-sr-policy-bgp-2site-srctl         # Vinbero SR Policy controller
CE_TOKYO=clab-sr-policy-bgp-2site-ce-tokyo
CE_OSAKA=clab-sr-policy-bgp-2site-ce-osaka

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
echo " sr-policy-bgp-2site interop scenario test (BGP-learned SR Policy)"
echo "=============================================="

# --- 1. iBGP VPN session with FRR ESTABLISHED ------------------------------
echo ""
echo "[1] iBGP VPN session (FRR) ESTABLISHED"
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

# --- 2. PE learned the SR Policy over BGP (SAFI 73) ------------------------
echo ""
echo "[2] PE learned the SR Policy over BGP from srctl"
srp_origin_bgp() {
    # The policy must be present with ORIGIN bgp -- proof the SAFI 73 session
    # is up and the NLRI + Tunnel Encap decoded. Match the transport SID and
    # a bgp origin row.
    dexec "$PE_TOKYO" vbctl sr-policy list 2>/dev/null | grep -qi "$TRANSPORT_SID" \
      && dexec "$PE_TOKYO" vbctl sr-policy list 2>/dev/null | grep -iq "bgp"
}
if retry srp_origin_bgp; then
    ok "vbctl sr-policy list shows the BGP-learned policy (origin bgp, transport $TRANSPORT_SID)"
    dexec "$PE_TOKYO" vbctl sr-policy list | sed 's/^/      /'
else
    ng "BGP-learned SR Policy (origin bgp) not found on the PE"
    dexec "$PE_TOKYO" vbctl sr-policy list || true
    echo "    --- srctl advertise log ---"
    dexec "$SRCTL" sh -c 'tail -5 /var/log/vinberod.log' 2>/dev/null | sed 's/^/      /' || true
fi

# --- 3. FRR color route resolves onto the BGP-learned policy ---------------
echo ""
echo "[3] FRR color-100 route resolves onto the BGP-learned policy"
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

# Steering proof: the encapsulated packet arriving at FRR must carry the
# transport SID as its outer destination. A non-steered route would encap
# straight to the service SID, so the transport SID as outer DA proves the
# BGP-learned policy composed transport ahead of the service SID.
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
    ok "steered packet seen with outer DA = transport SID $TRANSPORT_SID (BGP-learned steering confirmed)"
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
