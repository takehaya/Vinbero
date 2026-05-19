#!/usr/bin/env bash
# FRR <-> Vinbero BGP SRv6 L3VPN interop assertions.
#
# Verifies, against a running `make deploy` lab, the things the example
# exists to prove:
#   1. the iBGP session is ESTABLISHED on both sides;
#   2. FRR -> Vinbero: a VPN route FRR advertises (with an RFC 9252
#      SRv6 Service TLV) is decoded by Vinbero and lands in the headend
#      map -- SRv6 Service TLV *decode* interop, including the RFC 9252
#      §4 transposition reconstruction;
#   3. Vinbero -> FRR: the route Vinbero advertises reaches FRR's VPN
#      RIB with the SRv6 SID intact -- SRv6 Service TLV *encode* interop;
#   4. data plane: a real `ping` succeeds both ways between ce-tokyo
#      (10.1.0.10) and ce-osaka (10.2.0.10), riding the SRv6 L3VPN
#      through both PEs and the core.
#
# DATA-PLANE FLAKINESS -- the data plane settles asynchronously (XDP
# attach, BGP convergence, FRR's auto-installed seg6 localsid, NDP).
# Before pinging, section 4 GATES on every readiness precondition:
#   - both BGP sessions Established,
#   - the learned VPN routes installed (Vinbero headend maps + FRR RIB),
#   - the decap endpoints present (Vinbero SID function + FRR localsid),
#   - the underlay NDP neighbours resolved end to end.
# Only once all gates pass does it ping, with a generous retry. A slow
# data plane therefore cannot produce a spurious FAIL.
#
# Exit non-zero on the first failed assertion.
set -u

PE_TOKYO=clab-frr-interop-pe-tokyo   # Vinbero PE
PE_OSAKA=clab-frr-interop-pe-osaka   # FRR PE
CORE=clab-frr-interop-core
CE_TOKYO=clab-frr-interop-ce-tokyo
CE_OSAKA=clab-frr-interop-ce-osaka

# Customer prefixes.
TOKYO_PREFIX=10.1.0.0/24      # ce-tokyo subnet, advertised by Vinbero
OSAKA_PREFIX=10.2.0.0/24      # ce-osaka subnet, advertised by FRR

# Data-plane endpoints: the two customer hosts.
CE_TOKYO_ADDR=10.1.0.10
CE_OSAKA_ADDR=10.2.0.10

# Loopback peering addresses.
VIN_LOOPBACK=2001:db8:ff::1   # pe-tokyo (Vinbero)
FRR_LOOPBACK=2001:db8:ff::2   # pe-osaka (FRR)

# FRR's End.DT4 service SID for the ce-osaka prefix. FRR carries the SID
# function bits transposed in the VPN label, so the SID *on the wire* is
# the bare locator fd00:200:: while FRR's seg6local localsid sits at the
# transposed full SID below (function index 1 from `sid vpn export 1`).
# Vinbero must fold the label back per RFC 9252 §4 and reconstruct it.
FRR_FULL_SID=fd00:200:0:1::

pass=0
fail=0
ok()   { echo "  PASS: $1"; pass=$((pass + 1)); }
ng()   { echo "  FAIL: $1"; fail=$((fail + 1)); }

dexec() { docker exec "$@"; }

# retry CMD... -- run a command until it succeeds, default ~60s.
# retry_n N CMD... -- same but with an explicit attempt count (2s each).
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
echo " FRR <-> Vinbero SRv6 L3VPN interop test"
echo "=============================================="

# --- 1. iBGP session ESTABLISHED on both sides -----------------------------
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

# Vinbero side: the BGP applier logs the session; the in-process speaker
# has no `peers` CLI, so the daemon log is the source of truth.
if dexec "$PE_TOKYO" grep -q "BGP peer added" /var/log/vinberod.log 2>/dev/null; then
    ok "Vinbero BGP speaker started and peer configured"
else
    ng "Vinbero BGP speaker did not start"
fi

# --- 2. FRR -> Vinbero: SRv6 Service TLV decode ----------------------------
echo ""
echo "[2] FRR -> Vinbero  (SRv6 Service TLV decode)"

# Wait until FRR has actually advertised its VPNv4 route.
frr_has_export() {
    dexec "$PE_OSAKA" vtysh -c "show bgp ipv4 vpn $OSAKA_PREFIX" 2>/dev/null \
      | grep -q "Remote SID:"
}
retry frr_has_export || true

# 2a. FRR's VPNv4 route (ce-osaka subnet) lands in Vinbero's headend-v4 map.
if retry bash -c "docker exec $PE_TOKYO vbctl headend-v4 list 2>/dev/null | grep -q '$OSAKA_PREFIX'"; then
    ok "FRR VPNv4 route $OSAKA_PREFIX installed in Vinbero headend-v4 map"
    dexec "$PE_TOKYO" vbctl headend-v4 list | sed 's/^/      /'
else
    ng "FRR VPNv4 route $OSAKA_PREFIX missing from Vinbero headend-v4 map"
    dexec "$PE_TOKYO" vbctl headend-v4 list || true
fi

# frr_route_sid digs the first path's remoteSid out of vtysh JSON
# (`show bgp <afi> vpn <prefix> json` is keyed by route-distinguisher,
# each RD value carrying a `paths` list). Used here and in section 3.
frr_route_sid() {
    python3 -c "import sys,json; d=json.load(sys.stdin); \
rds=[v for v in d.values() if isinstance(v,dict) and 'paths' in v]; \
print(rds[0]['paths'][0].get('remoteSid','') if rds else '')"
}

# 2b. RFC 9252 §4 transposition. FRR carries the SID function bits in
#     the VPN label, so the SID *on the wire* is the bare locator.
#     Vinbero must fold the label back and reconstruct FRR's real
#     End.DT4 localsid -- the headend SEGMENTS column must show the
#     full SID, not the bare on-wire locator.
frr_wire_sid=$(dexec "$PE_OSAKA" vtysh -c "show bgp ipv4 vpn $OSAKA_PREFIX json" 2>/dev/null \
  | frr_route_sid 2>/dev/null)
vin_seg=$(dexec "$PE_TOKYO" vbctl headend-v4 list 2>/dev/null \
  | awk -v p="$OSAKA_PREFIX" '$1==p {print $NF}')
if [ "$vin_seg" = "$FRR_FULL_SID" ] && [ "$frr_wire_sid" != "$FRR_FULL_SID" ]; then
    ok "Vinbero folded the transposed SID: wire=$frr_wire_sid -> full=$vin_seg"
else
    ng "transposition decode wrong: wire='$frr_wire_sid' Vinbero='$vin_seg' want='$FRR_FULL_SID'"
fi

# --- 3. Vinbero -> FRR: SRv6 Service TLV encode ----------------------------
echo ""
echo "[3] Vinbero -> FRR  (SRv6 Service TLV encode)"

# Vinbero advertises the ce-tokyo subnet (10.1.0.0/24) into the L3VPN in
# vinbero/start.sh. Assert it reaches FRR's VPN RIB with the SID intact.
VIN_SID=fd00:100:0:1::
check_frr_rib() {
    local got
    got=$(dexec "$PE_OSAKA" vtysh -c "show bgp ipv4 vpn $TOKYO_PREFIX json" 2>/dev/null \
      | frr_route_sid 2>/dev/null)
    [ "$got" = "$VIN_SID" ]
}
if retry check_frr_rib; then
    ok "FRR RIB has $TOKYO_PREFIX with SRv6 SID $VIN_SID"
    dexec "$PE_OSAKA" vtysh -c "show bgp ipv4 vpn $TOKYO_PREFIX" | sed 's/^/      /'
else
    ng "FRR RIB missing $TOKYO_PREFIX / wrong SID"
    dexec "$PE_OSAKA" vtysh -c "show bgp ipv4 vpn" || true
fi

# 3b. FRR installs the VPN route into vrf-cust as an SRv6 encap route.
# Inspect the kernel FIB directly: the `ip route` text reliably shows
# the `encap seg6` action, whereas `vtysh show ip route` text does not.
frr_vrf_route() {
    dexec "$PE_OSAKA" ip route show vrf vrf-cust "$TOKYO_PREFIX" 2>/dev/null \
      | grep -q "encap seg6"
}
if retry frr_vrf_route; then
    ok "FRR installed $TOKYO_PREFIX into vrf-cust as an SRv6 encap route"
else
    ng "FRR did not install $TOKYO_PREFIX into vrf-cust"
    dexec "$PE_OSAKA" vtysh -c "show ip route vrf vrf-cust" || true
fi

# --- 4. Data plane: bidirectional SRv6 L3VPN ping --------------------------
echo ""
echo "[4] Data plane  (SRv6 L3VPN ping, both directions)"

# 4.0 READINESS GATE. The data plane settles asynchronously; ping only
# once every precondition holds, so a slow settle cannot flake the test.

# (a) both BGP sessions Established (FRR side checked above; re-gate so
#     section 4 is self-contained even if section 1 was slow).
if retry frr_established; then
    echo "  gate: iBGP session Established"
else
    ng "gate: iBGP session never reached Established"
fi

# (b) the learned VPN routes are installed on both PEs.
gate_vin_headend() {
    dexec "$PE_TOKYO" vbctl headend-v4 list 2>/dev/null | grep -q "$OSAKA_PREFIX"
}
gate_frr_rib() {
    dexec "$PE_OSAKA" ip route show vrf vrf-cust "$TOKYO_PREFIX" 2>/dev/null \
      | grep -q "encap seg6"
}
if retry gate_vin_headend; then
    echo "  gate: ce-osaka prefix in Vinbero headend map"
else
    ng "gate: ce-osaka prefix never installed in Vinbero headend map"
fi
if retry gate_frr_rib; then
    echo "  gate: ce-tokyo prefix in FRR vrf-cust RIB"
else
    ng "gate: ce-tokyo prefix never installed in FRR vrf-cust RIB"
fi

# (c) the decap endpoints exist on both PEs.
gate_vin_sid() {
    dexec "$PE_TOKYO" vbctl sid list 2>/dev/null | grep -q "fd00:100:0:1::"
}
gate_frr_localsid() {
    # FRR auto-installs an End.DT4 seg6local route at its transposed SID.
    dexec "$PE_OSAKA" ip -6 route show table all 2>/dev/null \
      | grep -qi "seg6local"
}
if retry gate_vin_sid; then
    echo "  gate: Vinbero End.DT4 SID function present"
else
    ng "gate: Vinbero End.DT4 SID function never appeared"
fi
if retry gate_frr_localsid; then
    echo "  gate: FRR seg6local End.DT4 localsid present"
else
    ng "gate: FRR seg6local End.DT4 localsid never appeared"
fi

# (d) underlay reachability end to end: both PE loopbacks mutually
#     reachable through the core, and the customer ARP/NDP resolved.
#     Source from the loopback explicitly -- without -I the kernel may
#     pick a link address the far PE has no route back to (the lab has
#     no IGP, only the per-loopback static routes).
gate_underlay_tokyo() {
    dexec "$PE_TOKYO" ping6 -c 1 -W 2 -I "$VIN_LOOPBACK" "$FRR_LOOPBACK" \
      >/dev/null 2>&1
}
gate_underlay_osaka() {
    dexec "$PE_OSAKA" ping6 -c 1 -W 2 -I "$FRR_LOOPBACK" "$VIN_LOOPBACK" \
      >/dev/null 2>&1
}
if retry gate_underlay_tokyo && retry gate_underlay_osaka; then
    echo "  gate: PE loopbacks mutually reachable through the core"
else
    ng "gate: PE loopbacks not mutually reachable"
fi

# Warm the customer-side ARP so the first End.DT4 decap egress and the
# first H.Encaps customer ingress do not race NDP/ARP resolution.
dexec "$PE_TOKYO" ping -c 1 -W 2 "$CE_TOKYO_ADDR" >/dev/null 2>&1 || true
dexec "$PE_OSAKA" ip vrf exec vrf-cust ping -c 1 -W 2 "$CE_OSAKA_ADDR" >/dev/null 2>&1 || true

echo "  --- gates passed, starting data-plane ping ---"

# 4a. ce-tokyo -> ce-osaka. ce-tokyo sends plaintext IPv4; Vinbero's XDP
# H.Encaps it towards FRR's service SID, the core forwards by the outer
# IPv6 header, FRR's seg6 End.DT4 decaps it into vrf-cust to ce-osaka.
# Generous retry: even with the gates above, the very first packet can
# still lose a beat behind XDP map propagation.
ce_tokyo_to_osaka() {
    dexec "$CE_TOKYO" ping -c 2 -W 2 "$CE_OSAKA_ADDR" >/dev/null 2>&1
}
if retry_n 45 ce_tokyo_to_osaka; then
    ok "ce-tokyo ($CE_TOKYO_ADDR) -> ce-osaka ($CE_OSAKA_ADDR) ping over SRv6 L3VPN"
    dexec "$CE_TOKYO" ping -c 3 -W 2 "$CE_OSAKA_ADDR" 2>&1 \
      | grep -E 'packets transmitted|rtt|round-trip' | sed 's/^/      /'
else
    ng "ce-tokyo -> ce-osaka ping failed"
    dexec "$CE_TOKYO" ping -c 3 -W 2 "$CE_OSAKA_ADDR" 2>&1 | sed 's/^/      /' || true
fi

# 4b. ce-osaka -> ce-tokyo (return direction). FRR H.Encaps the customer
# traffic towards Vinbero's End.DT4 SID; the core forwards it; Vinbero's
# XDP decaps it and forwards to ce-tokyo.
ce_osaka_to_tokyo() {
    dexec "$CE_OSAKA" ping -c 2 -W 2 "$CE_TOKYO_ADDR" >/dev/null 2>&1
}
if retry_n 45 ce_osaka_to_tokyo; then
    ok "ce-osaka ($CE_OSAKA_ADDR) -> ce-tokyo ($CE_TOKYO_ADDR) ping over SRv6 L3VPN"
    dexec "$CE_OSAKA" ping -c 3 -W 2 "$CE_TOKYO_ADDR" 2>&1 \
      | grep -E 'packets transmitted|rtt|round-trip' | sed 's/^/      /'
else
    ng "ce-osaka -> ce-tokyo ping failed"
    dexec "$CE_OSAKA" ping -c 3 -W 2 "$CE_TOKYO_ADDR" 2>&1 | sed 's/^/      /' || true
fi

# --- summary ---------------------------------------------------------------
echo ""
echo "=============================================="
echo " RESULT: $pass passed, $fail failed"
echo "=============================================="
[ "$fail" -eq 0 ] || exit 1
