#!/usr/bin/env bash
# FRR <-> Vinbero BGP SRv6 L3VPN interop assertions.
#
# Verifies, against a running `make deploy` lab, the four things the
# example exists to prove:
#   1. the BGP session is ESTABLISHED on both sides;
#   2. FRR -> Vinbero: a VPN route FRR advertises (with an RFC 9252
#      SRv6 Service TLV) is decoded by Vinbero and lands in the headend
#      map -- SRv6 Service TLV *decode* interop;
#   3. Vinbero -> FRR: a route advertised via `vbctl bgp advertise-vpn`
#      reaches FRR's VPN RIB with the SRv6 SID intact -- SRv6 Service
#      TLV *encode* interop;
#   4. data plane: a real `ping` succeeds both ways between the CE host
#      and FRR's customer over the SRv6 L3VPN -- Vinbero H.Encaps /
#      End.DT4 decap interop with FRR's seg6 dataplane.
#
# Exit non-zero on the first failed assertion.
set -u

FRR=clab-frr-interop-frr
VIN=clab-frr-interop-vinbero
CE=clab-frr-interop-ce

# Customer prefixes FRR exports (see frr/frr.conf).
FRR_V4_PREFIX=10.200.0.0/24
FRR_V6_PREFIX=fd00:c200::/64

# Data-plane endpoints: the CE host and FRR's customer address in
# vrf-cust. All CE<->customer traffic rides the SRv6 L3VPN.
CE_ADDR=10.0.0.10
FRR_CUST_ADDR=10.200.0.1

# Prefixes / SIDs Vinbero advertises towards FRR.
VIN_V4_PREFIX=10.100.0.0/24
VIN_V4_RD=65100:100
VIN_V4_SID=fd00:100:0:1::
VIN_V6_PREFIX=fd00:c100::/64
VIN_V6_RD=65100:106
VIN_V6_SID=fd00:100:0:2::

# eth1 IPv6 link addresses.
VIN_PEER=2001:db8:ff::2   # FRR sees Vinbero here
FRR_PEER=2001:db8:ff::1   # Vinbero sees FRR here

pass=0
fail=0
ok()   { echo "  PASS: $1"; pass=$((pass + 1)); }
ng()   { echo "  FAIL: $1"; fail=$((fail + 1)); }

dexec() { docker exec "$@"; }

# retry CMD... -- run a command until it succeeds, up to ~60s.
retry() {
    for _ in $(seq 1 30); do
        if "$@" >/dev/null 2>&1; then return 0; fi
        sleep 2
    done
    return 1
}

echo "=============================================="
echo " FRR <-> Vinbero SRv6 L3VPN interop test"
echo "=============================================="

# --- 1. BGP session ESTABLISHED on both sides ------------------------------
echo ""
echo "[1] BGP session ESTABLISHED"

frr_established() {
    dexec "$FRR" vtysh -c "show bgp summary json" 2>/dev/null \
      | python3 -c "import sys,json; d=json.load(sys.stdin); \
sys.exit(0 if d.get('ipv4Vpn',{}).get('peers',{}).get('$VIN_PEER',{}).get('state')=='Established' else 1)"
}
if retry frr_established; then
    ok "FRR sees peer $VIN_PEER Established (ipv4 vpn)"
else
    ng "FRR peer $VIN_PEER not Established"
    dexec "$FRR" vtysh -c "show bgp summary" || true
fi

# Vinbero side: the BGP applier logs the session; the in-process speaker
# has no `peers` CLI, so the daemon log is the source of truth.
if dexec "$VIN" grep -q "BGP peer added" /var/log/vinberod.log 2>/dev/null; then
    ok "Vinbero BGP speaker started and peer configured"
else
    ng "Vinbero BGP speaker did not start"
fi

# --- 2. FRR -> Vinbero: SRv6 Service TLV decode ----------------------------
echo ""
echo "[2] FRR -> Vinbero  (SRv6 Service TLV decode)"

# Wait until FRR has actually advertised its VPNv4 route.
frr_has_export() {
    dexec "$FRR" vtysh -c "show bgp ipv4 vpn $FRR_V4_PREFIX" 2>/dev/null \
      | grep -q "Remote SID:"
}
retry frr_has_export || true

# 2a. VPNv4 route lands in Vinbero's headend-v4 map.
if retry bash -c "docker exec $VIN vbctl headend-v4 list 2>/dev/null | grep -q '$FRR_V4_PREFIX'"; then
    ok "FRR VPNv4 route $FRR_V4_PREFIX installed in Vinbero headend-v4 map"
    dexec "$VIN" vbctl headend-v4 list | sed 's/^/      /'
else
    ng "FRR VPNv4 route $FRR_V4_PREFIX missing from Vinbero headend-v4 map"
    dexec "$VIN" vbctl headend-v4 list || true
fi

# 2b. VPNv6 route lands in Vinbero's headend-v6 map.
if retry bash -c "docker exec $VIN vbctl headend-v6 list 2>/dev/null | grep -q '$FRR_V6_PREFIX'"; then
    ok "FRR VPNv6 route $FRR_V6_PREFIX installed in Vinbero headend-v6 map"
    dexec "$VIN" vbctl headend-v6 list | sed 's/^/      /'
else
    ng "FRR VPNv6 route $FRR_V6_PREFIX missing from Vinbero headend-v6 map"
    dexec "$VIN" vbctl headend-v6 list || true
fi

# 2c. The decoded SRv6 SID is the one FRR allocated (headend SEGMENTS
#     column carries the segment list = the service SID).
# `show bgp <afi> vpn <prefix> json` is keyed by route-distinguisher,
# each RD value carrying a `paths` list -- dig the first path's SID out.
frr_route_sid() {
    # stdin = vtysh JSON; prints the first path's remoteSid.
    python3 -c "import sys,json; d=json.load(sys.stdin); \
rds=[v for v in d.values() if isinstance(v,dict) and 'paths' in v]; \
print(rds[0]['paths'][0].get('remoteSid','') if rds else '')"
}
frr_v4_sid=$(dexec "$FRR" vtysh -c "show bgp ipv4 vpn $FRR_V4_PREFIX json" 2>/dev/null \
  | frr_route_sid 2>/dev/null)
vin_v4_seg=$(dexec "$VIN" vbctl headend-v4 list 2>/dev/null \
  | awk -v p="$FRR_V4_PREFIX" '$1==p {print $NF}')
if [ -n "$frr_v4_sid" ] && [ "$frr_v4_sid" = "$vin_v4_seg" ]; then
    ok "SRv6 service SID matches end-to-end: FRR=$frr_v4_sid  Vinbero=$vin_v4_seg"
else
    ng "SRv6 service SID mismatch: FRR='$frr_v4_sid' Vinbero='$vin_v4_seg'"
fi

# --- 3. Vinbero -> FRR: SRv6 Service TLV encode ----------------------------
echo ""
echo "[3] Vinbero -> FRR  (SRv6 Service TLV encode)"

# Advertise a VPNv4 and a VPNv6 route from Vinbero with explicit SRv6
# service SIDs. Idempotent: re-running test.sh just re-advertises.
dexec "$VIN" vbctl bgp advertise-vpn --family vpnv4 \
    --prefix "$VIN_V4_PREFIX" --rd "$VIN_V4_RD" --rts 65000:200 \
    --sid "$VIN_V4_SID" --next-hop "$VIN_PEER" >/dev/null 2>&1 \
  && ok "vbctl advertised VPNv4 $VIN_V4_PREFIX (sid $VIN_V4_SID)" \
  || ng "vbctl advertise-vpn vpnv4 failed"

dexec "$VIN" vbctl bgp advertise-vpn --family vpnv6 \
    --prefix "$VIN_V6_PREFIX" --rd "$VIN_V6_RD" --rts 65000:206 \
    --sid "$VIN_V6_SID" --next-hop "$VIN_PEER" >/dev/null 2>&1 \
  && ok "vbctl advertised VPNv6 $VIN_V6_PREFIX (sid $VIN_V6_SID)" \
  || ng "vbctl advertise-vpn vpnv6 failed"

# 3a. VPNv4 route reaches FRR's RIB with the SID intact.
check_frr_rib() {
    # $1 = family (ipv4|ipv6), $2 = prefix, $3 = expected SID
    local got
    got=$(dexec "$FRR" vtysh -c "show bgp $1 vpn $2 json" 2>/dev/null \
      | frr_route_sid 2>/dev/null)
    [ "$got" = "$3" ]
}

if retry check_frr_rib ipv4 "$VIN_V4_PREFIX" "$VIN_V4_SID"; then
    ok "FRR RIB has $VIN_V4_PREFIX with SRv6 SID $VIN_V4_SID"
    dexec "$FRR" vtysh -c "show bgp ipv4 vpn $VIN_V4_PREFIX" | sed 's/^/      /'
else
    ng "FRR RIB missing $VIN_V4_PREFIX / wrong SID"
    dexec "$FRR" vtysh -c "show bgp ipv4 vpn" || true
fi

# 3b. VPNv6 route reaches FRR's RIB with the SID intact.
if retry check_frr_rib ipv6 "$VIN_V6_PREFIX" "$VIN_V6_SID"; then
    ok "FRR RIB has $VIN_V6_PREFIX with SRv6 SID $VIN_V6_SID"
    dexec "$FRR" vtysh -c "show bgp ipv6 vpn $VIN_V6_PREFIX" | sed 's/^/      /'
else
    ng "FRR RIB missing $VIN_V6_PREFIX / wrong SID"
    dexec "$FRR" vtysh -c "show bgp ipv6 vpn" || true
fi

# --- 4. Data plane: bidirectional SRv6 L3VPN ping --------------------------
echo ""
echo "[4] Data plane  (SRv6 L3VPN ping, both directions)"

# 4a. CE -> FRR customer. The CE sends plaintext IPv4 to FRR's customer
# address; Vinbero's XDP H.Encaps it towards FRR's service SID, FRR's
# seg6 End.DT4 decaps it into vrf-cust. The reply rides the L3VPN back.
# Retry: the BGP-driven headend / End.DT4 entries settle asynchronously.
ce_to_frr() {
    dexec "$CE" ping -c 2 -W 2 "$FRR_CUST_ADDR" >/dev/null 2>&1
}
if retry ce_to_frr; then
    ok "CE ($CE_ADDR) -> FRR customer ($FRR_CUST_ADDR) ping over SRv6 L3VPN"
    dexec "$CE" ping -c 3 -W 2 "$FRR_CUST_ADDR" 2>&1 \
      | grep -E 'packets transmitted|rtt|round-trip' | sed 's/^/      /'
else
    ng "CE -> FRR customer ping failed"
    dexec "$CE" ping -c 3 -W 2 "$FRR_CUST_ADDR" 2>&1 | sed 's/^/      /' || true
fi

# 4b. FRR customer -> CE (return direction). FRR H.Encaps the customer
# traffic towards Vinbero's End.DT4 SID; Vinbero's XDP decaps it and
# forwards to the CE. `ip vrf exec` sources the ping from vrf-cust.
frr_to_ce() {
    dexec "$FRR" ip vrf exec vrf-cust \
        ping -c 2 -W 2 -I "$FRR_CUST_ADDR" "$CE_ADDR" >/dev/null 2>&1
}
if retry frr_to_ce; then
    ok "FRR customer ($FRR_CUST_ADDR) -> CE ($CE_ADDR) ping over SRv6 L3VPN"
    dexec "$FRR" ip vrf exec vrf-cust ping -c 3 -W 2 -I "$FRR_CUST_ADDR" "$CE_ADDR" 2>&1 \
      | grep -E 'packets transmitted|rtt|round-trip' | sed 's/^/      /'
else
    ng "FRR customer -> CE ping failed"
    dexec "$FRR" ip vrf exec vrf-cust ping -c 3 -W 2 -I "$FRR_CUST_ADDR" "$CE_ADDR" 2>&1 \
      | sed 's/^/      /' || true
fi

# --- summary ---------------------------------------------------------------
echo ""
echo "=============================================="
echo " RESULT: $pass passed, $fail failed"
echo "=============================================="
[ "$fail" -eq 0 ] || exit 1
