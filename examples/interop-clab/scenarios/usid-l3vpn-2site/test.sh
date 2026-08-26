#!/usr/bin/env bash
# usid-l3vpn-2site interop scenario assertions (Vinbero <-> FRR, uSID).
#
# Verifies, against a running `make deploy` lab, the things the scenario
# exists to prove:
#   1. the iBGP session is ESTABLISHED on both sides;
#   2. FRR -> Vinbero: the uSID VPN route FRR advertises (format
#      usid-f3216: SID Structure 32/16/16/0 -- FRR still transposes the
#      function uSID into the VPN label, so the wire SID is the bare
#      block+node) is decoded by Vinbero, folded back to the full
#      micro-SID, and -- because the structure is uSID-shaped --
#      installed with H.Encaps.Red;
#   3. Vinbero -> FRR: the micro-SID Vinbero advertises from its uSID
#      locator reaches FRR's VPN RIB intact;
#   4. data plane: a real `ping` succeeds both ways, and the
#      Vinbero -> FRR direction carries NO SRH on the wire (reduced
#      encapsulation), asserted with tcpdump on the core.
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
# Failed assertions accumulate (for cascade diagnostics) and the script
# exits non-zero after the summary if any failed.
set -u

PE_TOKYO=clab-usid-l3vpn-2site-pe-tokyo   # Vinbero PE
PE_OSAKA=clab-usid-l3vpn-2site-pe-osaka   # FRR PE
CORE=clab-usid-l3vpn-2site-core
CE_TOKYO=clab-usid-l3vpn-2site-ce-tokyo
CE_OSAKA=clab-usid-l3vpn-2site-ce-osaka

# Customer prefixes.
TOKYO_PREFIX=10.1.0.0/24      # ce-tokyo subnet, advertised by Vinbero
OSAKA_PREFIX=10.2.0.0/24      # ce-osaka subnet, advertised by FRR

# Data-plane endpoints: the two customer hosts.
CE_TOKYO_ADDR=10.1.0.10
CE_OSAKA_ADDR=10.2.0.10

# Loopback peering addresses.
VIN_LOOPBACK=2001:db8:ff::1   # pe-tokyo (Vinbero)
FRR_LOOPBACK=2001:db8:ff::2   # pe-osaka (FRR)

# FRR's uDT4 service SID for the ce-osaka prefix: with format
# usid-f3216 the function uSID (index 1 from `sid vpn export 1`) sits
# right after the block+node. FRR still transposes it into the VPN
# label, so the wire carries the bare block+node and Vinbero folds the
# label back into the full micro-SID.
FRR_WIRE_SID=fd00:200:2::
FRR_FULL_SID=fd00:200:2:1::

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
echo " usid-l3vpn-2site interop scenario test (Vinbero <-> FRR, uSID)"
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

# Vinbero side: the in-process speaker has no `peers` CLI, so the daemon
# log is the source of truth. gobgp's FSM logs "Peer Up" exactly when the
# session reaches Established -- "BGP peer added" would only prove the
# peer was configured.
check_vin_established() {
    dexec "$PE_TOKYO" grep -q "Peer Up" /var/log/vinberod.log 2>/dev/null
}
if retry check_vin_established; then
    ok "Vinbero BGP session Established (gobgp Peer Up)"
else
    ng "Vinbero BGP session never reached Established"
    dexec "$PE_TOKYO" tail -20 /var/log/vinberod.log 2>/dev/null || true
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

# 2b. The locator format actually took effect: a rejected `format
#     usid-f3216` line would silently leave FRR in classic mode and every
#     later assertion could still pass as plain SRv6. The running config
#     only contains lines vtysh parsed.
if dexec "$PE_OSAKA" vtysh -c "show running-config" 2>/dev/null \
  | grep -q "format usid-f3216"; then
    ok "FRR accepted the usid-f3216 locator format"
else
    ng "FRR running config lost 'format usid-f3216' (rejected at load?)"
fi

# 2c. uSID wire format: FRR's usid-f3216 still transposes the function
#     uSID into the VPN label, so the wire SID must be the bare
#     block+node -- wire == full would mean the fold below proved
#     nothing -- and Vinbero must fold the label back into the full uDT4
#     micro-SID.
frr_wire_sid=$(dexec "$PE_OSAKA" vtysh -c "show bgp ipv4 vpn $OSAKA_PREFIX json" 2>/dev/null \
  | frr_route_sid 2>/dev/null)
if [ "$frr_wire_sid" = "$FRR_WIRE_SID" ]; then
    ok "FRR advertises the transposed bare block+node: $frr_wire_sid"
else
    ng "unexpected wire SID: '$frr_wire_sid' want '$FRR_WIRE_SID' (did FRR stop transposing?)"
fi
vin_seg=$(dexec "$PE_TOKYO" vbctl headend-v4 list 2>/dev/null \
  | awk -v p="$OSAKA_PREFIX" '$1==p {print $NF}')
if [ "$vin_seg" = "$FRR_FULL_SID" ]; then
    ok "uSID folded and installed in full: wire=$frr_wire_sid -> $vin_seg"
else
    ng "uSID decode wrong: wire='$frr_wire_sid' Vinbero='$vin_seg' want='$FRR_FULL_SID'"
fi

# 2d. The uSID-shaped SID Structure makes Vinbero install the route with
#     H.Encaps.Red (reduced encapsulation).
if dexec "$PE_TOKYO" vbctl headend-v4 list 2>/dev/null \
  | awk -v p="$OSAKA_PREFIX" '$1==p' | grep -q "H_ENCAPS_RED"; then
    ok "Vinbero installed $OSAKA_PREFIX with H.Encaps.Red"
else
    ng "Vinbero did not use H.Encaps.Red for the uSID route"
    dexec "$PE_TOKYO" vbctl headend-v4 list || true
fi

# --- 3. Vinbero -> FRR: SRv6 Service TLV encode ----------------------------
echo ""
echo "[3] Vinbero -> FRR  (SRv6 Service TLV encode)"

# Vinbero advertises the ce-tokyo subnet (10.1.0.0/24) into the L3VPN in
# vinbero/start.sh. Assert it reaches FRR's VPN RIB with the SID intact.
VIN_SID=fd00:100:1:1::
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

# 3b. Vinbero attaches the RFC 9252 SID Structure Sub-Sub-TLV
# (32/16/16/0) to the route. FRR accepts the route with or without it
# and exposes no structure in its show output or logs, so assert it on
# the wire: a route-refresh (soft in) makes pe-tokyo re-send its UPDATE
# while a capture runs, and the Sub-Sub-TLV appears as the byte
# sequence type 1, length 6, 32/16/16/0 with no transposition
# (hex 01 0006 20 10 10 00 00 00).
bgpcap=/tmp/usid_bgp.pcap
bgpcaperr=/tmp/usid_bgp.err
structure_on_wire() {
    dexec "$PE_OSAKA" sh -c "rm -f $bgpcap $bgpcaperr; pkill tcpdump" 2>/dev/null
    dexec "$PE_OSAKA" sh -c "timeout 20 tcpdump -ni eth2 -U -w $bgpcap 'tcp port 179' >/dev/null 2>$bgpcaperr" &
    BGPCAPPID=$!
    attached=0
    for _ in $(seq 1 30); do
        if dexec "$PE_OSAKA" grep -q "listening on" "$bgpcaperr" 2>/dev/null; then
            attached=1
            break
        fi
        sleep 0.5
    done
    if [ "$attached" -ne 1 ]; then
        # Capture never attached: sending the refresh now would lose the
        # UPDATE for good. Bail out to the retry instead.
        dexec "$PE_OSAKA" pkill tcpdump 2>/dev/null || true
        wait $BGPCAPPID 2>/dev/null || true
        return 1
    fi
    dexec "$PE_OSAKA" vtysh -c "clear bgp ipv4 vpn * soft in" >/dev/null 2>&1
    sleep 5
    dexec "$PE_OSAKA" pkill tcpdump 2>/dev/null || true
    wait $BGPCAPPID 2>/dev/null || true
    dexec "$PE_OSAKA" sh -c "od -An -tx1 $bgpcap | tr -d ' \n' | grep -q 010006201010000000"
}
if retry_n 3 structure_on_wire; then
    ok "Vinbero advertised the SID Structure Sub-Sub-TLV 32/16/16/0 on the wire"
else
    ng "SID Structure Sub-Sub-TLV 32/16/16/0 not seen in the BGP UPDATE"
fi

# 3c. FRR installs the VPN route into vrf-cust as an SRv6 encap route.
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

# Gate results accumulate here; a single failed gate makes 4a-4c
# pointless (minutes of doomed retries and cascade errors), so they are
# skipped -- the failed gate already failed the run.
gates_ok=1

# 4.0 READINESS GATE. The data plane settles asynchronously; ping only
# once every precondition holds, so a slow settle cannot flake the test.

# (a) both BGP sessions Established (FRR side checked above; re-gate so
#     section 4 is self-contained even if section 1 was slow).
if retry frr_established; then
    echo "  gate: iBGP session Established"
else
    ng "gate: iBGP session never reached Established"
    gates_ok=0
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
    gates_ok=0
fi
if retry gate_frr_rib; then
    echo "  gate: ce-tokyo prefix in FRR vrf-cust RIB"
else
    ng "gate: ce-tokyo prefix never installed in FRR vrf-cust RIB"
    gates_ok=0
fi

# (c) the decap endpoints exist on both PEs.
gate_vin_sid() {
    dexec "$PE_TOKYO" vbctl sid list 2>/dev/null | grep -q "fd00:100:1:1::"
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
    gates_ok=0
fi
if retry gate_frr_localsid; then
    echo "  gate: FRR seg6local End.DT4 localsid present"
else
    ng "gate: FRR seg6local End.DT4 localsid never appeared"
    gates_ok=0
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
    gates_ok=0
fi

# Warm the customer-side ARP so the first End.DT4 decap egress and the
# first H.Encaps customer ingress do not race NDP/ARP resolution.
dexec "$PE_TOKYO" ping -c 1 -W 2 "$CE_TOKYO_ADDR" >/dev/null 2>&1 || true
dexec "$PE_OSAKA" ip vrf exec vrf-cust ping -c 1 -W 2 "$CE_OSAKA_ADDR" >/dev/null 2>&1 || true

if [ "$gates_ok" -eq 1 ]; then
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

# 4c. Wire check: the Vinbero -> FRR direction must carry no SRH -- a
# single uSID under H.Encaps.Red is plain IPv4-in-IPv6. Capture on the
# core's pe-tokyo-facing link while pinging: IPIP (proto 4) packets must
# appear, routing-header packets must not.
# The core container is bare alpine without tcpdump; capture on the FRR
# PE's core-facing link instead, which sees the same packets.
cap=/tmp/usid_wire.pcap
caperr=/tmp/usid_wire.err
wire_capture() {
    dexec "$PE_OSAKA" sh -c "rm -f $cap $caperr; pkill tcpdump" 2>/dev/null
    # -U flushes per packet: without it the pcap header and packets sit in
    # tcpdump's stdio buffer and a file-size readiness gate never fires on
    # a slow runner. Readiness comes from tcpdump's own "listening on"
    # stderr line -- printed exactly when the capture is attached.
    dexec "$PE_OSAKA" sh -c "timeout 20 tcpdump -ni eth2 -U -w $cap 'ip6 dst net fd00:200:2::/48' >/dev/null 2>$caperr" &
    CAPPID=$!
    attached=0
    for _ in $(seq 1 30); do
        if dexec "$PE_OSAKA" grep -q "listening on" "$caperr" 2>/dev/null; then
            attached=1
            break
        fi
        sleep 0.5
    done
    if [ "$attached" -ne 1 ]; then
        # Capture never attached: pinging now proves nothing. Bail out to
        # the retry instead of counting an empty capture.
        dexec "$PE_OSAKA" pkill tcpdump 2>/dev/null || true
        wait $CAPPID 2>/dev/null || true
        return 1
    fi
    dexec "$CE_TOKYO" ping -c 5 -W 2 "$CE_OSAKA_ADDR" >/dev/null 2>&1 || true
    sleep 1
    dexec "$PE_OSAKA" pkill tcpdump 2>/dev/null || true
    wait $CAPPID 2>/dev/null || true
    ipip_count=$(dexec "$PE_OSAKA" sh -c "tcpdump -nr $cap 'ip6 proto 4' 2>/dev/null | wc -l")
    srh_count=$(dexec "$PE_OSAKA" sh -c "tcpdump -nr $cap 'ip6 proto 43' 2>/dev/null | wc -l")
    [ "${ipip_count:-0}" -gt 0 ]
}
# Retry the whole capture in case a run catches nothing at all.
retry_n 3 wire_capture || true
if [ "${ipip_count:-0}" -gt 0 ] && [ "${srh_count:-0}" -eq 0 ]; then
    ok "reduced encapsulation on the wire: $ipip_count IPIP packets, 0 SRH"
else
    ng "wire check failed: ipip=${ipip_count:-unset} srh=${srh_count:-unset} (want >0 / 0)"
    dexec "$PE_OSAKA" sh -c "tcpdump -nr $cap 2>/dev/null | head -5" || true
fi

else
    echo "  SKIP: data-plane checks (a readiness gate failed; see FAILs above)"
fi

# --- summary ---------------------------------------------------------------
echo ""
echo "=============================================="
echo " RESULT: $pass passed, $fail failed"
echo "=============================================="
[ "$fail" -eq 0 ] || exit 1
