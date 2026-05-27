#!/usr/bin/env bash
# evpn-multihoming interop assertions (Vinbero 3-PE, dual-homed CE).
#
# pe1 + pe2 attach one Ethernet Segment (ES-1) for the dual-homed ce-mh; pe3 is
# the remote PE for ce-remote. It proves:
#   1. RT2/RT3/RT4 are exchanged (pe3 learns ce-mh's MAC; pe1 learns ce-remote's);
#   2. pe1 and pe2 independently elect the same DF (pe1, the lower encap source)
#      from each other's RT4 (RFC 8584);
#   3. data plane both directions: ce-mh <-> ce-remote over SRv6 EVPN;
#   4. BUM reaches ce-mh exactly once -- the DF forwards, the non-DF drops
#      (dt2m_non_df_drop), and split-horizon stops a PE re-flooding the other's
#      BUM back to the shared CE -- so ce-remote sees no duplicate replies.
set -u

PE1=clab-evpn-multihoming-pe1
PE2=clab-evpn-multihoming-pe2
PE3=clab-evpn-multihoming-pe3
CE_MH=clab-evpn-multihoming-ce-mh
CE_REMOTE=clab-evpn-multihoming-ce-remote

CE_MH_MAC=aa:bb:cc:00:00:10
CE_REMOTE_MAC=aa:bb:cc:00:00:30
CE_MH_ADDR=10.0.0.10
CE_REMOTE_ADDR=10.0.0.30
DF_SRC=fd00:100::   # pe1's encap source = the elected DF (lowest of pe1/pe2)

pass=0
fail=0
ok() { echo "  PASS: $1"; pass=$((pass + 1)); }
ng() { echo "  FAIL: $1"; fail=$((fail + 1)); }
dexec() { docker exec "$@"; }

# Two PEs plus DF election can take a while to converge.
retry() { retry_n 75 "$@"; }
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
echo " evpn-multihoming interop (RT4 DF + split-horizon)"
echo "=============================================="

# --- 1. RT2 exchange --------------------------------------------------------
echo ""
echo "[1] MAC exchange over BGP EVPN (RT2)"
if retry bash -c "docker exec $PE3 vbctl fdb list 2>/dev/null | grep -qi $CE_MH_MAC"; then
    ok "pe3 learned ce-mh's MAC ($CE_MH_MAC) via RT2"
else
    ng "pe3 did not learn ce-mh's MAC"
    dexec "$PE3" vbctl fdb list || true
fi
if retry bash -c "docker exec $PE1 vbctl fdb list 2>/dev/null | grep -qi $CE_REMOTE_MAC"; then
    ok "pe1 learned ce-remote's MAC ($CE_REMOTE_MAC) via RT2"
else
    ng "pe1 did not learn ce-remote's MAC"
    dexec "$PE1" vbctl fdb list || true
fi

# --- 2. DF election: pe1 and pe2 agree DF = pe1 (lowest encap source) -------
echo ""
echo "[2] DF election (RFC 8584; lowest PE source wins)"
# pe2's local PE is fd00:200::, so a matching fd00:100:: in its ES list can only
# be the elected DF (pe1) -- proving both PEs ran the same election.
if retry bash -c "docker exec $PE1 vbctl es list 2>/dev/null | grep -qi $DF_SRC"; then
    ok "pe1 elected DF = $DF_SRC (pe1)"
else
    ng "pe1 did not elect DF $DF_SRC"
    dexec "$PE1" vbctl es list || true
fi
if retry bash -c "docker exec $PE2 vbctl es list 2>/dev/null | grep -qi $DF_SRC"; then
    ok "pe2 agrees DF = $DF_SRC (pe1)"
    dexec "$PE2" vbctl es list | sed 's/^/      /'
else
    ng "pe2 did not agree DF $DF_SRC"
    dexec "$PE2" vbctl es list || true
fi

# --- 3. Data plane both directions ------------------------------------------
echo ""
echo "[3] Data plane (ce-mh <-> ce-remote over SRv6 EVPN)"
if retry_n 45 bash -c "docker exec $CE_MH ping -c 2 -W 2 $CE_REMOTE_ADDR >/dev/null 2>&1"; then
    ok "ce-mh -> ce-remote: ping over the EVPN L2VPN"
else
    ng "ce-mh -> ce-remote: ping failed"
    dexec "$CE_MH" ping -c 2 -W 2 "$CE_REMOTE_ADDR" 2>&1 | sed 's/^/      /' || true
fi
if retry_n 45 bash -c "docker exec $CE_REMOTE ping -c 2 -W 2 $CE_MH_ADDR >/dev/null 2>&1"; then
    ok "ce-remote -> ce-mh: ping over the EVPN L2VPN"
else
    ng "ce-remote -> ce-mh: ping failed"
    dexec "$CE_REMOTE" ping -c 2 -W 2 "$CE_MH_ADDR" 2>&1 | sed 's/^/      /' || true
fi

# --- 4. BUM single delivery (DF forwards, non-DF drops, no re-flood) --------
echo ""
echo "[4] BUM single delivery to the dual-homed CE"
# Re-ARP from ce-remote so the request is BUM-flooded to both pe1/pe2's
# End.DT2M; only the DF (pe1) delivers to ce-mh and split-horizon prevents a
# loop, so ce-remote must see no duplicate (DUP!) ICMP replies.
docker exec "$CE_REMOTE" apk add --no-cache net-tools >/dev/null 2>&1
docker exec "$CE_REMOTE" arp -d "$CE_MH_ADDR" >/dev/null 2>&1
dup=$(docker exec "$CE_REMOTE" ping -c 3 -W 2 "$CE_MH_ADDR" 2>&1 | grep -c "DUP!")
if [ "$dup" -eq 0 ]; then
    ok "ce-remote -> ce-mh: no duplicate replies (single DF delivery + split-horizon)"
else
    ng "ce-remote -> ce-mh: $dup duplicate reply/replies (multi-homing double-delivery)"
fi

echo ""
echo "=============================================="
echo " RESULT: $pass passed, $fail failed"
echo "=============================================="
[ "$fail" -eq 0 ] || exit 1
