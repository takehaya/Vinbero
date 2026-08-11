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
#      BUM back to the shared CE -- so ce-remote sees no duplicate replies;
#   5. RT1 aliasing: both PEs advertise per-ES (all-active) + per-EVI A-D, so
#      pe3 folds ES-1 into one EVPN ECMP group with a member per PE;
#   6. RT1 mass withdraw: withdrawing pe2's per-ES route shrinks the group to
#      pe1 in one update, traffic survives, and re-advertising heals it.
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
ESI=00:00:00:00:00:00:00:00:00:01
DF_SRC=fd00:100::   # pe1's encap source = the elected DF (lowest of pe1/pe2)

pass=0
fail=0
ok() { echo "  PASS: $1"; pass=$((pass + 1)); }
ng() { echo "  FAIL: $1"; fail=$((fail + 1)); }
dexec() { docker exec "$@"; }

# DF_PE is the 4th column of `vbctl es list` (ESI, LOCAL_ATTACHED, LOCAL_PE,
# DF_PE, MODE). Reading the column -- not grepping the whole line -- avoids a
# false pass: on pe1 the LOCAL_PE column is also fd00:100::, so a substring
# match would succeed even with no DF elected. When DF_PE is empty the columns
# shift and $4 holds MODE, which never equals an address, so the check fails.
df_pe() { docker exec "$1" vbctl es list 2>/dev/null | awk -v e="$ESI" '$1==e {print $4}'; }
df_is() { [ "$(df_pe "$1")" = "$2" ]; }

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
# Assert the DF_PE column on both PEs equals fd00:100:: (pe1). Both PEs run the
# election independently, so agreement proves they computed the same result.
if retry df_is "$PE1" "$DF_SRC"; then
    ok "pe1 elected DF = $DF_SRC (pe1) [DF_PE column]"
else
    ng "pe1 did not elect DF $DF_SRC (DF_PE=$(df_pe "$PE1"))"
    dexec "$PE1" vbctl es list || true
fi
if retry df_is "$PE2" "$DF_SRC"; then
    ok "pe2 agrees DF = $DF_SRC (pe1) [DF_PE column]"
    dexec "$PE2" vbctl es list | sed 's/^/      /'
else
    ng "pe2 did not agree DF $DF_SRC (DF_PE=$(df_pe "$PE2"))"
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
#
# Flush the resolved neighbour so the next ping re-ARPs. Use busybox `ip neigh
# flush` (always present, no runtime apk -- net-tools arp -d would need an
# `apk add` that fails on a CI runner with no Alpine mirror), falling back to
# bouncing the access link (which also clears the cache). Critically, ASSERT the
# entry is gone before counting DUP!: under `set -u` (no -e) a failed flush would
# otherwise leave the step-3 entry resolved, the ping would not re-flood, and
# dup=0 would pass without exercising DF or split-horizon at all.
docker exec "$CE_REMOTE" ip neigh flush dev eth1 >/dev/null 2>&1 \
    || docker exec "$CE_REMOTE" sh -c "ip link set dev eth1 down; ip link set dev eth1 up" >/dev/null 2>&1 \
    || true
sleep 1
if docker exec "$CE_REMOTE" ip neigh show "$CE_MH_ADDR" dev eth1 2>/dev/null \
        | grep -qiE "REACHABLE|STALE|DELAY|PROBE|PERMANENT"; then
    ng "ce-remote: $CE_MH_ADDR neighbour not flushed (setup failed); BUM single-delivery not asserted"
else
    dup=$(docker exec "$CE_REMOTE" ping -c 3 -W 2 "$CE_MH_ADDR" 2>&1 | grep -c "DUP!")
    if [ "$dup" -eq 0 ]; then
        ok "ce-remote -> ce-mh: no duplicate replies (single DF delivery + split-horizon)"
    else
        ng "ce-remote -> ce-mh: $dup duplicate reply/replies (multi-homing double-delivery)"
    fi
fi

# --- 5. RT1 aliasing: pe3 aggregates ES-1 into one ECMP group ---------------
echo ""
echo "[5] RT1 aliasing (pe3 spreads ES-1 unicast across pe1+pe2)"
# pe1 and pe2 both advertise the two RT1 forms for ES-1 (per-ES all-active +
# per-EVI with their own End.DT2U SID), so pe3 must fold them into one EVPN
# ECMP group -- group ids at or above 0x80000000 are the EVPN partition -- with
# one member per PE, and point ce-mh's MAC at that group instead of a single PE.
EVPN_GROUP_BASE=2147483648

es_group_json() { docker exec "$PE3" vbctl --json headend-group list 2>/dev/null; }
es_group_members() {
    es_group_json | python3 -c "
import sys, json
groups = json.load(sys.stdin) or []
for g in groups:
    if (g.get('group_id') or 0) >= $EVPN_GROUP_BASE:
        print(len(g.get('members') or []))
        sys.exit(0)
print(0)"
}
es_group_member_count_is() { [ "$(es_group_members)" = "$1" ]; }

if retry es_group_member_count_is 2; then
    ok "pe3 built the EVPN ES group with one member per PE (pe1+pe2)"
else
    ng "pe3 has no two-member EVPN ES group (members=$(es_group_members))"
    es_group_json || true
fi

es_group_sids() {
    es_group_json | python3 -c "
import sys, json
groups = json.load(sys.stdin) or []
for g in groups:
    if (g.get('group_id') or 0) >= $EVPN_GROUP_BASE:
        for m in g.get('members') or []:
            print((m.get('segments') or [''])[0])
"
}
sids=$(es_group_sids)
if echo "$sids" | grep -q "fd00:100:" && echo "$sids" | grep -q "fd00:200:"; then
    ok "group members carry one End.DT2U SID per PE (fd00:100:: / fd00:200::)"
else
    ng "group member SIDs do not span both PEs: $sids"
fi

# Aliased unicast must still deliver (whichever member the flow hashes to).
if retry_n 10 bash -c "docker exec $CE_REMOTE ping -c 2 -W 2 $CE_MH_ADDR >/dev/null 2>&1"; then
    ok "ce-remote -> ce-mh unicast works over the aliased group"
else
    ng "ce-remote -> ce-mh unicast broken after aliasing"
fi

# --- 6. RT1 mass withdraw: dropping pe2's per-ES shrinks the group ----------
echo ""
echo "[6] RT1 mass withdraw (pe2 leaves, traffic survives, pe2 returns)"
# Withdrawing pe2's per-ES route is the RFC 7432 §8.2 mass-withdraw signal:
# pe3 must drop pe2 from the ES group in one update -- no per-MAC withdraws --
# while unicast keeps flowing through pe1.
docker exec "$PE2" vbctl bgp withdraw-evpn-ad --rd 65100:2 \
    --esi "$ESI" --per-es >/dev/null 2>&1 || true

if retry_n 15 es_group_member_count_is 1; then
    ok "pe3 shrank the ES group to pe1 only on pe2's per-ES withdraw"
else
    ng "pe3 did not converge to one member (members=$(es_group_members))"
    es_group_json || true
fi
if retry_n 10 bash -c "docker exec $CE_REMOTE ping -c 2 -W 2 $CE_MH_ADDR >/dev/null 2>&1"; then
    ok "ce-remote -> ce-mh unicast survives the mass withdraw"
else
    ng "ce-remote -> ce-mh unicast broken after the mass withdraw"
fi

# Re-advertise and the group must heal back to two members.
docker exec "$PE2" vbctl bgp advertise-evpn-ad --rd 65100:2 --esi "$ESI" \
    --route-targets 65000:100 --per-es --next-hop 2001:db8:ff::2 >/dev/null 2>&1 || true

if retry_n 15 es_group_member_count_is 2; then
    ok "pe3 restored the two-member group on pe2's re-advertise"
else
    ng "pe3 did not restore two members (members=$(es_group_members))"
    es_group_json || true
fi

echo ""
echo "=============================================="
echo " RESULT: $pass passed, $fail failed"
echo "=============================================="
[ "$fail" -eq 0 ] || exit 1
