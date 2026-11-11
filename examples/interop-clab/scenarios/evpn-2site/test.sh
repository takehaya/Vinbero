#!/usr/bin/env bash
# evpn-2site interop scenario assertions (Vinbero <-> Vinbero).
#
# Two Vinbero PEs run an SRv6 EVPN L2VPN (ELAN). They exchange customer MACs
# as BGP EVPN RT2 (MAC/IP) and their BUM flood endpoints as RT3 (Inclusive
# Multicast). It proves:
#   1. each PE LEARNED the peer's MAC over BGP -- the RT2 appears in fdb_map
#      as a remote entry pointing at a bd_peer, and the RT3 installs a second
#      bd_peer toward the peer's End.DT2M flood SID;
#   2. data plane, both directions: ce-tokyo <-> ce-osaka ping over the
#      stretched L2 domain, with the frame H.Encaps.L2'd toward the peer's
#      End.DT2U SID (outer DA on the core link);
#   3. BUM flood: the CEs resolve ARP dynamically (no static ARP) -- the ARP
#      broadcast is flooded over the EVPN, proving RT3 / End.DT2M works;
#   4. the EVPN binding pe-osaka made over the API comes back from the state
#      file when its vinberod restarts, and imports pe-tokyo's RT2 again.
#
# Exit non-zero on the first failed assertion.
set -u

PE_TOKYO=clab-evpn-2site-pe-tokyo
PE_OSAKA=clab-evpn-2site-pe-osaka
CORE=clab-evpn-2site-core
CE_TOKYO=clab-evpn-2site-ce-tokyo
CE_OSAKA=clab-evpn-2site-ce-osaka

CE_TOKYO_MAC=aa:bb:cc:00:00:10
CE_OSAKA_MAC=aa:bb:cc:00:00:20
CE_TOKYO_ADDR=10.0.0.10
CE_OSAKA_ADDR=10.0.0.20
TOKYO_DT2U=fd00:100:0:2::   # pe-tokyo End.DT2U SID (outer DA for osaka->tokyo)
OSAKA_DT2U=fd00:200:0:2::   # pe-osaka End.DT2U SID (outer DA for tokyo->osaka)
TOKYO_DT2M=fd00:100:0:3::   # pe-tokyo End.DT2M flood SID (RT3)
OSAKA_DT2M=fd00:200:0:3::   # pe-osaka End.DT2M flood SID (RT3)

pass=0
fail=0
ok() { echo "  PASS: $1"; pass=$((pass + 1)); }
ng() { echo "  FAIL: $1"; fail=$((fail + 1)); }

dexec() { docker exec "$@"; }

# Allow generous time for the iBGP session to establish and RT2/RT3 to
# replicate: two PEs starting together can take ~100s to converge.
retry()   { retry_n 75 "$@"; }
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
echo " evpn-2site interop test (EVPN RT2 over SRv6)"
echo "=============================================="

# --- 1. Each PE learned the peer's MAC over BGP (RT2 -> fdb_map) ------------
echo ""
echo "[1] customer MACs exchanged over BGP EVPN (RT2)"
# pe-tokyo must have ce-osaka's MAC as a remote FDB entry; pe-osaka must have
# ce-tokyo's. The MAC in the FDB came only from the peer's RT2.
tokyo_learned_osaka_mac() {
    dexec "$PE_TOKYO" vbctl fdb list 2>/dev/null | grep -iq "$CE_OSAKA_MAC"
}
osaka_learned_tokyo_mac() {
    dexec "$PE_OSAKA" vbctl fdb list 2>/dev/null | grep -iq "$CE_TOKYO_MAC"
}
if retry tokyo_learned_osaka_mac; then
    ok "pe-tokyo learned ce-osaka's MAC ($CE_OSAKA_MAC) via RT2"
    dexec "$PE_TOKYO" vbctl fdb list | sed 's/^/      /'
else
    ng "pe-tokyo did not learn ce-osaka's MAC"
    dexec "$PE_TOKYO" vbctl fdb list || true
fi
if retry osaka_learned_tokyo_mac; then
    ok "pe-osaka learned ce-tokyo's MAC ($CE_TOKYO_MAC) via RT2"
else
    ng "pe-osaka did not learn ce-tokyo's MAC"
    dexec "$PE_OSAKA" vbctl fdb list || true
fi

# Each PE must also have a bd_peer (the encap target the RT2 installed).
if retry bash -c "docker exec $PE_TOKYO vbctl bd-peer list 2>/dev/null | grep -q '$OSAKA_DT2U'"; then
    ok "pe-tokyo has a bd_peer toward pe-osaka's End.DT2U SID ($OSAKA_DT2U)"
else
    ng "pe-tokyo has no bd_peer toward $OSAKA_DT2U"
    dexec "$PE_TOKYO" vbctl bd-peer list || true
fi
if retry bash -c "docker exec $PE_OSAKA vbctl bd-peer list 2>/dev/null | grep -q '$TOKYO_DT2U'"; then
    ok "pe-osaka has a bd_peer toward pe-tokyo's End.DT2U SID ($TOKYO_DT2U)"
else
    ng "pe-osaka has no bd_peer toward $TOKYO_DT2U"
    dexec "$PE_OSAKA" vbctl bd-peer list || true
fi

# Each PE must also have the RT3 BUM flood bd_peer (the End.DT2M encap target
# the peer's RT3 installed). This is the second bd_peer per BD.
if retry bash -c "docker exec $PE_TOKYO vbctl bd-peer list 2>/dev/null | grep -q '$OSAKA_DT2M'"; then
    ok "pe-tokyo has a BUM flood bd_peer toward pe-osaka's End.DT2M SID ($OSAKA_DT2M)"
else
    ng "pe-tokyo has no BUM flood bd_peer toward $OSAKA_DT2M"
    dexec "$PE_TOKYO" vbctl bd-peer list || true
fi
if retry bash -c "docker exec $PE_OSAKA vbctl bd-peer list 2>/dev/null | grep -q '$TOKYO_DT2M'"; then
    ok "pe-osaka has a BUM flood bd_peer toward pe-tokyo's End.DT2M SID ($TOKYO_DT2M)"
else
    ng "pe-osaka has no BUM flood bd_peer toward $TOKYO_DT2M"
    dexec "$PE_OSAKA" vbctl bd-peer list || true
fi

# --- 2. Data plane: bidirectional L2, encapped toward the learned SID ------
echo ""
echo "[2] Data plane (stretched L2 over SRv6 EVPN)"

# l2_dir <src_ce> <dst_addr> <expect_outer_da> "<label>": ping one direction
# over the EVPN and confirm the frame is H.Encaps.L2'd toward the peer's
# End.DT2U SID by capturing that outer DA on the core's ingress link.
l2_dir() {
    local src_c=$1 dst=$2 outer_da=$3 label=$4
    if ! retry_n 45 bash -c "docker exec $src_c ping -c 2 -W 2 $dst >/dev/null 2>&1"; then
        ng "$label: ping failed"
        dexec "$src_c" ping -c 3 -W 2 "$dst" 2>&1 | sed 's/^/      /' || true
        return
    fi
    ok "$label: ping over the EVPN L2VPN"
    local cap; cap=$(mktemp)
    dexec "$CORE" timeout 8 tcpdump -nli any "ip6 and dst $outer_da" >"$cap" 2>/dev/null &
    local pid=$!
    sleep 1
    for _ in 1 2 3 4 5; do
        dexec "$src_c" ping -c 1 -W 2 "$dst" >/dev/null 2>&1
        sleep 1
    done
    wait "$pid" 2>/dev/null
    if grep -q "$outer_da" "$cap"; then
        ok "$label: outer DA = peer End.DT2U SID $outer_da (H.Encaps.L2 over SRv6 confirmed)"
        sed 's/^/      /' "$cap" | head -1
    else
        ng "$label: no packet with outer DA $outer_da (not encapped over the EVPN)"
    fi
    rm -f "$cap"
}

l2_dir "$CE_TOKYO" "$CE_OSAKA_ADDR" "$OSAKA_DT2U" "ce-tokyo -> ce-osaka"
l2_dir "$CE_OSAKA" "$CE_TOKYO_ADDR" "$TOKYO_DT2U" "ce-osaka -> ce-tokyo"

# --- 3. BUM flood: ARP resolved dynamically (no static ARP) ----------------
echo ""
echo "[3] BUM flood (ARP resolved over RT3 / End.DT2M)"
# The pings above resolved ARP with no static entries: the ARP broadcast was
# BUM-flooded over the EVPN toward the peer's End.DT2M SID, decapped into the
# peer bridge, and answered. A dynamic (non-PERMANENT) neighbour entry holding
# the peer's MAC proves the flood path works.
check_dynamic_arp() {
    local ce=$1 addr=$2 mac=$3 label=$4
    local entry
    entry=$(dexec "$ce" ip neigh show "$addr" dev eth1 2>/dev/null)
    if ! echo "$entry" | grep -iq "$mac"; then
        ng "$label: no resolved ARP entry for $addr ($entry)"
        return
    fi
    if echo "$entry" | grep -q PERMANENT; then
        ng "$label: ARP entry for $addr is PERMANENT (static), not flooded"
        return
    fi
    ok "$label: resolved $addr dynamically via BUM flood"
}
check_dynamic_arp "$CE_TOKYO" "$CE_OSAKA_ADDR" "$CE_OSAKA_MAC" "ce-tokyo"
check_dynamic_arp "$CE_OSAKA" "$CE_TOKYO_ADDR" "$CE_TOKYO_MAC" "ce-osaka"

# Directly capture the ARP broadcast encapped toward the peer's End.DT2M SID,
# isolating the RT3 flood path (a unicast-only setup could resolve ARP too, so
# the dynamic-resolve check above is necessary but not sufficient). Drop the
# resolved neighbour first (needs net-tools' arp -d) so the ping re-ARPs.
docker exec "$CE_TOKYO" apk add --no-cache net-tools >/dev/null 2>&1
docker exec "$CE_TOKYO" arp -d "$CE_OSAKA_ADDR" >/dev/null 2>&1
fcap=$(mktemp)
dexec "$CORE" timeout 8 tcpdump -nli any "ip6 and dst $OSAKA_DT2M" >"$fcap" 2>/dev/null &
fpid=$!
sleep 1
for _ in 1 2 3; do
    docker exec "$CE_TOKYO" ping -c 1 -W 2 "$CE_OSAKA_ADDR" >/dev/null 2>&1
    sleep 1
done
wait "$fpid" 2>/dev/null
if grep -qi "ARP" "$fcap"; then
    ok "ce-tokyo: ARP broadcast flooded toward End.DT2M SID $OSAKA_DT2M (RT3 flood path confirmed)"
    grep -i ARP "$fcap" | head -1 | sed 's/^/      /'
else
    ng "ce-tokyo: no ARP flood captured toward $OSAKA_DT2M (RT3 flood path not exercised)"
fi
rm -f "$fcap"

# --- 4. The EVPN binding made over the API survives a daemon restart --------
echo ""
echo "[4] pe-osaka's vinberod restarts with its EVPN binding"
# start.sh bound evi-100 with `vbctl vrf-bgp bind`. The daemon is restarted
# and not bound again: the binding comes back from the state file, the bridge
# facet with it. The maps are not pinned and LOC1 was registered over the
# API, so LOC1 is registered again (the source locator RT2 installs need);
# pe-tokyo's RT2 then installs ce-tokyo's MAC into bd 100 once more, which
# only a binding importing 65000:100 into evi-100 allows.
osaka_pid=$(dexec "$PE_OSAKA" cat /var/run/vinberod.pid)
dexec "$PE_OSAKA" kill -TERM "$osaka_pid"
# start.sh has exited, so nothing reaps the old daemon: a zombie counts as
# stopped.
osaka_stopped() {
    docker exec "$PE_OSAKA" sh -c "[ ! -e /proc/$osaka_pid ] || grep -q '^State:[[:space:]]*Z' /proc/$osaka_pid/status"
}
if retry_n 15 osaka_stopped; then
    ok "pe-osaka's vinberod stopped"
else
    ng "pe-osaka's vinberod did not stop"
fi
dexec -d "$PE_OSAKA" sh -c \
    'echo $$ > /var/run/vinberod.pid; exec /usr/local/bin/vinberod --bgp-enabled -c /etc/vinbero/vinbero.yaml >> /var/log/vinberod.log 2>&1'
# The new daemon says it restored the binding, so the checks below cannot be
# answered by the old one.
osaka_restored() {
    dexec "$PE_OSAKA" grep -q 'VRF bindings restored from the state file' /var/log/vinberod.log
}
if retry_n 30 bash -c "docker exec $PE_OSAKA vbctl locator list" && retry_n 15 osaka_restored; then
    ok "pe-osaka's vinberod is back and restored the bindings from its state file"
else
    ng "pe-osaka's vinberod did not come back with its bindings"
    dexec "$PE_OSAKA" tail -30 /var/log/vinberod.log || true
fi
osaka_bound() {
    dexec "$PE_OSAKA" vbctl vrf-bgp list 2>/dev/null | grep 'evi-100' | grep -qF 'evpn=[65000:100(import)]'
}
if osaka_bound; then
    ok "pe-osaka restored evi-100's binding (evpn import 65000:100) without a new bind"
else
    ng "pe-osaka lost evi-100's binding over the restart"
fi
dexec "$PE_OSAKA" vbctl vrf-bgp list | sed 's/^/      /'
dexec "$PE_OSAKA" vbctl locator create \
    --name LOC1 \
    --prefix fd00:200::/48 \
    --block-len 32 --node-len 16 --function-len 16 --argument-len 64 \
    --behavior classic >/dev/null
if retry osaka_learned_tokyo_mac; then
    ok "pe-osaka learned ce-tokyo's MAC ($CE_TOKYO_MAC) via RT2 again after the restart"
else
    ng "pe-osaka did not learn ce-tokyo's MAC after the restart"
    dexec "$PE_OSAKA" vbctl fdb list || true
fi

echo ""
echo "=============================================="
echo " RESULT: $pass passed, $fail failed"
echo "=============================================="
[ "$fail" -eq 0 ] || exit 1
