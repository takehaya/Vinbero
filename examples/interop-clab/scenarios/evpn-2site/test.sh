#!/usr/bin/env bash
# evpn-2site interop scenario assertions (Vinbero <-> Vinbero).
#
# Two Vinbero PEs run an SRv6 EVPN L2VPN (ELAN), exchanging customer MACs as
# BGP EVPN RT2 (MAC/IP). It proves:
#   1. each PE LEARNED the peer's MAC over BGP -- the RT2 appears in fdb_map
#      as a remote entry pointing at a bd_peer (the SAFI 70 session and the
#      RT2 / SRv6 L2 Service TLV decode both work);
#   2. data plane, both directions: ce-tokyo <-> ce-osaka ping over the
#      stretched L2 domain, with the frame H.Encaps.L2'd toward the peer's
#      End.DT2U SID (outer DA on the core link) -- BGP-learned RT2 actually
#      drives the L2 forwarding path.
#
# Scope: RT2 unicast only (the CEs carry static ARP, so no BUM flood is
# needed). Exit non-zero on the first failed assertion.
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

echo ""
echo "=============================================="
echo " RESULT: $pass passed, $fail failed"
echo "=============================================="
[ "$fail" -eq 0 ] || exit 1
