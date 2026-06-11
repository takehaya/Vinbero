#!/usr/bin/env bash
# mup-2site-multivrf interop scenario assertions.
#
# Two MUP service instances (VPN-A / VPN-B) overlap everywhere a VPN may
# overlap: same N3 endpoint, same TEID, same inner UE and DN addressing. The
# GW's uplink instances (vrf-bgp --mup-uplink-interfaces) key the F-TEID
# lookup by ingress ifindex; the PE's per-VPN End.DT4 delivers into separate
# kernel VRFs. It proves, end to end:
#   1. control plane: the GW installs BOTH T2STs — identical {endpoint, TEID}
#      — under distinct uplink instances, behind one shared gate;
#   2. uplink isolation A: a GTP-U burst from gnb-a reaches dn-a and ONLY
#      dn-a, even though dn-b would accept the byte-identical inner packet;
#   3. uplink isolation B: the mirror case from gnb-b.
set -u

P=clab-mup-2site-multivrf
GNBA=$P-gnb-a; GNBB=$P-gnb-b; GW=$P-mup-gw; PE=$P-mup-pe; DNA=$P-dn-a; DNB=$P-dn-b

N3=172.16.0.254        # shared N3 endpoint (both VPNs)
TEID=256               # shared session TEID (both VPNs)
UE=10.1.0.1            # shared inner UE address (both VPNs)
DNHOST=10.0.0.1        # shared DN host (both VPNs)

pass=0; fail=0
ok() { echo "  PASS: $1"; pass=$((pass + 1)); }
ng() { echo "  FAIL: $1"; fail=$((fail + 1)); }
dexec() { docker exec "$@"; }
retry() { local i; for i in $(seq 1 30); do "$@" >/dev/null 2>&1 && return 0; sleep 2; done; return 1; }

echo "=============================================="
echo " mup-2site-multivrf interop (two VPNs, one GW, overlapping F-TEIDs)"
echo "=============================================="

# --- 1. Control plane: both T2STs install under distinct instances ----------
echo ""; echo "[1] control plane (per-instance F-TEID install)"
if retry bash -c "docker exec $GW grep -c 'MUP DSD segment discovery' /var/log/vinberod.log | grep -q '^2$'"; then
    ok "mup-gw received both per-VPN DSDs"
else
    ng "mup-gw did not receive both DSDs"; dexec "$GW" grep 'MUP DSD' /var/log/vinberod.log || true
fi
# The two T2STs carry the SAME {endpoint, TEID}; without instances the second
# install would overwrite the first. The install log carries the instance the
# F-TEID entry was keyed under (bind order in mup-gw/start.sh: vpn-a=1, vpn-b=2).
if retry bash -c "docker exec $GW grep 'MUP T2ST uplink installed' /var/log/vinberod.log | grep -q '\"instance\": 1'" \
   && retry bash -c "docker exec $GW grep 'MUP T2ST uplink installed' /var/log/vinberod.log | grep -q '\"instance\": 2'"; then
    ok "mup-gw installed both overlapping T2STs under distinct uplink instances (1 and 2)"
else
    ng "mup-gw did not install both T2STs under distinct instances"
    dexec "$GW" grep 'MUP T2ST' /var/log/vinberod.log | sed 's/^/      /' || true
fi
if retry bash -c "docker exec $GW vbctl headend-v4 list 2>/dev/null | grep -c '$N3' | grep -q '^1$'"; then
    ok "the F-TEID gate on $N3/32 is shared (installed once across instances)"
else
    ng "unexpected gate state for $N3"; dexec "$GW" vbctl headend-v4 list || true
fi

# run_isolation SENDER WANT_DN OTHER_DN LABEL_WANT LABEL_OTHER
# Sends a GTP-U burst from SENDER and asserts the decapped inner packet
# reaches WANT_DN and only WANT_DN. The inner packets of the two VPNs are
# byte-identical, so which DN container captures them is the entire signal.
run_isolation() {
    local sender=$1 want=$2 other=$3 lwant=$4 lother=$5
    local wcap ocap wpid opid
    wcap=$(mktemp); ocap=$(mktemp)
    dexec "$want" timeout 10 tcpdump -nnli eth1 "icmp and src $UE" >"$wcap" 2>/dev/null &
    wpid=$!
    dexec "$other" timeout 10 tcpdump -nnli eth1 "icmp and src $UE" >"$ocap" 2>/dev/null &
    opid=$!
    sleep 1
    for _ in 1 2 3; do
        dexec "$sender" python3 /send_gtpu.py --n3-endpoint "$N3" --teid "$TEID" \
            --inner-src "$UE" --inner-dst "$DNHOST" --count 3 >/dev/null 2>&1
        sleep 1
    done
    wait "$wpid" "$opid" 2>/dev/null
    if grep -q "$UE > $DNHOST" "$wcap"; then
        ok "$lwant received the decapped uplink inner packet"
        sed 's/^/      /' "$wcap" | head -2
    else
        ng "$lwant did not receive the uplink inner packet"
        echo "      mup-gw uplink state:"; dexec "$GW" vbctl headend-v4 list 2>/dev/null | sed 's/^/      /' || true
    fi
    if grep -q "$UE > $DNHOST" "$ocap"; then
        ng "$lother received traffic that belongs to the other VPN (instance leak)"
        sed 's/^/      /' "$ocap" | head -4
    else
        ok "$lother received nothing (no cross-instance leak)"
    fi
    rm -f "$wcap" "$ocap"
}

# --- 2. Uplink isolation, VPN-A ----------------------------------------------
echo ""; echo "[2] uplink isolation VPN-A (gnb-a -> instance 1 -> vrf-a -> dn-a)"
run_isolation "$GNBA" "$DNA" "$DNB" "dn-a" "dn-b"

# --- 3. Uplink isolation, VPN-B ----------------------------------------------
echo ""; echo "[3] uplink isolation VPN-B (gnb-b -> instance 2 -> vrf-b -> dn-b)"
run_isolation "$GNBB" "$DNB" "$DNA" "dn-b" "dn-a"

echo ""
echo "=============================================="
echo " RESULT: $pass passed, $fail failed"
echo "=============================================="
[ "$fail" -eq 0 ] || exit 1
