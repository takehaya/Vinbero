#!/usr/bin/env bash
# mup-2site interop scenario assertions.
#
# A MUP Controller (mup-c) advertises BGP MUP routes (SAFI 85); a Vinbero MUP-GW
# and MUP-PE program the SRv6 GTP data plane; emulated gNB / DN drive real traffic.
# It proves, end to end:
#   1. control plane: mup-gw installs the T2ST uplink F-TEID gate, mup-pe
#      installs the T1ST downlink H.Encaps (apply log + headend_v4 map), and
#      the downlink outer IPv6 source embeds the UPF N3 anchor per
#      RFC 9433 §6.6 (per-VRF mup_gtp4_source_prefix + same-RD T2ST endpoint);
#   2. uplink data: gNB GTP-U -> mup-gw (F-TEID) -SRv6-> mup-pe (End.DT4) ->
#      DN receives the decapped inner packet;
#   3. downlink data: DN -> mup-pe (H.Encaps) -SRv6-> mup-gw (End.M.GTP4.E)
#      -> gNB receives GTP-U sourced from the UPF anchor.
set -u

P=clab-mup-2site
GNB=$P-gnb; PA=$P-mup-gw; PD=$P-mup-pe; DN=$P-dn

UE=10.1.0.1            # T1ST UE prefix
DNHOST=10.0.0.1        # DN host (uplink inner dst)
N3=172.16.0.254        # T2ST endpoint (gNB's GTP-U outer dst)
TEID=256               # session TEID (0x100)

pass=0; fail=0
ok() { echo "  PASS: $1"; pass=$((pass + 1)); }
ng() { echo "  FAIL: $1"; fail=$((fail + 1)); }
dexec() { docker exec "$@"; }
retry() { local i; for i in $(seq 1 30); do "$@" >/dev/null 2>&1 && return 0; sleep 2; done; return 1; }

echo "=============================================="
echo " mup-2site interop (MUP-C -> MUP-GW/MUP-PE -> gNB/DN data path)"
echo "=============================================="

# --- 1. Control plane: SID resolution then data-plane install ---------------
# The controller's T1ST/T2ST carry NO SID, so an install can ONLY happen if the
# edge node resolved the SID from its peer's segment-discovery route (RFC 9433 §3).
# RDs are per-advertiser (sessions 65100:1, ISD 65100:11, DSD 65100:12) and VPN
# membership is the RT alone (downlink 100:2000, uplink 100:6000), so both
# installs below also prove the resolution is RT-scoped across RDs, and the
# T1ST/T2ST pass mup-pe's mup_ipv4 import-RT filter.
echo ""; echo "[1] control plane (SID resolution + apply from BGP MUP)"
if retry bash -c "docker exec $PD grep -q 'MUP ISD segment discovery' /var/log/vinberod.log"; then
    ok "mup-pe received mup-gw's ISD (interwork segment discovery)"
else
    ng "mup-pe never received the ISD (full-mesh iBGP or advertise failed)"
fi
if retry bash -c "docker exec $PD vbctl headend-v4 list 2>/dev/null | grep -q '$UE'" \
   && retry bash -c "docker exec $PD grep -q 'MUP T1ST downlink installed' /var/log/vinberod.log"; then
    ok "mup-pe resolved the T1ST against the ISD and installed the downlink H.Encaps for $UE/32"
else
    ng "mup-pe did not resolve/install the T1ST downlink"; dexec "$PD" vbctl headend-v4 list || true
fi
# RFC 9433 §6.6 source embed: the binding for RD 65100:1 carries
# mup_gtp4_source_prefix fd00:d::/64 and the same-RD T2ST endpoint
# ($N3 = ac10:00fe) is the UPF anchor, so the downlink headend SRC ADDR must
# read exactly fd00:d::ac10:fe:0:0 -- not the plain locator-derived encap
# source.
EMBED_SRC="fd00:d::ac10:fe:0:0"
if retry bash -c "docker exec $PD vbctl headend-v4 list 2>/dev/null | grep -qF '$EMBED_SRC'"; then
    ok "mup-pe downlink outer source embeds the UPF N3 anchor ($N3 at v4src position 64: $EMBED_SRC)"
else
    ng "mup-pe downlink outer source does not embed the UPF anchor (expected SRC ADDR $EMBED_SRC)"
    dexec "$PD" vbctl headend-v4 list || true
fi
if retry bash -c "docker exec $PA grep -q 'MUP DSD segment discovery' /var/log/vinberod.log"; then
    ok "mup-gw received mup-pe's DSD (direct segment discovery)"
else
    ng "mup-gw never received the DSD (full-mesh iBGP or advertise failed)"
fi
if retry bash -c "docker exec $PA vbctl headend-v4 list 2>/dev/null | grep -q '$N3'" \
   && retry bash -c "docker exec $PA grep -q 'MUP T2ST uplink installed' /var/log/vinberod.log"; then
    ok "mup-gw resolved the T2ST against the DSD and installed the uplink F-TEID gate for $N3/32"
else
    ng "mup-gw did not resolve/install the T2ST uplink gate"; dexec "$PA" vbctl headend-v4 list || true
fi

# --- 2. Uplink: gNB GTP-U -> ... -> DN receives the inner packet ------------
echo ""; echo "[2] uplink data plane (gNB GTP-U -> SRv6 -> End.DT4 -> DN)"
ucap=$(mktemp)
dexec "$DN" timeout 10 tcpdump -nli eth1 "icmp and src $UE" >"$ucap" 2>/dev/null &
upid=$!
sleep 1
for _ in 1 2 3; do
    dexec "$GNB" python3 /send_gtpu.py --n3-endpoint "$N3" --teid "$TEID" \
        --inner-src "$UE" --inner-dst "$DNHOST" --count 3 >/dev/null 2>&1
    sleep 1
done
wait "$upid" 2>/dev/null
if grep -q "$UE > $DNHOST" "$ucap" || grep -qi "$UE" "$ucap"; then
    ok "DN received the decapped uplink inner packet ($UE -> $DNHOST)"
    sed 's/^/      /' "$ucap" | head -2
else
    ng "DN did not receive the uplink inner packet"
    echo "      mup-gw uplink entries:"; dexec "$PA" vbctl headend-v4 list 2>/dev/null | sed 's/^/      /' || true
fi
rm -f "$ucap"

# --- 3. Downlink: DN -> ... -> gNB receives GTP-U ---------------------------
echo ""; echo "[3] downlink data plane (DN -> SRv6 -> End.M.GTP4.E -> gNB GTP-U)"
dcap=$(mktemp)
dexec "$GNB" timeout 10 tcpdump -nli eth1 "udp port 2152" >"$dcap" 2>/dev/null &
dpid=$!
sleep 1
dexec "$DN" ping -c 5 -i 0.5 -W 2 "$UE" >/dev/null 2>&1 &
wait "$dpid" 2>/dev/null
# The GTP-U must be sourced from the UPF N3 anchor and addressed to the gNB
# endpoint, not just be any UDP/2152 packet. Match the source IP only, not the
# UDP source port (the GTP-U source port is implementation-defined). Escape
# the dots so they stay literal in the regex.
N3_RE=${N3//./\\.}
if grep -qE "$N3_RE\.[0-9]+ > 172\.16\.0\.1\.2152" "$dcap"; then
    ok "gNB received downlink GTP-U from the UPF anchor ($N3) for the UE session"
    sed 's/^/      /' "$dcap" | head -2
else
    ng "gNB did not receive downlink GTP-U sourced from the UPF anchor $N3"
    sed 's/^/      /' "$dcap" | head -4
    echo "      mup-pe headend entries:"; dexec "$PD" vbctl headend-v4 list 2>/dev/null | sed 's/^/      /' || true
fi
rm -f "$dcap"

echo ""
echo "=============================================="
echo " RESULT: $pass passed, $fail failed"
echo "=============================================="
[ "$fail" -eq 0 ] || exit 1
