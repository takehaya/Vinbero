#!/usr/bin/env bash
# ecmp-2site interop scenario assertions (Vinbero <-> FRR x2).
#
# Verifies, against a running `make deploy` lab, the things the scenario
# exists to prove:
#   1. both iBGP sessions are ESTABLISHED;
#   2. Vinbero aggregates the two FRR PEs' advertisements of ONE customer
#      prefix into a single ECMP group with two members;
#   3. the prober tracks both paths (their loopbacks) as up;
#   4. data plane: flows from twelve distinct sources reach ce-osaka and
#      actually spread over BOTH FRR PEs;
#   5. fast reroute: cutting pe-osaka-b's underlay mid-path is detected
#      by the prober (BGP hold time is 30s, deliberately too slow to
#      help) and every flow keeps working through pe-osaka-a;
#   6. recovery: restoring the link brings the path back and flows
#      spread again.
#
# Exit non-zero on the first failed assertion.
set -u

PE_TOKYO=clab-ecmp-2site-pe-tokyo
PE_OSAKA_A=clab-ecmp-2site-pe-osaka-a
PE_OSAKA_B=clab-ecmp-2site-pe-osaka-b
CORE=clab-ecmp-2site-core
CE_TOKYO=clab-ecmp-2site-ce-tokyo
CE_OSAKA=clab-ecmp-2site-ce-osaka

OSAKA_PREFIX=10.2.0.0/24
CE_OSAKA_IP=10.2.0.10
VIN_LOOPBACK=2001:db8:ff::1
FRR_A_LOOPBACK=2001:db8:ff::2
FRR_B_LOOPBACK=2001:db8:ff::3
# The twelve inner sources the spread test pings from.
SRCS=$(seq 10 21 | sed 's/^/10.1.0./')

VBCTL="/usr/local/bin/vbctl"

pass=0
fail=0
ok()   { echo "  PASS: $1"; pass=$((pass + 1)); }
ng()   { echo "  FAIL: $1"; fail=$((fail + 1)); }

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
echo " ecmp-2site interop scenario test (Vinbero <-> FRR x2)"
echo "=============================================="

# --- 1. both iBGP sessions ESTABLISHED -------------------------------------
echo ""
echo "[1] iBGP sessions ESTABLISHED"

frr_established() {
    dexec "$1" vtysh -c "show bgp summary json" 2>/dev/null \
      | python3 -c "import sys,json; d=json.load(sys.stdin); \
sys.exit(0 if d.get('ipv4Vpn',{}).get('peers',{}).get('$VIN_LOOPBACK',{}).get('state')=='Established' else 1)"
}
for pe in "$PE_OSAKA_A" "$PE_OSAKA_B"; do
    if retry frr_established "$pe"; then
        ok "$pe sees peer $VIN_LOOPBACK Established (ipv4 vpn)"
    else
        ng "$pe peer $VIN_LOOPBACK not Established"
        dexec "$pe" vtysh -c "show bgp summary" || true
    fi
done

# --- 2. one prefix, one group, two members ---------------------------------
echo ""
echo "[2] ECMP aggregation (two PEs -> one group)"

group_json() {
    dexec "$PE_TOKYO" "$VBCTL" --json headend-group list 2>/dev/null
}
group_has_two_members() {
    group_json | python3 -c "
import sys, json
groups = json.load(sys.stdin) or []
for g in groups:
    if '$OSAKA_PREFIX' in (g.get('prefixes') or []) and len(g.get('members') or []) == 2:
        sys.exit(0)
sys.exit(1)"
}
if retry group_has_two_members; then
    ok "one ECMP group holds both PEs' paths for $OSAKA_PREFIX"
else
    ng "no two-member group for $OSAKA_PREFIX"
    group_json || true
fi

group_member_sids() {
    group_json | python3 -c "
import sys, json
groups = json.load(sys.stdin) or []
for g in groups:
    if '$OSAKA_PREFIX' in (g.get('prefixes') or []):
        for m in g.get('members') or []:
            print(m.get('segments', [''])[0])
"
}
sids=$(group_member_sids)
if echo "$sids" | grep -q "fd00:200:" && echo "$sids" | grep -q "fd00:300:"; then
    ok "group members carry one SID per FRR locator (fd00:200:: / fd00:300::)"
else
    ng "group member SIDs do not span both locators: $sids"
fi

# --- 3. prober tracks both paths -------------------------------------------
echo ""
echo "[3] prober state"

prober_json() {
    dexec "$PE_TOKYO" "$VBCTL" --json prober status 2>/dev/null
}
prober_paths_up() {
    # $1 = expected number of up paths among the group's two.
    prober_json | python3 -c "
import sys, json
d = json.load(sys.stdin)
if not d.get('enabled'):
    sys.exit(1)
paths = [p for p in d.get('paths') or [] if p.get('dst') in ('$FRR_A_LOOPBACK', '$FRR_B_LOOPBACK')]
up = [p for p in paths if p.get('up')]
sys.exit(0 if len(paths) == 2 and len(up) == $1 else 1)"
}
if retry prober_paths_up 2; then
    ok "prober probes both PE loopbacks and reports them up"
else
    ng "prober does not report two up paths"
    prober_json || true
fi

# --- 4. data plane: reachability + spread over both PEs ---------------------
echo ""
echo "[4] data plane spread"

ping_from() {
    dexec "$CE_TOKYO" ping -c 1 -W 2 -I "$1" "$CE_OSAKA_IP"
}
# Readiness gate: the first source pings through before anything is
# measured, so slow convergence cannot masquerade as a spread failure.
if retry ping_from 10.1.0.10; then
    ok "ce-tokyo reaches ce-osaka through the L3VPN"
else
    ng "ce-tokyo cannot reach ce-osaka at all"
fi

rx_bytes() { dexec "$1" cat "/sys/class/net/eth2/statistics/rx_bytes"; }

# warm_arp resolves every source's ARP entry on the Vinbero PE through the
# kernel path. The End.DT4 return delivery is a BPF FIB lookup, which
# reports NO_NEIGH (and the XDP program drops) for a neighbour the kernel
# has never resolved -- it does not trigger resolution itself.
warm_arp() {
    local src
    for src in $SRCS; do
        dexec "$PE_TOKYO" ping -c 1 -W 2 "$src" >/dev/null 2>&1 || true
    done
}

burst() {
    # 20 large pings from every source; per flow ~26KB towards its PE.
    local src rc=0
    warm_arp
    for src in $SRCS; do
        if ! dexec "$CE_TOKYO" ping -c 20 -s 1200 -i 0.05 -W 2 -q -I "$src" "$CE_OSAKA_IP" >/dev/null 2>&1; then
            echo "    (ping from $src failed)"
            rc=1
        fi
    done
    return $rc
}

a0=$(rx_bytes "$PE_OSAKA_A"); b0=$(rx_bytes "$PE_OSAKA_B")
if burst; then
    ok "all twelve sources ping through"
else
    ng "some sources cannot ping"
fi
a1=$(rx_bytes "$PE_OSAKA_A"); b1=$(rx_bytes "$PE_OSAKA_B")
da=$((a1 - a0)); db=$((b1 - b0))
# Threshold 40KB: one flow's worth (~26KB) plus background noise clears
# it, pure noise (probes, keepalives) stays well under it.
if [ "$da" -gt 40000 ] && [ "$db" -gt 40000 ]; then
    ok "flows spread over both PEs (pe-a +${da}B, pe-b +${db}B)"
else
    ng "flows did not spread (pe-a +${da}B, pe-b +${db}B)"
fi

# --- 5. fast reroute on a mid-path underlay failure -------------------------
echo ""
echo "[5] fast reroute (cut pe-osaka-b's underlay)"

# The cut removes core's routes towards pe-osaka-b rather than downing
# the link: an admin link-down flushes the IPv6 addresses on BOTH veth
# ends and nothing restores them, which would break the lab beyond what
# a path failure means. Route removal is the same mid-path blackhole
# the prober exists to catch, and is cleanly reversible.
dexec "$CORE" ip -6 route del 2001:db8:ff::3/128 2>/dev/null || true
dexec "$CORE" ip -6 route del fd00:300::/48 2>/dev/null || true
# The prober must notice within a few hundred ms. The assertion polls
# fast and bounds the total elapsed time at 5 seconds -- generous for
# the docker-exec plumbing, still far under the 30s BGP hold time, so a
# BGP withdraw can never be what passes this check.
mask_start=$(date +%s%N)
masked=""
for i in $(seq 1 25); do
    if prober_paths_up 1 >/dev/null 2>&1; then masked=yes; break; fi
    sleep 0.2
done
mask_ms=$(( ($(date +%s%N) - mask_start) / 1000000 ))
if [ -n "$masked" ] && [ "$mask_ms" -lt 5000 ]; then
    ok "prober masked the dead path in ${mask_ms}ms"
else
    ng "prober did not mask the dead path within 5s (${mask_ms}ms)"
    prober_json || true
fi
if burst; then
    ok "every flow still pings through the surviving PE"
else
    ng "flows were lost after the path failure"
fi

# --- 6. recovery ------------------------------------------------------------
echo ""
echo "[6] recovery"

dexec "$CORE" ip -6 route replace 2001:db8:ff::3/128 via 2001:db8:3::1 dev eth3
dexec "$CORE" ip -6 route replace fd00:300::/48 via 2001:db8:3::1 dev eth3
# If the outage outlived the BGP hold time the session dropped too; give
# it time to re-establish and re-advertise before judging the prober.
if retry prober_paths_up 2; then
    ok "prober brought the path back"
else
    ng "path did not recover"
    prober_json || true
fi
a0=$(rx_bytes "$PE_OSAKA_A"); b0=$(rx_bytes "$PE_OSAKA_B")
if burst; then
    ok "all sources ping after recovery"
else
    ng "some sources cannot ping after recovery"
fi
a1=$(rx_bytes "$PE_OSAKA_A"); b1=$(rx_bytes "$PE_OSAKA_B")
da=$((a1 - a0)); db=$((b1 - b0))
if [ "$da" -gt 40000 ] && [ "$db" -gt 40000 ]; then
    ok "traffic spreads over both PEs again (pe-a +${da}B, pe-b +${db}B)"
else
    ng "spread did not return (pe-a +${da}B, pe-b +${db}B)"
fi

# --- summary ----------------------------------------------------------------
echo ""
echo "=============================================="
echo " RESULT: $pass passed, $fail failed"
echo "=============================================="
[ "$fail" -eq 0 ]
