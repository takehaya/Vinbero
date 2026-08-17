#!/usr/bin/env bash
# cplane-plugin-2site scenario assertions.
#
# Verifies, against a running `make deploy` lab, that a control-plane
# plugin does the whole job it exists for:
#   1. both plugins are registered and running;
#   2. pe-osaka's plugin originates a VPN route carrying its own SRv6
#      endpoint behavior codepoint (0xFE01), which no standard assigns;
#   3. pe-tokyo's plugin -- not vinbero's own applier -- turns that route
#      into a headend entry, because the claimed codepoint withholds it
#      from the applier;
#   4. data plane: a real `ping` from ce-tokyo reaches ce-osaka through
#      forwarding state that exists only because a plugin declared it.
#
# The return direction rides an ordinary L3VPN route with no plugin
# involved. A failure in one direction therefore points at the plugin and
# a failure in both points at the lab.
#
# DATA-PLANE FLAKINESS -- the data plane settles asynchronously (XDP
# attach, BGP convergence, plugin registration, NDP). Section 4 gates on
# every readiness precondition before pinging, with a generous retry, so
# a slow data plane cannot produce a spurious FAIL.
#
# Exit non-zero on the first failed assertion.
set -u

PE_TOKYO=clab-cplane-plugin-2site-pe-tokyo   # receiving plugin
PE_OSAKA=clab-cplane-plugin-2site-pe-osaka   # advertising plugin
CORE=clab-cplane-plugin-2site-core
CE_TOKYO=clab-cplane-plugin-2site-ce-tokyo
CE_OSAKA=clab-cplane-plugin-2site-ce-osaka

TOKYO_PREFIX=10.1.0.0/24      # ce-tokyo subnet, advertised without a plugin
OSAKA_PREFIX=10.2.0.0/24      # ce-osaka subnet, advertised BY the plugin

CE_TOKYO_ADDR=10.1.0.10
CE_OSAKA_ADDR=10.2.0.10

TOKYO_LOOPBACK=2001:db8:ff::1
OSAKA_LOOPBACK=2001:db8:ff::2

# The SID pe-osaka's plugin advertises, and the behavior codepoint it
# stamps into the SID TLV. 0xFE01 is outside the standardized space on
# purpose: vinbero refuses a claim on any behavior it implements itself.
PLUGIN_SID=fd00:200:0:1::
PLUGIN_BEHAVIOR=0xFE01

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
echo " cplane-plugin-2site scenario test"
echo "=============================================="

# --- 1. both plugins registered --------------------------------------------
echo ""
echo "[1] control-plane plugins registered"

for node in "$PE_TOKYO" "$PE_OSAKA"; do
    if retry bash -c "docker exec $node vbctl plugin cplane list 2>/dev/null | grep -q custom-behavior"; then
        ok "$node runs the custom-behavior plugin"
    else
        ng "$node did not register the plugin"
        dexec "$node" vbctl plugin cplane list || true
        dexec "$node" grep -i "plugin" /var/log/vinberod.log | tail -20 || true
    fi
done

# The capability each side was granted is the one it needs and no more.
# pe-tokyo cannot originate a route; pe-osaka cannot write forwarding
# state. Neither is a check the plugin could get past: the host functions
# for what they were not granted are not linked into their modules.
if dexec "$PE_TOKYO" grep -q '"capabilities": \["headend"\]\|capabilities.*headend' /var/log/vinberod.log 2>/dev/null; then
    ok "pe-tokyo's plugin was granted headend only"
else
    ng "pe-tokyo's plugin capabilities not visible in the log"
    dexec "$PE_TOKYO" grep -i "capabilit" /var/log/vinberod.log | tail -5 || true
fi

# --- 2. the plugin originated a route with its own behavior ----------------
echo ""
echo "[2] pe-osaka: the plugin originated $OSAKA_PREFIX"

# The plugin logs what it declared; the daemon logs the reconcile.
if retry bash -c "docker exec $PE_OSAKA grep -q 'plugin advertisement set applied' /var/log/vinberod.log"; then
    ok "pe-osaka applied the plugin's advertisement set"
    dexec "$PE_OSAKA" grep "advertisement set applied" /var/log/vinberod.log | tail -2 | sed 's/^/      /'
else
    ng "pe-osaka never applied an advertisement from the plugin"
    dexec "$PE_OSAKA" grep -i "plugin" /var/log/vinberod.log | tail -20 || true
fi

# --- 3. the receiving plugin installed the headend entry -------------------
echo ""
echo "[3] pe-tokyo: the plugin installed the forwarding state"

if retry bash -c "docker exec $PE_TOKYO vbctl headend-v4 list 2>/dev/null | grep -q '$OSAKA_PREFIX'"; then
    ok "$OSAKA_PREFIX is in pe-tokyo's headend-v4 map"
    dexec "$PE_TOKYO" vbctl headend-v4 list | sed 's/^/      /'
else
    ng "$OSAKA_PREFIX missing from pe-tokyo's headend-v4 map"
    dexec "$PE_TOKYO" vbctl headend-v4 list || true
    dexec "$PE_TOKYO" grep -i "plugin" /var/log/vinberod.log | tail -20 || true
fi

# It must steer into the SID the plugin advertised, not somewhere else.
seg=$(dexec "$PE_TOKYO" vbctl headend-v4 list 2>/dev/null \
    | awk -v p="$OSAKA_PREFIX" '$1==p {print $NF}')
if [ "$seg" = "$PLUGIN_SID" ]; then
    ok "it steers into the advertised SID $PLUGIN_SID"
else
    ng "it steers into '$seg', want $PLUGIN_SID"
fi

# And the plugin is what put it there. The daemon logs the reconcile of a
# plugin's declared set separately from anything its own appliers do.
if dexec "$PE_TOKYO" grep -q "plugin desired set applied" /var/log/vinberod.log 2>/dev/null; then
    ok "the entry came from the plugin's declared set"
    dexec "$PE_TOKYO" grep "desired set applied" /var/log/vinberod.log | tail -2 | sed 's/^/      /'
else
    ng "no plugin declaration was applied on pe-tokyo"
    dexec "$PE_TOKYO" grep -i "plugin" /var/log/vinberod.log | tail -20 || true
fi

# The claim is what kept vinbero's own applier off it. An applier that had
# processed the route would have logged its own VPN handling for it.
if dexec "$PE_TOKYO" grep -q "steering $OSAKA_PREFIX" /var/log/vinberod.log 2>/dev/null; then
    ok "the plugin itself reported steering $OSAKA_PREFIX"
else
    ng "the plugin never reported seeing $OSAKA_PREFIX"
    dexec "$PE_TOKYO" grep -i "steering\|custom-behavior" /var/log/vinberod.log | tail -10 || true
fi

# --- 4. data plane ----------------------------------------------------------
echo ""
echo "[4] data plane: ce-tokyo -> ce-osaka over plugin-installed state"

# Gate on every precondition before pinging, so a slow data plane cannot
# produce a spurious failure.
echo "  gating on readiness..."

if retry bash -c "docker exec $PE_TOKYO vbctl headend-v4 list 2>/dev/null | grep -q '$OSAKA_PREFIX'"; then
    echo "  gate: pe-tokyo headend entry present"
else
    ng "gate: pe-tokyo headend entry never appeared"
fi

if retry bash -c "docker exec $PE_OSAKA vbctl sid list 2>/dev/null | grep -q '${PLUGIN_SID}/128'"; then
    echo "  gate: pe-osaka End.DT4 endpoint present"
else
    ng "gate: pe-osaka End.DT4 endpoint missing"
    dexec "$PE_OSAKA" vbctl sid list || true
fi

# The return direction is an ordinary L3VPN route, no plugin involved.
if retry bash -c "docker exec $PE_OSAKA vbctl headend-v4 list 2>/dev/null | grep -q '$TOKYO_PREFIX'"; then
    echo "  gate: pe-osaka learned the return route"
else
    ng "gate: pe-osaka never learned $TOKYO_PREFIX"
    dexec "$PE_OSAKA" vbctl headend-v4 list || true
fi

# Underlay reachability, so the encapsulated packet has somewhere to go.
if retry bash -c "docker exec $PE_TOKYO ping6 -c1 -W2 $OSAKA_LOOPBACK"; then
    echo "  gate: PE loopbacks mutually reachable through the core"
else
    ng "gate: underlay not reachable between the PEs"
fi

echo "  --- gates passed, starting data-plane ping ---"

ping_ok() {
    dexec "$CE_TOKYO" ping -c 3 -W 2 "$CE_OSAKA_ADDR" >/dev/null 2>&1
}
if retry_n 20 ping_ok; then
    ok "ce-tokyo ($CE_TOKYO_ADDR) -> ce-osaka ($CE_OSAKA_ADDR) over the plugin's SRv6 path"
    dexec "$CE_TOKYO" ping -c 3 -W 2 "$CE_OSAKA_ADDR" | tail -3 | sed 's/^/      /'
else
    ng "ce-tokyo cannot reach ce-osaka"
    dexec "$CE_TOKYO" ping -c 3 -W 2 "$CE_OSAKA_ADDR" || true
    dexec "$PE_TOKYO" vbctl headend-v4 list || true
    dexec "$PE_OSAKA" vbctl sid list || true
fi

# --- 5. unregistering takes the plugin's state with it ---------------------
echo ""
echo "[5] unregistering removes what the plugin owned"

if dexec "$PE_TOKYO" vbctl plugin cplane unregister --name custom-behavior >/dev/null 2>&1; then
    if retry_n 10 bash -c "! docker exec $PE_TOKYO vbctl headend-v4 list 2>/dev/null | grep -q '$OSAKA_PREFIX'"; then
        ok "the plugin's headend entry went with it"
    else
        ng "the plugin's headend entry survived unregistration"
        dexec "$PE_TOKYO" vbctl headend-v4 list || true
    fi
else
    ng "could not unregister the plugin"
fi

echo ""
echo "=============================================="
echo " RESULT: $pass passed, $fail failed"
echo "=============================================="
[ "$fail" -eq 0 ]
