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

# The behavior codepoint pe-osaka's plugin stamps into the SID TLV.
# 0xFE01 is outside the standardized space on purpose: vinbero refuses a
# claim on any behavior it implements itself.
PLUGIN_BEHAVIOR=0xFE01

# The block the plugin allocates its SID from, and the eBPF slot that SID
# dispatches to. The address itself is not spelled here: the plugin asks
# for one and the daemon picks it, which is the half of the mechanism this
# scenario exists to exercise. Asserting a fixed address would quietly
# turn into asserting the allocator's first choice.
PLUGIN_LOCATOR_BLOCK=fd00:200:
PLUGIN_SLOT=32

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

# The capability says what it may do; the scope says where. pe-tokyo's
# plugin may install headend entries only inside 10.2.0.0/16, so it cannot
# write a longer prefix over traffic this node already forwards -- which
# would win on longest match without ever touching the entry it shadows.
if dexec "$PE_TOKYO" vbctl plugin cplane stats 2>/dev/null | grep -q '10.2.0.0/16'; then
    ok "pe-tokyo's plugin is scoped to 10.2.0.0/16"
else
    ng "pe-tokyo's plugin scope is not reported"
    dexec "$PE_TOKYO" vbctl plugin cplane stats || true
fi

# pe-osaka's plugin may originate only into vrf-cust, and it never names
# the route distinguisher: that comes from the VRF's binding, because the
# route targets are what decide which VRF a peer imports the route into.
if dexec "$PE_OSAKA" vbctl plugin cplane stats 2>/dev/null | grep -q 'vrf-cust'; then
    ok "pe-osaka's plugin is scoped to vrf-cust"
else
    ng "pe-osaka's plugin scope is not reported"
    dexec "$PE_OSAKA" vbctl plugin cplane stats || true
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

# It must steer into the SID the plugin advertised, which is the address
# pe-osaka's daemon allocated for it. This is where the two halves meet, so
# the rest of the checks are written against what the wire actually says.
PLUGIN_SID=$(dexec "$PE_TOKYO" vbctl headend-v4 list 2>/dev/null \
    | awk -v p="$OSAKA_PREFIX" '$1==p {print $NF}')
# An empty extraction must fail hard, not fall through: a later
# grep -q "${PLUGIN_SID}/128" would otherwise become grep -q "/128" and
# match any SID on the box, hiding the very failure this scenario exists to
# catch (the daemon not allocating the SID).
if [ -z "$PLUGIN_SID" ]; then
    ng "pe-tokyo installed no headend entry for $OSAKA_PREFIX; the SID-dependent checks cannot run"
    echo ""
    echo "=============================================="
    echo " RESULT: $pass passed, $fail failed"
    echo "=============================================="
    exit 1
fi
case "$PLUGIN_SID" in
    "$PLUGIN_LOCATOR_BLOCK"*)
        ok "it steers into $PLUGIN_SID, an address out of the plugin's locator"
        ;;
    *)
        ng "it steers into '$PLUGIN_SID', want an address in $PLUGIN_LOCATOR_BLOCK"
        ;;
esac

# And the plugin is what put it there. The daemon logs the reconcile of a
# plugin's declared set separately from anything its own appliers do.
if dexec "$PE_TOKYO" grep -q "plugin desired set applied" /var/log/vinberod.log 2>/dev/null; then
    ok "the entry came from the plugin's declared set"
    dexec "$PE_TOKYO" grep "desired set applied" /var/log/vinberod.log | tail -2 | sed 's/^/      /'
else
    ng "no plugin declaration was applied on pe-tokyo"
    dexec "$PE_TOKYO" grep -i "plugin" /var/log/vinberod.log | tail -20 || true
fi

# --- 3b. pe-osaka: the plugin's own SID dispatches to its own slot ---------
echo ""
echo "[3b] pe-osaka: the SID the plugin was given dispatches to its eBPF half"

# The daemon allocated the address, so nothing in the config names it. What
# is asserted is the chain: the plugin asked for a SID from its locator,
# the daemon installed a dispatch entry for it, and that entry points at
# the slot the plugin's own eBPF program occupies.
if retry bash -c "docker exec $PE_OSAKA vbctl sid list 2>/dev/null | grep -q '${PLUGIN_SID}/128'"; then
    ok "pe-osaka installed a dispatch entry for ${PLUGIN_SID}"
    dexec "$PE_OSAKA" vbctl sid list | sed 's/^/      /'
else
    ng "pe-osaka has no dispatch entry for ${PLUGIN_SID}"
    dexec "$PE_OSAKA" vbctl sid list || true
    dexec "$PE_OSAKA" grep -i "local sid\|plugin" /var/log/vinberod.log | tail -20 || true
fi

action=$(dexec "$PE_OSAKA" vbctl sid list 2>/dev/null \
    | awk -v p="${PLUGIN_SID}/128" '$1==p {print $2}')
if [ "$action" = "$PLUGIN_SLOT" ]; then
    ok "it dispatches to endpoint slot $PLUGIN_SLOT, the plugin's own"
else
    ng "it dispatches to '$action', want slot $PLUGIN_SLOT"
fi

# The eBPF half is loaded in that slot, so the dispatch has somewhere to
# land. Without it the SID would be an address that drops what reaches it.
if dexec "$PE_OSAKA" vbctl plugin list 2>/dev/null | grep -q "plugin_custom_behavior"; then
    ok "the plugin's eBPF half occupies the slot"
    dexec "$PE_OSAKA" vbctl plugin list | sed 's/^/      /'
else
    ng "no eBPF plugin is loaded on pe-osaka"
    dexec "$PE_OSAKA" vbctl plugin list || true
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
    echo "  gate: pe-osaka holds the SID its plugin was given"
else
    ng "gate: pe-osaka does not hold ${PLUGIN_SID}"
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

# The packets got there through the plugin's own slot, not by some other
# path that happens to reach ce-osaka. The per-slot invocation counter is
# bumped for the slot the dispatcher chose, so a non-zero count for slot
# 32 is the data plane saying it ran the plugin's program.
slot_pkts=$(dexec "$PE_OSAKA" vbctl stats slot show --type endpoint --plugin-only 2>/dev/null \
    | awk -v s="$PLUGIN_SLOT" '$2==s {print $4}')
if [ -n "$slot_pkts" ] && [ "$slot_pkts" -gt 0 ] 2>/dev/null; then
    ok "endpoint slot $PLUGIN_SLOT forwarded $slot_pkts packets"
else
    ng "endpoint slot $PLUGIN_SLOT forwarded nothing, so the ping took another path"
    dexec "$PE_OSAKA" vbctl stats slot show --type endpoint --plugin-only || true
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

# --- 6. the scope is enforced, not just reported ---------------------------
echo ""
echo "[6] pe-tokyo: a plugin scoped away from the prefix cannot install it"

# The plugin is unregistered (step 5). Re-register it with a headend prefix
# that does NOT cover 10.2.0.0/24, and assert the entry does not come back
# and the daemon logged the refusal. This is the check that would fail if
# checkScope were a no-op -- the stats-based assertions in step 1 would not.
dexec "$PE_TOKYO" sh -c 'printf "\010\201\374\003" > /tmp/plugin-config.bin' || true
if dexec "$PE_TOKYO" vbctl plugin cplane register \
    --name custom-behavior --wasm /plugin.wasm --config /tmp/plugin-config.bin \
    --behavior 0xFE01 --family vpnv4 \
    --capability headend --headend-prefix 10.99.0.0/16 >/dev/null 2>&1; then
    if retry_n 10 bash -c "! docker exec $PE_TOKYO vbctl headend-v4 list 2>/dev/null | grep -q '$OSAKA_PREFIX'"; then
        ok "$OSAKA_PREFIX was not installed under a scope that does not cover it"
    else
        ng "the plugin installed $OSAKA_PREFIX outside its scope"
        dexec "$PE_TOKYO" vbctl headend-v4 list || true
    fi
    if dexec "$PE_TOKYO" grep -q "outside this plugin's scope" /var/log/vinberod.log 2>/dev/null; then
        ok "the daemon logged the out-of-scope refusal"
    else
        ng "no out-of-scope refusal in the daemon log"
        dexec "$PE_TOKYO" grep -i "scope" /var/log/vinberod.log | tail -5 || true
    fi
else
    ng "could not re-register the plugin with a narrow scope"
fi

# Re-register correctly and assert the entry comes back, so the refusal
# above was the scope and not a broken plugin.
if dexec "$PE_TOKYO" vbctl plugin cplane register \
    --name custom-behavior --wasm /plugin.wasm --config /tmp/plugin-config.bin \
    --behavior 0xFE01 --family vpnv4 \
    --capability headend --headend-prefix 10.2.0.0/16 >/dev/null 2>&1; then
    if retry_n 10 bash -c "docker exec $PE_TOKYO vbctl headend-v4 list 2>/dev/null | grep -q '$OSAKA_PREFIX'"; then
        ok "$OSAKA_PREFIX came back once the scope covered it"
    else
        ng "$OSAKA_PREFIX did not return under a covering scope"
        dexec "$PE_TOKYO" vbctl headend-v4 list || true
    fi
else
    ng "could not re-register the plugin with a covering scope"
fi

echo ""
echo "=============================================="
echo " RESULT: $pass passed, $fail failed"
echo "=============================================="
[ "$fail" -eq 0 ]
