#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
interactive=false
if (($#)); then
    if [[ "$#" != 1 || "$1" != --interactive ]]; then
        echo "Usage: $0 [--interactive]" >&2
        exit 2
    fi
    interactive=true
fi
check_root
for binary in "$VINBEROD_BIN" "$VINBERO_BIN"; do
    [[ -x "$binary" ]] || { print_error "Build first: make build"; exit 1; }
done
for artifact in "$WASM" "$PLUGIN"; do
    [[ -s "$artifact" ]] || { print_error "Missing $artifact; see README.md"; exit 1; }
done
for dep in jq ss timeout; do command -v "$dep" >/dev/null; done
resolve_bpftool
for ns in "${NAMESPACES[@]}"; do
    ip -n "$ns" link show lo >/dev/null
    [[ -z "$(ip netns pids "$ns")" ]] || { print_error "$ns is already in use"; exit 1; }
done

work=$(mktemp -d /tmp/vinbero_cpdp.XXXXXX)
pids=()
cleanup() {
    local rc=$?
    trap - EXIT
    for pid in "${pids[@]}"; do kill -TERM "$pid" 2>/dev/null || true; done
    for pid in "${pids[@]}"; do
        for ((attempt = 0; attempt < 50; attempt++)); do
            kill -0 "$pid" 2>/dev/null || break
            sleep 0.1
        done
        kill -KILL "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    if ((rc != 0 && rc != 130 && rc != 143)); then
        for log in "$work"/*.log; do tail -80 "$log"; done
    fi
    echo "Daemon logs and state: $work"
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for node in 1 2; do
    sed "s|__STATE_PATH__|$work/pe$node-state.json|" "$EXAMPLE_DIR/vinbero_pe$node.yaml" > "$work/pe$node.yaml"
    ip netns exec "cpdp-pe$node" "$VINBEROD_BIN" --bgp-enabled -c "$work/pe$node.yaml" > "$work/pe$node.log" 2>&1 &
    pids+=("$!")
done
for ns in "$PE1" "$PE2"; do wait_for "$ns RPC ready" ctl "$ns" locator list; done

cp "$EXAMPLE_DIR/pe1.json" "$work/pe1.json"
cp "$EXAMPLE_DIR/pe2.json" "$work/pe2.json"
jq '.endpoint.allowed_underlay_prefix = "fd00:100::bad/128"' "$work/pe2.json" > "$work/pe2-deny.json"
before_maps=$("$BPFTOOL_BIN" -j map show | jq '[.[] | select(.name == "cdplane_policy") | .id]')
ctl "$PE2" plugin register --type endpoint --index 32 --prog "$PLUGIN" --program plugin_custom_cdplane_behavior
decision_map=$("$BPFTOOL_BIN" -j map show | jq -er --argjson before "$before_maps" \
    '[.[] | select(.name == "cdplane_policy") | .id | select(. as $id | $before | index($id) | not)] |
     if length == 1 then .[0] else error("expected one new policy counter map") end')
ctl "$PE1" sid create --trigger-prefix fd00:100:0:1::/128 --action END_DT4 --vrf-name vrf-cust
ctl "$PE1" bgp advertise-vpn --family vpnv4 --prefix 10.1.0.0/24 --rd 65100:100 \
    --rts 65000:200 --sid fd00:100:0:1:: --next-hop 2001:db8:ff::1

register() {
    local backend=$1
    "$EXAMPLE_DIR/apply.sh" pe1 "$work/pe1.json" "$backend"
    "$EXAMPLE_DIR/apply.sh" pe2 "$work/pe2.json" "$backend"
}

headend_sid() {
    ctl "$PE1" --json headend-v4 list | jq -er '.[] | select(.trigger_prefix == "10.2.0.0/24") | .segments[0]'
}

ready() {
    local backend=$1 sid
    for ns in "$PE1" "$PE2"; do
        ctl "$ns" plugin cplane stats | awk -v backend="$backend" \
            '$1 == "custom-cdplane-behavior" && $2 == backend && $6 == "running" { found=1 } END { exit !found }' || return 1
    done
    sid=$(headend_sid) || return 1
    [[ "$sid" == fd00:200:* ]] || return 1
    ctl "$PE2" --json sid list | jq -e --arg sid "$sid/128" \
        'any(.[]; .trigger_prefix == $sid and .action == 32)' >/dev/null || return 1
    ctl "$PE2" --json headend-v4 list | jq -e \
        'any(.[]; .trigger_prefix == "10.1.0.0/24")' >/dev/null
}

slot_packets() {
    ctl "$PE2" --json stats slot show --type endpoint --plugin-only --all |
        jq -er '.[] | select(.slot == 32) | (.packets // 0)'
}

policy_packets() {
    "$BPFTOOL_BIN" -j map dump id "$decision_map" |
        jq -er --argjson index "$1" '[.[] | (.formatted // .) | select(.key == $index) | .values[].value] | add'
}

check_denied() {
    local replies rc=0
    replies=$(ip netns exec "$HOST1" ping -c 2 -W 1 10.2.0.10 2>&1) || rc=$?
    echo "$replies"
    [[ "$rc" == 1 ]] && grep -Fq '2 packets transmitted, 0 received' <<< "$replies"
}

policy_denied() {
    ready "$1" && check_denied
}

policy_restored() {
    ready "$1" && ip netns exec "$HOST1" ping -c 1 -W 1 10.2.0.10 >/dev/null
}

socket_identity() {
    ip netns exec "$1" ss -Hntie state established '( sport = :179 or dport = :179 )' |
        awk 'NR == 1 { print $3, $4 } /ino:/ { for (i=1; i<=NF; i++) if ($i ~ /^ino:/) print $i }'
}

register native
wait_for "Native BGP route and plugin SID ready" ready native
sid=$(headend_sid)
[[ -n "$(ip -n "$PE2" route show table 100 10.2.0.0/24)" ]]
[[ -z "$(ip -n "$PE2" route show table main 10.2.0.0/24)" ]]
if [[ "$interactive" == true ]]; then
    echo "Interactive lab is running; Ctrl-C stops its daemons."
    echo "Policy files and logs: $work"
    echo "bpftool executable: $BPFTOOL_BIN"
    echo "From another terminal in $EXAMPLE_DIR:"
    echo "  sudo ./apply.sh pe2 $work/pe2-deny.json"
    echo "  sudo ./apply.sh pe2 $work/pe2.json"
    echo "  sudo ./apply.sh pe1 $work/pe1.json wasm"
    echo "  sudo ./apply.sh pe2 $work/pe2.json wasm"
    echo "  sudo ip netns exec $HOST1 ping -c 3 -W 1 10.2.0.10"
    while true; do sleep 1; done
fi
for ns in "$PE1" "$PE2"; do
    socket_identity "$ns" > "$work/$ns-socket.txt"
    [[ -s "$work/$ns-socket.txt" ]]
done
for pid in "${pids[@]}"; do awk '{print $1, $22}' "/proc/$pid/stat"; done > "$work/processes.txt"

first=true
for backend in native wasm native; do
    if [[ "$first" == true ]]; then first=false; else register "$backend"; fi
    wait_for "$backend route and SID ready" ready "$backend"
    [[ "$(headend_sid)" == "$sid" ]]
    for ns in "$PE1" "$PE2"; do
        [[ "$(socket_identity "$ns")" == "$(cat "$work/$ns-socket.txt")" ]]
    done
    current=$(for pid in "${pids[@]}"; do awk '{print $1, $22}' "/proc/$pid/stat"; done)
    [[ "$current" == "$(cat "$work/processes.txt")" ]]
    # Resolve the customer neighbour through the same VRF as the decap grant.
    ip netns exec "$PE2" ping -I vrf-cust -c 1 -W 2 10.2.0.10 >/dev/null
    before=$(slot_packets)
    allowed_before=$(policy_packets 0)
    replies=$(ip netns exec "$HOST1" ping -c 3 -W 2 10.2.0.10)
    echo "$replies"
    grep -Fq '3 packets transmitted, 3 received, 0% packet loss' <<< "$replies"
    after=$(slot_packets)
    ((after >= before + 3))
    (( $(policy_packets 0) >= allowed_before + 3 ))
    print_success "$backend: customer ping passed through Dplane slot32 ($before -> $after); daemon and BGP unchanged"

    denied_before=$(policy_packets 1)
    "$EXAMPLE_DIR/apply.sh" pe2 "$work/pe2-deny.json" "$backend"
    wait_for "$backend rejected policy traffic with route and SID present" policy_denied "$backend"
    [[ "$(headend_sid)" == "$sid" ]]
    (( $(policy_packets 1) >= denied_before + 2 ))
    "$EXAMPLE_DIR/apply.sh" pe2 "$work/pe2.json" "$backend"
    wait_for "$backend restored policy and forwarding" policy_restored "$backend"
    [[ "$(headend_sid)" == "$sid" ]]
done

# Removing the advertising controller retracts its route and allocated SID.
# Identify this endpoint's host maps through program references, rather than
# selecting another namespace's maps with the same kernel names.
program_maps=$("$BPFTOOL_BIN" -j prog show | jq -er --argjson counter "$decision_map" \
    '[.[] | select(.map_ids | index($counter)) | .map_ids] | if length == 1 then .[0] else error("ambiguous endpoint") end')
aux_map=$("$BPFTOOL_BIN" -j map show | jq -er --argjson ids "$program_maps" \
    '.[] | select(.name == "sid_aux_map") | .id | select(. as $id | $ids | index($id))')
host_maps=$("$BPFTOOL_BIN" -j prog show | jq -er --argjson aux "$aux_map" \
    '[.[] | select(.map_ids | index($aux)) | .map_ids[]] | unique')
grant_map=$("$BPFTOOL_BIN" -j map show | jq -er --argjson ids "$host_maps" \
    '[.[] | select(.name | startswith("plugin_endt_vrf")) | .id | select(. as $id | $ids | index($id))] |
     if length == 1 then .[0] else error("ambiguous VRF grant map") end')
aux_index=$(ctl "$PE2" --json sid list | jq -er --arg sid "$sid/128" \
    '.[] | select(.trigger_prefix == $sid) | .plugin_aux_index')
# The lab runs on little-endian Linux (amd64/arm64); bpftool takes raw keys.
aux_key=()
for shift in 0 8 16 24; do
    printf -v byte '%02x' "$(((aux_index >> shift) & 255))"
    aux_key+=("$byte")
done
"$BPFTOOL_BIN" -j map lookup id "$aux_map" key hex "${aux_key[@]}" | jq -e '.value[0] == "0x01"' >/dev/null
"$BPFTOOL_BIN" -j map dump id "$grant_map" | jq -e 'length == 1' >/dev/null
printf '%s\n' '{"version":1,"allowed_underlay_prefix":"fd00:100::/128"}' > "$work/endpoint.json"
if ctl "$PE2" plugin aux update --map-type endpoint --slot 32 --index "$aux_index" \
    --json-file "$work/endpoint.json" > "$work/owner-rejection.log" 2>&1; then
    print_error "Independent aux API overwrote Cplane-owned policy"
    exit 1
fi
grep -Fq 'permission_denied' "$work/owner-rejection.log"
allocated=$(ctl "$PE2" plugin aux alloc --map-type endpoint --slot 32 --json-file "$work/endpoint.json")
independent_index=${allocated##*=}
[[ "$independent_index" =~ ^[0-9]+$ ]]
ctl "$PE2" plugin aux update --map-type endpoint --slot 32 --index "$independent_index" --json-file "$work/endpoint.json"
ctl "$PE2" plugin aux get --map-type endpoint --slot 32 --index "$independent_index" > "$work/independent-aux.txt"
ctl "$PE2" plugin aux free --map-type endpoint --slot 32 --index "$independent_index"
print_success "JSON-file aux operations passed; Cplane-owned policy rejected manual update"
ctl "$PE2" plugin cplane unregister --name custom-cdplane-behavior
withdrawn() {
    local entries sids
    entries=$(ctl "$PE1" --json headend-v4 list) || return 1
    sids=$(ctl "$PE2" --json sid list) || return 1
    jq -e 'all((. // [])[]; .trigger_prefix != "10.2.0.0/24")' <<< "$entries" >/dev/null &&
        jq -e --arg sid "$sid/128" 'all((. // [])[]; .trigger_prefix != $sid)' <<< "$sids" >/dev/null
}
wait_for "Unregister retracted the headend and plugin SID" withdrawn
"$BPFTOOL_BIN" -j map lookup id "$aux_map" key hex "${aux_key[@]}" | jq -e 'all(.value[]; . == "0x00")' >/dev/null
"$BPFTOOL_BIN" -j map dump id "$grant_map" | jq -e 'length == 0' >/dev/null
print_success "Unregister cleared the host-managed aux and VRF grant"
ping_rc=0
replies=$(ip netns exec "$HOST1" ping -c 2 -W 1 10.2.0.10 2>&1) || ping_rc=$?
echo "$replies"
if [[ "$ping_rc" != 1 ]] || ! grep -Fq '2 packets transmitted, 0 received' <<< "$replies"; then
    print_error "Traffic still forwarded after the advertising plugin was removed"
    exit 1
fi
ctl "$PE1" plugin cplane unregister --name custom-cdplane-behavior
ctl "$PE2" plugin unregister --type endpoint --index 32
print_success "Cplane + Dplane lifecycle passed (native -> WASM -> native -> unregister)"
