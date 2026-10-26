#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
check_root
for binary in "$VINBEROD_BIN" "$VINBERO_BIN"; do
    [[ -x "$binary" ]] || { print_error "Build first: make build"; exit 1; }
done
for artifact in "$WASM" "$PLUGIN"; do
    [[ -s "$artifact" ]] || { print_error "Missing $artifact; see README.md"; exit 1; }
done
for dep in jq ss timeout; do command -v "$dep" >/dev/null; done
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
    if ((rc)); then
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

# The shared controller's protobuf fields: 9 receive prefix; 2 locator,
# 3 advertised prefix, 4 VRF, 5 endpoint slot, 7 next hop, 8 decap VRF.
printf '\112\01310.2.0.0/24' > "$work/receive.bin"
printf '\022\004LOC2\032\01310.2.0.0/24\042\010vrf-cust\050\040\072\0162001:db8:ff::2\102\010vrf-cust' > "$work/send.bin"
ctl "$PE2" plugin register --type endpoint --index 32 --prog "$PLUGIN" --program plugin_custom_behavior
ctl "$PE1" sid create --trigger-prefix fd00:100:0:1::/128 --action END_DT4 --vrf-name vrf-cust
ctl "$PE1" bgp advertise-vpn --family vpnv4 --prefix 10.1.0.0/24 --rd 65100:100 \
    --rts 65000:200 --sid fd00:100:0:1:: --next-hop 2001:db8:ff::1

register() {
    local backend=$1
    local args=(--native custom-behavior)
    [[ "$backend" != wasm ]] || args=(--wasm "$WASM")
    ctl "$PE1" plugin cplane register --name custom-cdplane-behavior "${args[@]}" \
        --config "$work/receive.bin" --behavior 0xFE01 --family vpnv4 --tick-ms 1000 \
        --capability headend --headend-prefix 10.2.0.0/24
    ctl "$PE2" plugin cplane register --name custom-cdplane-behavior "${args[@]}" \
        --config "$work/send.bin" --behavior 0xFE01 --family vpnv4 --tick-ms 1000 \
        --capability advertise --capability local_sid --vrf vrf-cust --locator LOC2 --endpoint-slot 32
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

socket_identity() {
    ip netns exec "$1" ss -Hntie state established '( sport = :179 or dport = :179 )' |
        awk 'NR == 1 { print $3, $4 } /ino:/ { for (i=1; i<=NF; i++) if ($i ~ /^ino:/) print $i }'
}

register native
wait_for "Native BGP route and plugin SID ready" ready native
sid=$(headend_sid)
[[ -n "$(ip -n "$PE2" route show table 100 10.2.0.0/24)" ]]
[[ -z "$(ip -n "$PE2" route show table main 10.2.0.0/24)" ]]
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
    replies=$(ip netns exec "$HOST1" ping -c 3 -W 2 10.2.0.10)
    echo "$replies"
    grep -Fq '3 packets transmitted, 3 received, 0% packet loss' <<< "$replies"
    after=$(slot_packets)
    ((after >= before + 3))
    print_success "$backend: customer ping passed through Dplane slot32 ($before -> $after); daemon and BGP unchanged"
done

# Removing the advertising controller retracts its route and allocated SID.
ctl "$PE2" plugin cplane unregister --name custom-cdplane-behavior
withdrawn() {
    local entries sids
    entries=$(ctl "$PE1" --json headend-v4 list) || return 1
    sids=$(ctl "$PE2" --json sid list) || return 1
    jq -e 'all((. // [])[]; .trigger_prefix != "10.2.0.0/24")' <<< "$entries" >/dev/null &&
        jq -e --arg sid "$sid/128" 'all((. // [])[]; .trigger_prefix != $sid)' <<< "$sids" >/dev/null
}
wait_for "Unregister retracted the headend and plugin SID" withdrawn
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
