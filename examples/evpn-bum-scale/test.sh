#!/bin/bash
# examples/evpn-bum-scale/test.sh
# NUM_PES Vinbero PEs (default 9: 8 remote PEs per PE, the most one bridge
# domain floods to) in one EVPN bridge domain, over an iBGP full mesh. Each PE
# advertises its host's MAC (RT2) and its flood SID (RT3), so every PE holds
# one RT3 flood peer and one RT2 unicast peer per remote PE. The test checks:
#
#   1. every PE installs all of them (the RT2 peers take no flood slot);
#   2. known unicast between every pair of hosts, and that a known-unicast
#      frame reaches its PE only;
#   3. unknown unicast, broadcast and ARP: each remote PE receives exactly one
#      copy, each remote host exactly one, and no PE sends a copy back into
#      the core (split horizon);
#   4. RX split horizon on an Ethernet Segment: once the last two PEs share
#      an ESI, a broadcast from the first of them is not delivered by the
#      other one.
#
# BUM_MODE=tc (default), xdp or xdp-native (xdp in native XDP) selects
# settings.l2.bum_mode. NUM_PES must match setup.sh.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/test_utils.sh"

check_root

NUM_PES="${NUM_PES:-9}"
BUM_MODE="${BUM_MODE:-tc}"
VINBEROD_BIN="${SCRIPT_DIR}/../../out/bin/vinberod"
VINBERO_BIN="${SCRIPT_DIR}/../../out/bin/vinbero"
TMP=/tmp/vinbero_ebs
ESI=00:11:22:33:44:55:66:77:88:99 # type 0 (operator-configured)
REMOTES=$((NUM_PES - 1))

TESTS_PASSED=0
TESTS_FAILED=0
PIDS=()

cleanup() {
    local pid
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2> /dev/null || true
    done
    for pid in "${PIDS[@]}"; do
        wait "$pid" 2> /dev/null || true
    done
}
trap cleanup EXIT
rm -rf "$TMP"
mkdir -p "$TMP"
# A state file left by an earlier run would bring its circuits back.
rm -f /tmp/vinbero_ebs_*_state.json

hex() { printf '%x' "$1"; }
ce_mac() { printf '02:00:00:00:%02x:01' "$1"; }
pe_addr() { echo "2001:db8:e0::$(hex "$1")"; }
loc() { echo "fd00:0:$(hex "$1")"; }
pe_log() { echo "/tmp/vinbero_ebs_pe$1.log"; }
vbctl() {
    local i="$1"
    shift
    ip netns exec "ebs-pe$i" "${VINBERO_BIN}" -s http://127.0.0.1:8080 "$@"
}

expect_eq() {
    local desc="$1" got="$2" want="$3"
    if [ "$got" = "$want" ]; then
        print_success "$desc (got $got)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        print_error "$desc (got '$got', want $want)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

stats_counter() {
    vbctl "$1" stats show 2> /dev/null | awk -v n="$2" '$1 == n {print $2; exit}'
}

# write_config <i>: the vinberod config of PE i, with an iBGP session to
# every other PE (the lower-numbered end dials).
write_config() {
    local i="$1" j out="$TMP/pe$1.yaml"
    {
        cat << EOF
internal:
  devices:
    - ebs-u$i
    - ebs-a$i
  bpf:
    device_mode: generic
  server:
    bind: "127.0.0.1:8080"
  logger:
    level: info
    format: text
    no_color: true

bgp:
  global:
    local_asn: 65100
    router_id: "10.255.0.$i"
    listen_port: 179
    source_locator: "LOC1"
  peers:
EOF
        for j in $(seq 1 "$NUM_PES"); do
            [ "$i" = "$j" ] && continue
            local passive=false
            [ "$i" -gt "$j" ] && passive=true
            cat << EOF
    - neighbor: "$(pe_addr "$j")"
      peer_asn: 65100
      passive: $passive
      hold_time_sec: 9
      keepalive_sec: 3
      connect_retry_sec: 2
      families:
        - evpn
EOF
        done
        cat << EOF

settings:
  state_path: /tmp/vinbero_ebs_pe${i}_state.json
  # Each daemon its own plugin store: the nine start at once.
  cplane_plugins:
    path: $TMP/pe$i-cplane-plugins
  enable_stats: true
  entries:
    sid_function:
      capacity: 256
    headendv4:
      capacity: 64
    headendv6:
      capacity: 64
    headend_l2:
      capacity: 64
    fdb:
      capacity: 1024
    bd_peer:
      capacity: 256
EOF
    } > "$out"
    bum_mode_config "$out" "$TMP/pe$i.$BUM_MODE.yaml"
}

# configure <i>: the bridge domain, its SIDs and circuit, and the routes PE i
# advertises.
configure() {
    local i="$1"
    vbctl "$i" vrf bridge-attach --vrf evi-100 --name br100 --bd-id 100 --members "ebs-a$i" > /dev/null
    vbctl "$i" vrf-bgp bind --vrf evi-100 --rt evpn:65000:100:import > /dev/null
    vbctl "$i" locator create --name LOC1 --prefix "$(loc "$i")::/48" \
        --block-len 32 --node-len 16 --function-len 16 --argument-len 64 --behavior classic > /dev/null
    vbctl "$i" sid create --trigger-prefix "$(loc "$i"):2::/128" --action END_DT2 --bd-id 100 --bridge-name br100 > /dev/null
    vbctl "$i" sid create --trigger-prefix "$(loc "$i"):3::/128" --action END_DT2M --bd-id 100 --bridge-name br100 > /dev/null
    vbctl "$i" hl2 create --interface "ebs-a$i" --vlan-id 0 \
        --src-addr "$(loc "$i"):2::" --segments "$(loc "$i"):2::" --bd-id 100 > /dev/null
    vbctl "$i" bgp advertise-evpn-mac --rd "65100:$i" --route-targets 65000:100 \
        --mac "$(ce_mac "$i")" --sid "$(loc "$i"):2::" --next-hop "$(pe_addr "$i")" > /dev/null
    vbctl "$i" bgp advertise-evpn-imet --rd "65100:$i" --route-targets 65000:100 \
        --sid "$(loc "$i"):3::" --next-hop "$(pe_addr "$i")" > /dev/null
}

# peer_counts <i>: "<peers> <remote MACs>" PE i holds in bridge domain 100.
peer_counts() {
    local peers macs
    peers=$(vbctl "$1" --json peer list --bd-id 100 2> /dev/null |
        python3 -c 'import json,sys; print(len(json.load(sys.stdin) or []))' 2> /dev/null || echo 0)
    macs=$(vbctl "$1" --json fdb list 2> /dev/null |
        python3 -c 'import json,sys; print(sum(1 for e in (json.load(sys.stdin) or []) if e.get("bd_id") == 100 and e.get("is_remote")))' 2> /dev/null || echo 0)
    echo "$peers $macs"
}

# marker_send <i> <dst mac> <tag>: host i sends one Ethernet frame
# (EtherType 0x88b5) to <dst mac> carrying <tag>.
marker_send() {
    ip netns exec "ebs-ce$1" python3 -c '
import socket, sys
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind((sys.argv[1], 0))
dst = bytes.fromhex(sys.argv[2].replace(":", ""))
s.send(dst + s.getsockname()[4] + b"\x88\xb5" + sys.argv[3].encode().ljust(46, b"\0"))
' "ebs-h$1" "$2" "$3"
}

# capture_all <tag> [filter...]: starts one capture per core port in each
# direction and one per host, receive side; CAP_PIDS holds them.
capture_all() {
    local tag="$1" i
    shift
    CAP_PIDS=()
    for i in $(seq 1 "$NUM_PES"); do
        capture_start ebs-core "ebs-c$i" "$TMP/$tag.core-out$i.pcap" -Q out "$@"
        CAP_PIDS+=("$CAPTURE_PID")
        capture_start ebs-core "ebs-c$i" "$TMP/$tag.core-in$i.pcap" -Q in "$@"
        CAP_PIDS+=("$CAPTURE_PID")
        capture_start "ebs-ce$i" "ebs-h$i" "$TMP/$tag.ce$i.pcap" -Q in "$@"
        CAP_PIDS+=("$CAPTURE_PID")
    done
}

capture_stop_all() {
    sleep 1
    kill "${CAP_PIDS[@]}" 2> /dev/null || true
    wait "${CAP_PIDS[@]}" 2> /dev/null || true
}

# check_flood <desc> <tag> <sender> [skip]: every PE but the sender received
# exactly one copy from the core and delivered exactly one to its host; no PE
# sent one back into the core; the sender's host got none back. [skip] is a
# PE whose host must receive none (split horizon on an Ethernet Segment).
check_flood() {
    local desc="$1" tag="$2" s="$3" skip="${4:-}" i want
    for i in $(seq 1 "$NUM_PES"); do
        if [ "$i" = "$s" ]; then
            expect_eq "[$desc] copies the sender PE $s put into the core" \
                "$(bum_marker_count "$TMP/$tag.core-in$i.pcap" "$tag")" "$REMOTES"
            expect_eq "[$desc] copies back at the sender's host" \
                "$(bum_marker_count "$TMP/$tag.ce$i.pcap" "$tag")" 0
            continue
        fi
        expect_eq "[$desc] copies PE $i received" "$(bum_marker_count "$TMP/$tag.core-out$i.pcap" "$tag")" 1
        expect_eq "[$desc] copies PE $i sent back into the core" "$(bum_marker_count "$TMP/$tag.core-in$i.pcap" "$tag")" 0
        want=1
        [ "$i" = "$skip" ] && want=0
        expect_eq "[$desc] copies host $i received" "$(bum_marker_count "$TMP/$tag.ce$i.pcap" "$tag")" "$want"
    done
}

echo "=========================================="
echo "EVPN BUM with $NUM_PES PEs in one bridge domain (BUM_MODE=${BUM_MODE})"
echo "=========================================="

namespaces=(ebs-core)
for i in $(seq 1 "$NUM_PES"); do
    namespaces+=("ebs-pe$i" "ebs-ce$i")
done
bum_native_prepare "${namespaces[@]}"

print_info "Starting $NUM_PES vinberod..."
for i in $(seq 1 "$NUM_PES"); do
    cfg=$(write_config "$i")
    setsid ip netns exec "ebs-pe$i" "${VINBEROD_BIN}" --bgp-enabled -c "$cfg" > "$(pe_log "$i")" 2>&1 &
    PIDS+=($!)
done
for i in $(seq 1 "$NUM_PES"); do
    wait_vinbero_ready "ebs-pe$i" 127.0.0.1:8080 90
done
BUM_EFFECTIVE=$(BUM_MODE="$BUM_MODE" bum_effective_mode "$(pe_log 1)")
print_info "BUM replication runs in mode ${BUM_EFFECTIVE}"

print_info "Configuring the PEs..."
for i in $(seq 1 "$NUM_PES"); do
    configure "$i"
done

print_info "Waiting for every PE to install $REMOTES RT3 and $REMOTES RT2 peers..."
want="$((2 * REMOTES)) $REMOTES"
for i in $(seq 1 "$NUM_PES"); do
    got=""
    for _ in $(seq 180); do
        got=$(peer_counts "$i")
        [ "$got" = "$want" ] && break
        sleep 1
    done
    expect_eq "PE $i peers and remote MACs in bd 100" "$got" "$want"
done
for i in $(seq 1 "$NUM_PES"); do
    expect_eq "PE $i logged no peer index shortage" "$(grep -c 'no free peer index' "$(pe_log "$i")" || true)" 0
done

echo ""
echo "=========================================="
echo "Known unicast"
echo "=========================================="
fails=0
for s in $(seq 1 "$NUM_PES"); do
    pings=()
    for d in $(seq 1 "$NUM_PES"); do
        [ "$s" = "$d" ] && continue
        ip netns exec "ebs-ce$s" ping -c 2 -W 2 -q "10.100.0.$d" > "$TMP/ping.$s.$d" 2>&1 &
        pings+=($!)
    done
    wait "${pings[@]}" || true
    for d in $(seq 1 "$NUM_PES"); do
        [ "$s" = "$d" ] && continue
        if ! grep -q ' 0% packet loss\| 50% packet loss' "$TMP/ping.$s.$d"; then
            print_error "host $s -> host $d: $(grep 'packet loss' "$TMP/ping.$s.$d")"
            fails=$((fails + 1))
        fi
    done
done
expect_eq "host pairs without connectivity" "$fails" 0

dst=$((NUM_PES / 2 + 1))
tag="ebsuc-$RANDOM"
capture_all "$tag"
marker_send 1 "$(ce_mac "$dst")" "$tag"
capture_stop_all
for i in $(seq 2 "$NUM_PES"); do
    want=0
    [ "$i" = "$dst" ] && want=1
    expect_eq "[known unicast to host $dst] copies PE $i received" "$(bum_marker_count "$TMP/$tag.core-out$i.pcap" "$tag")" "$want"
    expect_eq "[known unicast to host $dst] copies host $i received" "$(bum_marker_count "$TMP/$tag.ce$i.pcap" "$tag")" "$want"
done

echo ""
echo "=========================================="
echo "BUM (running ${BUM_EFFECTIVE})"
echo "=========================================="
for s in 1 "$NUM_PES"; do
    tag="ebsuu$s-$RANDOM"
    capture_all "$tag"
    marker_send "$s" 02:00:00:00:ff:01 "$tag"
    capture_stop_all
    check_flood "unknown unicast from host $s" "$tag" "$s"

    tag="ebsbc$s-$RANDOM"
    capture_all "$tag"
    marker_send "$s" ff:ff:ff:ff:ff:ff "$tag"
    capture_stop_all
    check_flood "broadcast from host $s" "$tag" "$s"
done

# ARP: host 1 resolves the last host again; its request reaches every host
# once and the reply comes back unicast.
ip netns exec ebs-ce1 ip neigh flush dev ebs-h1
CAP_PIDS=()
for i in $(seq 2 "$NUM_PES"); do
    capture_start "ebs-ce$i" "ebs-h$i" "$TMP/arp.ce$i.pcap" -Q in arp and ether src "$(ce_mac 1)"
    CAP_PIDS+=("$CAPTURE_PID")
done
arp_ok=0
ip netns exec ebs-ce1 ping -c 1 -W 2 "10.100.0.$NUM_PES" > /dev/null 2>&1 && arp_ok=1
capture_stop_all
expect_eq "host 1 resolved host $NUM_PES over ARP" "$arp_ok" 1
for i in $(seq 2 "$NUM_PES"); do
    expect_eq "ARP requests of host 1 at host $i" "$(capture_count "$TMP/arp.ce$i.pcap")" 1
done

echo ""
echo "=========================================="
echo "Split horizon on an Ethernet Segment"
echo "=========================================="
a=$((NUM_PES - 1))
b=$NUM_PES
print_info "PE $a and PE $b attach ESI $ESI; PE $a advertises a MAC on it"
for i in "$a" "$b"; do
    vbctl "$i" es create --esi "$ESI" --local-attached --local-pe "$(loc "$i")::" --mode ALL_ACTIVE
done
# A MAC on the segment behind PE a: its RT2 carries the ESI, which PE b
# writes into PE a's RT2 peer (and its reverse entry, which the receive
# side's split horizon reads).
es_mac=$(printf '02:00:00:00:%02x:02' "$a")
vbctl "$a" bgp advertise-evpn-mac --rd "65100:$a" --route-targets 65000:100 \
    --mac "$es_mac" --sid "$(loc "$a"):2::" --next-hop "$(pe_addr "$a")" --esi "$ESI"
got=""
for _ in $(seq 60); do
    got=$(vbctl "$b" --json fdb list 2> /dev/null |
        python3 -c 'import json,sys; print(sum(1 for e in (json.load(sys.stdin) or []) if e.get("mac") == sys.argv[1] and e.get("esi") == sys.argv[2]))' "$es_mac" "$ESI" 2> /dev/null || echo 0)
    [ "$got" = 1 ] && break
    sleep 1
done
expect_eq "PE $b holds the segment's MAC behind PE $a" "$got" 1
before=$(stats_counter "$b" SPLIT_HORIZON_RX)
tag="ebssh-$RANDOM"
capture_all "$tag"
marker_send "$a" ff:ff:ff:ff:ff:ff "$tag"
capture_stop_all
check_flood "broadcast from host $a on the segment" "$tag" "$a" "$b"
after=$(stats_counter "$b" SPLIT_HORIZON_RX)
expect_eq "PE $b counted the split-horizon drop" "$([ "${after:-0}" -gt "${before:-0}" ] && echo yes || echo no)" yes

echo ""
echo "=========================================="
echo "Results"
echo "=========================================="
echo "Passed: $TESTS_PASSED"
echo "Failed: $TESTS_FAILED"
[ "$TESTS_FAILED" -gt 0 ] && exit 1
exit 0
