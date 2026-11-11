#!/usr/bin/env bash
# Runs the vinbero CNI plugin in L2 mode (CNI_COMMAND and the network
# configuration on stdin) against two PEs sharing one EVPN bridge domain, and
# checks pod-to-pod L2 traffic over SRv6 (ARP/ping across nodes, IPv6/ND
# between pods), a silent pod, isolation of two bridge domains that use the
# same prefix and the same MAC, the bridge-domain MTU, that the bridge gives a
# pod no path into the host stack, DEL/re-ADD, a netns gone before DEL, and a
# daemon restart with pods attached.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
check_root
for binary in "$VINBEROD_BIN" "$VINBERO_BIN" "$CNI_BIN"; do
    [[ -x "$binary" ]] || { print_error "Missing $binary; build first: make build"; exit 1; }
done
for dep in jq timeout python3; do command -v "$dep" >/dev/null; done

CNI_PLUGIN_DIR=${CNI_PLUGIN_DIR:-}
if [[ -z "$CNI_PLUGIN_DIR" ]]; then
    for dir in /opt/cni/bin /usr/lib/cni; do
        [[ -x "$dir/host-local" ]] && CNI_PLUGIN_DIR=$dir && break
    done
fi
[[ -x "${CNI_PLUGIN_DIR:-}/host-local" ]] || {
    print_error "host-local IPAM plugin not found; install the CNI reference plugins or set CNI_PLUGIN_DIR"
    exit 1
}
for ns in "${NAMESPACES[@]}"; do ip -n "$ns" link show lo >/dev/null; done
for ns in "$PE1" "$PE2"; do
    [[ -z "$(ip netns pids "$ns")" ]] || { print_error "$ns is already in use"; exit 1; }
done

work=$(mktemp -d /tmp/vinbero_cni_l2.XXXXXX)
cni_path="$work/cni-bin"
mkdir -p "$cni_path"
cp "$CNI_PLUGIN_DIR/host-local" "$CNI_BIN" "$cni_path/"
mv "$cni_path/vinbero-cni" "$cni_path/vinbero"

declare -A pids=()
cleanup() {
    local rc=$?
    trap - EXIT
    for node in "${!pids[@]}"; do kill -TERM "${pids[$node]}" 2>/dev/null || true; done
    for node in "${!pids[@]}"; do wait "${pids[$node]}" 2>/dev/null || true; done
    if ((rc != 0)); then
        for log in "$work"/*.log; do echo "--- BGP peer events in $log"; grep -a 'Topic=Peer' "$log" || true; done
        for log in "$work"/*.log; do echo "--- $log"; tail -60 "$log"; done
    fi
    echo "Daemon logs and state: $work"
    exit "$rc"
}
trap cleanup EXIT

start_pe() {
    local node=$1
    sed "s|__STATE_PATH__|$work/pe$node-state.json|" "$EXAMPLE_DIR/vinbero_pe$node.yaml" > "$work/pe$node.yaml"
    ip netns exec "cnil2-pe$node" "$VINBEROD_BIN" --bgp-enabled -c "$work/pe$node.yaml" >> "$work/pe$node.log" 2>&1 &
    pids[$node]=$!
    wait_for "cnil2-pe$node RPC ready" ctl "cnil2-pe$node" locator list
}
stop_pe() {
    local node=$1 sig=${2:-TERM}
    kill -"$sig" "${pids[$node]}"
    wait "${pids[$node]}" 2>/dev/null || true
    unset "pids[$node]"
}

PASS=0
FAIL=0
pass() { print_success "$1"; PASS=$((PASS + 1)); }
fail() { print_error "$1"; FAIL=$((FAIL + 1)); }
check() { local d=$1; shift; if "$@" >/dev/null 2>&1; then pass "$d"; else fail "$d"; fi; }
check_not() { local d=$1; shift; if "$@" >/dev/null 2>&1; then fail "$d"; else pass "$d"; fi; }
eventually() { local d=$1; shift; if wait_for "$d" "$@"; then PASS=$((PASS + 1)); else FAIL=$((FAIL + 1)); fi; }

# netconf <node> <tenant>: one subnet (10.200.0.0/16) shared across nodes with
# per-node host-local ranges; tenant-l2b reuses tenant-l2's addresses in its
# own bridge domain. PE1's tenant-l2 carries the binding (the first ADD binds
# it); every other binding comes from the daemon config.
netconf() {
    local node=$1 tenant=${2:-tenant-l2} binding="" bridge=br-l2 bd=100
    if [[ "$tenant" == tenant-l2b ]]; then bridge=br-l2b bd=200; fi
    if [[ "$node" == 1 && "$tenant" == tenant-l2 ]]; then
        binding='"rd": "65100:1", "rts": [{"family": "evpn", "rt": "65000:100", "direction": "both"}], "locator": "LOC1",'
    fi
    cat <<JSON
{
  "cniVersion": "1.0.0",
  "name": "$tenant",
  "type": "vinbero",
  "mode": "l2",
  "server": "127.0.0.1:8085",
  "vrf": "$tenant",
  "bridge": "$bridge",
  "bdId": $bd,
  $binding
  "dataDir": "$work/cni-pe$node",
  "ipam": {
    "type": "host-local",
    "dataDir": "$work/ipam-pe$node-$tenant",
    "ranges": [[{"subnet": "10.200.0.0/16", "rangeStart": "10.200.$node.2", "rangeEnd": "10.200.$node.254"}]]
  }
}
JSON
}

cni() {
    local node=$1 cmd=$2 pod=$3 tenant=${4:-tenant-l2}
    netconf "$node" "$tenant" | ip netns exec "cnil2-pe$node" env \
        CNI_COMMAND="$cmd" CNI_CONTAINERID="$pod" CNI_NETNS="/var/run/netns/$pod" \
        CNI_IFNAME=net1 CNI_PATH="$cni_path" "$cni_path/vinbero"
}
cni_add() { cni "$1" ADD "$2" "${3:-tenant-l2}" > "$work/$2.json"; }

host_veth() { jq -r '.interfaces[0].name' "$work/$1.json"; }
pod_ip() { jq -r '.ips[0].address | split("/")[0]' "$work/$1.json"; }
pod_mac() { jq -r '.interfaces[1].mac' "$work/$1.json"; }

pod_has() { ip -n "$1" -4 addr show dev net1 | grep -q "inet $2/16"; }
pod_mtu() { ip -n "$1" link show net1 | grep -q "mtu $2"; }
in_vrf_bridge() { ip -n "cnil2-pe$1" link show "$2" | grep -q "master $3"; }
device_attached() {
    ctl "cnil2-pe$1" --json device list | jq -e --arg n "$2" 'any(.devices[]?; .name == $n and .mode == "generic")'
}
has_ac() {
    ctl "cnil2-pe$1" --json vrf show | jq -e --arg n "$2" --arg v "$3" \
        'any(.vrfs[]? | select(.name == $v) | .acs[]?; .interface_name == $n)'
}
has_circuit() {
    ctl "cnil2-pe$1" --json hl2 list | jq -e --arg n "$2" --argjson b "$3" \
        'any(.[]?; .interface_name == $n and .bd_id == $b)'
}
# remote_mac <node> <mac> <bd>: the PE learned <mac> as a remote FDB entry.
remote_mac() {
    ctl "cnil2-pe$1" --json fdb list | jq -e --arg m "$(echo "$2" | tr 'A-Z' 'a-z')" --argjson b "$3" \
        'any(.[]?; (.mac|ascii_downcase) == $m and .bd_id == $b and .is_remote)'
}
ping_from() { ip netns exec "$1" ping -c 2 -W 2 "$2"; }
in_echos() {
    ip netns exec "$1" awk '/^Icmp:/ { if (!c) { for (i=1;i<=NF;i++) if ($i=="InEchos") c=i } else { print $c; exit } }' /proc/net/snmp
}
# reaches_only <from> <ip> <pod> <other>: a ping from <from> to ip is answered
# by <pod>; <other> (same address in the other bridge domain) sees none of it.
reaches_only() {
    local from=$1 ip=$2 pod=$3 other=$4 p0 o0
    p0=$(in_echos "$pod"); o0=$(in_echos "$other")
    ping_from "$from" "$ip" || return 1
    (($(in_echos "$pod") > p0 && $(in_echos "$other") == o0))
}
# sysctl value of the bridge on a PE.
br_sysctl() { ip netns exec "cnil2-pe$1" cat "/proc/sys/$2" 2>/dev/null; }

echo "=========================================="
echo "vinbero CNI plugin, L2 mode"
echo "=========================================="

start_pe 1
start_pe 2

check "ADD pod1 on PE1 (tenant-l2)" cni_add 1 "$POD1"
check "ADD pod1b on PE1 (tenant-l2)" cni_add 1 "$POD1B"
check "ADD pod2 on PE2 (tenant-l2)" cni_add 2 "$POD2"
ip1=$(pod_ip "$POD1"); ip1b=$(pod_ip "$POD1B"); ip2=$(pod_ip "$POD2")
mac1=$(pod_mac "$POD1"); mac2=$(pod_mac "$POD2")
veth1=$(host_veth "$POD1"); veth2=$(host_veth "$POD2")
echo "pod1 $ip1/$mac1 ($veth1), pod1b $ip1b, pod2 $ip2/$mac2 ($veth2)"

check "ADD result: on-link prefix, no gateway" \
    jq -e '.ips[0].address | endswith("/16")' "$work/$POD1.json"
check "ADD result: no gateway in L2" jq -e '.ips[0].gateway == null' "$work/$POD1.json"
check "pod1 has its on-link address" pod_has "$POD1" "$ip1"
check "pod MTU leaves room for inner Ethernet" pod_mtu "$POD1" 1422
check "host veth is a member of br-l2 (PE1)" in_vrf_bridge 1 "$veth1" br-l2
check "host veth is an AC of tenant-l2" has_ac 1 "$veth1" tenant-l2
check "host veth has a bd 100 circuit" has_circuit 1 "$veth1" 100
check "host veth attached (PE1)" device_attached 1 "$veth1"
check "host veth attached (PE2)" device_attached 2 "$veth2"

echo "--- bridge hardening (br-l2 on PE1) ---"
check "disable_ipv6=1 on br-l2" test "$(br_sysctl 1 net/ipv6/conf/br-l2/disable_ipv6)" = 1
check "ipv4 forwarding=0 on br-l2" test "$(br_sysctl 1 net/ipv4/conf/br-l2/forwarding)" = 0
check "rp_filter=1 on br-l2" test "$(br_sysctl 1 net/ipv4/conf/br-l2/rp_filter)" = 1
check "arp_ignore=8 on br-l2" test "$(br_sysctl 1 net/ipv4/conf/br-l2/arp_ignore)" = 8
check "br-l2 has no IPv6 address" test -z "$(ip -n "$PE1" -o -6 addr show dev br-l2 2>/dev/null)"

eventually "PE2 learned pod1's MAC as remote" remote_mac 2 "$mac1" 100
eventually "PE1 learned pod2's MAC as remote (silent pre-advertise)" remote_mac 1 "$mac2" 100
check "pod1 -> pod2 across the PEs (ARP + ping over SRv6)" ping_from "$POD1" "$ip2"
check "pod2 -> pod1b across the PEs" ping_from "$POD2" "$ip1b"
check "pod1 -> pod1b on the same PE" ping_from "$POD1" "$ip1b"
check "CHECK pod1" cni 1 CHECK "$POD1"

echo "--- IPv6 / ND between pods at the Ethernet level ---"
# The pods carry no IPAM IPv6, but their kernel-assigned link-locals reach
# each other over the bridge domain (ND floods as BUM).
ll1=$(ip -n "$POD1" -o -6 addr show dev net1 scope link | awk '{print $4}' | cut -d/ -f1)
check "pod1 has an IPv6 link-local" test -n "$ll1"
eventually "pod2 -> pod1 over IPv6 link-local (ND across nodes)" \
    ip netns exec "$POD2" ping -6 -c 2 -W 3 "$ll1%net1"

echo "--- silent pod (never sends) ---"
check "ADD silent pod on PE1" cni_add 1 "$PODS"
macs=$(pod_mac "$PODS")
# Keep it silent: no IPv6 so it emits no ND, and we never ping from it.
ip netns exec "$PODS" sysctl -qw net.ipv6.conf.net1.disable_ipv6=1 || true
eventually "PE2 reaches the silent pod's MAC via the static FDB pre-advertise" remote_mac 2 "$macs" 100
ips=$(pod_ip "$PODS")
check "pod2 -> silent pod (unicast after RT2, no frame from the pod)" ping_from "$POD2" "$ips"

echo "--- two bridge domains, same prefix and same MAC, must not see each other ---"
check "ADD pod1x on PE1 (tenant-l2b)" cni_add 1 "$POD1X" tenant-l2b
check "ADD pod2x on PE2 (tenant-l2b)" cni_add 2 "$POD2X" tenant-l2b
ip1x=$(pod_ip "$POD1X"); ip2x=$(pod_ip "$POD2X")
check "pod1x reuses pod1's address" test "$ip1x" = "$ip1"
check "pod2x reuses pod2's address" test "$ip2x" = "$ip2"
# Force the same MAC in both bridge domains, then relearn. Flush the stale
# ARP the other pods cached for pod1's old MAC, so a later ping re-resolves.
ip -n "$POD1" link set net1 address 02:00:00:00:be:ef
ip -n "$POD1X" link set net1 address 02:00:00:00:be:ef
for pod in "$POD1" "$POD1B" "$PODS" "$POD1X" "$POD2" "$POD2X"; do
    ip -n "$pod" neigh flush all 2>/dev/null || true
done
ping_from "$POD1" "$ip1b" >/dev/null 2>&1 || true
ping_from "$POD1X" "$ip2x" >/dev/null 2>&1 || true
check "pod1x's host veth is a member of br-l2b" in_vrf_bridge 1 "$(host_veth "$POD1X")" br-l2b
eventually "PE2 imported pod1x's MAC into bd 200" remote_mac 2 02:00:00:00:be:ef 200
check "pod2 -> $ip1 reaches tenant-l2's pod1 only, not pod1x" reaches_only "$POD2" "$ip1" "$POD1" "$POD1X"
check "pod2x -> $ip1x reaches tenant-l2b's pod1x only, not pod1" reaches_only "$POD2X" "$ip1x" "$POD1X" "$POD1"

echo "--- the bridge gives a pod no path into the host stack ---"
brmac1=$(ip -n "$PE1" -o link show br-l2 | awk -F'link/ether ' '{print $2}' | awk '{print $1}')
# A pod that discovers the bridge MAC and routes a node address through it:
# rp_filter and forwarding must still drop it. Demonstrate with a UDP probe to
# a node address, first hardened (no delivery), then with rp_filter off.
ip -n "$POD1" neigh replace 10.255.0.1 lladdr "$brmac1" dev net1 nud permanent
ip -n "$POD1" route replace 10.255.0.1/32 dev net1
udp_probe() { # <listens-received?>
    ip netns exec "$PE1" timeout 3 python3 - "$@" <<'PY' &
import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("10.255.0.1",9999)); s.settimeout(2.5)
try:
    s.recvfrom(64); open(sys.argv[1],"w").write("got")
except Exception: pass
PY
    local lpid=$!
    sleep 0.3
    for _ in 1 2 3; do ip netns exec "$POD1" python3 -c 'import socket;socket.socket(socket.AF_INET,socket.SOCK_DGRAM).sendto(b"x",("10.255.0.1",9999))'; sleep 0.2; done
    wait "$lpid" 2>/dev/null || true
}
rm -f "$work/udp-hardened"
udp_probe "$work/udp-hardened"
check_not "UDP from a pod to a node address is dropped (rp_filter)" test -e "$work/udp-hardened"
# Negative control: with rp_filter off the same probe is delivered, proving
# the setting is what closes it.
ip netns exec "$PE1" sysctl -qw net.ipv4.conf.br-l2.rp_filter=0
ip netns exec "$PE1" sysctl -qw net.ipv4.conf.all.rp_filter=0
rm -f "$work/udp-open"
udp_probe "$work/udp-open"
check "negative control: with rp_filter off the probe is delivered" test -e "$work/udp-open"
ip netns exec "$PE1" sysctl -qw net.ipv4.conf.br-l2.rp_filter=1
# ND for the bridge: with disable_ipv6 the bridge has no link-local to answer.
check_not "ND for the bridge gets no reply (disable_ipv6)" \
    ip netns exec "$POD1B" ping -6 -c1 -W2 "ff02::1%net1"
# Negative control: re-enabling IPv6 gives the bridge a link-local.
ip netns exec "$PE1" sysctl -qw net.ipv6.conf.br-l2.disable_ipv6=0 || true
eventually "negative control: with disable_ipv6 off the bridge gets a link-local" \
    bash -c 'ip -n '"$PE1"' -o -6 addr show dev br-l2 scope link | grep -q inet6'
ip netns exec "$PE1" sysctl -qw net.ipv6.conf.br-l2.disable_ipv6=1
check "pod-to-pod still works after the hardening checks" ping_from "$POD1" "$ip1b"

echo "--- MTU at the boundary with DF set ---"
# An inner payload that fits (1422) and one that does not (1500) with DF.
check "DF ping within the L2 MTU succeeds" \
    ip netns exec "$POD1" ping -c2 -W2 -M "do" -s 1394 "$ip1b"
check_not "DF ping over the L2 MTU is dropped" \
    ip netns exec "$POD1" ping -c1 -W2 -M "do" -s 1472 "$ip2"

echo "--- DEL and re-ADD ---"
check "DEL pod1b" cni 1 DEL "$POD1B"
check_not "pod1b's veth is gone" ip -n "$PE1" link show "$(host_veth "$POD1B")"
check "re-ADD pod1b" cni_add 1 "$POD1B"
ip1b=$(pod_ip "$POD1B")
check "pod1 -> re-added pod1b" ping_from "$POD1" "$ip1b"

echo "--- netns gone before DEL ---"
# pod1b's host veth vanishes with the pod; DEL must still clean up.
ip -n "$PE1" link del "$(host_veth "$POD1B")" 2>/dev/null || true
check "DEL pod1b after its veth vanished" cni 1 DEL "$POD1B"
check "ADD still works for others afterwards" cni_add 1 "$POD1B"
ip1b=$(pod_ip "$POD1B")

echo "--- daemon restart (TERM), pods attached ---"
stop_pe 2
start_pe 2
check "host veth re-attached after restart (PE2)" device_attached 2 "$veth2"
check "PE2 kept pod2's bd circuit after restart" has_circuit 2 "$veth2" 100
eventually "PE1 learned pod2's MAC again after the PE2 restart" remote_mac 1 "$mac2" 100
eventually "pod1 -> pod2 after the PE2 restart" ping_from "$POD1" "$ip2"

echo "--- daemon restart (KILL), pods attached ---"
stop_pe 1 KILL
start_pe 1
check "host veth re-attached after kill (PE1)" device_attached 1 "$veth1"
check "PE1 kept pod1's bd circuit after kill" has_circuit 1 "$veth1" 100
check "br-l2 still hardened after the daemon restart" test "$(br_sysctl 1 net/ipv4/conf/br-l2/rp_filter)" = 1
eventually "pod2 -> pod1 after the PE1 kill-restart" ping_from "$POD2" "$ip1"

echo "--- DEL everything ---"
for d in "1 $POD1 tenant-l2" "1 $POD1B tenant-l2" "1 $PODS tenant-l2" "1 $POD1X tenant-l2b" "2 $POD2 tenant-l2" "2 $POD2X tenant-l2b"; do
    set -- $d
    check "DEL $2" cni "$1" DEL "$2" "$3"
done
check "the bridge stays after the last pod (PE1)" ip -n "$PE1" link show br-l2
check "CHECK after DEL fails" cni 1 CHECK "$POD1"

echo "=========================================="
echo "Passed: $PASS  Failed: $FAIL"
echo "=========================================="
((FAIL == 0))
