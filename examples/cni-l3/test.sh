#!/usr/bin/env bash
# Runs the vinbero CNI plugin the way a container runtime does (CNI_COMMAND
# and the network configuration on stdin) against two PEs, and checks
# pod-to-pod traffic over SRv6, the /32 VPNv4 advertisement, and that DEL
# withdraws the route and detaches the veth.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
check_root
for binary in "$VINBEROD_BIN" "$VINBERO_BIN" "$CNI_BIN"; do
    [[ -x "$binary" ]] || { print_error "Missing $binary; build first: make build"; exit 1; }
done
for dep in jq timeout; do command -v "$dep" >/dev/null; done

# The plugin delegates IPAM; host-local comes with the reference plugins.
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
for ns in "${NAMESPACES[@]}"; do
    ip -n "$ns" link show lo >/dev/null
done
for ns in "$PE1" "$PE2"; do
    [[ -z "$(ip netns pids "$ns")" ]] || { print_error "$ns is already in use"; exit 1; }
done

work=$(mktemp -d /tmp/vinbero_cni_l3.XXXXXX)
# The plugin execs IPAM from CNI_PATH; keep both binaries in one place.
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
        for log in "$work"/*.log; do echo "--- $log"; tail -60 "$log"; done
    fi
    echo "Daemon logs and state: $work"
    exit "$rc"
}
trap cleanup EXIT

start_pe() {
    local node=$1
    sed "s|__STATE_PATH__|$work/pe$node-state.json|" "$EXAMPLE_DIR/vinbero_pe$node.yaml" > "$work/pe$node.yaml"
    ip netns exec "cnil3-pe$node" "$VINBEROD_BIN" --bgp-enabled -c "$work/pe$node.yaml" >> "$work/pe$node.log" 2>&1 &
    pids[$node]=$!
    wait_for "cnil3-pe$node RPC ready" ctl "cnil3-pe$node" locator list
}

stop_pe() {
    local node=$1
    kill -TERM "${pids[$node]}"
    wait "${pids[$node]}" 2>/dev/null || true
    unset "pids[$node]"
}

PASS=0
FAIL=0
pass() { print_success "$1"; PASS=$((PASS + 1)); }
fail() { print_error "$1"; FAIL=$((FAIL + 1)); }
check() {
    local desc=$1; shift
    if "$@" > /dev/null 2>&1; then pass "$desc"; else fail "$desc"; fi
}
check_not() {
    local desc=$1; shift
    if "$@" > /dev/null 2>&1; then fail "$desc"; else pass "$desc"; fi
}
eventually() {
    local desc=$1; shift
    if wait_for "$desc" "$@"; then PASS=$((PASS + 1)); else FAIL=$((FAIL + 1)); fi
}

# netconf <node>: PE1's network configuration carries the BGP binding, so
# the first ADD creates the VRF and binds it; PE2's only names the VRF,
# whose binding comes from vinbero_pe2.yaml.
netconf() {
    local node=$1 binding=""
    if [[ "$node" == 1 ]]; then
        binding='"rd": "65100:1", "rts": [{"family": "vpnv4", "rt": "65000:100", "direction": "both"}], "locator": "LOC1",'
    fi
    cat <<JSON
{
  "cniVersion": "1.0.0",
  "name": "tenant-a",
  "type": "vinbero",
  "server": "127.0.0.1:8084",
  "vrf": "tenant-a",
  "tableId": 100,
  $binding
  "dataDir": "$work/cni-pe$node",
  "ipam": {
    "type": "host-local",
    "dataDir": "$work/ipam-pe$node",
    "ranges": [[{"subnet": "10.100.$node.0/24"}]],
    "routes": [{"dst": "10.100.0.0/16"}]
  }
}
JSON
}

# cni <node> <command> <pod>: run the plugin on a PE for a pod netns.
cni() {
    local node=$1 cmd=$2 pod=$3
    netconf "$node" | ip netns exec "cnil3-pe$node" env \
        CNI_COMMAND="$cmd" CNI_CONTAINERID="$pod" CNI_NETNS="/var/run/netns/$pod" \
        CNI_IFNAME=net1 CNI_PATH="$cni_path" "$cni_path/vinbero"
}

host_veth() {
    jq -r '.interfaces[0].name' "$work/$1.json"
}

pod_ip() {
    jq -r '.ips[0].address | split("/")[0]' "$work/$1.json"
}

# headend_to <node> <ip>: the PE has an encap entry for ip/32 in tenant-a
# whose service SID is in the other PE's locator, i.e. it imported the VPNv4
# route into the VRF its pods' ports classify to, and nothing for it in the
# global VRF.
headend_to() {
    local node=$1 ip=$2 other=$((3 - $1))
    ctl "cnil3-pe$node" --json headend-v4 list --vrf tenant-a |
        jq -e --arg p "$ip/32" --arg loc "fd00:$other:" \
            'any(.[]?; .trigger_prefix == $p and (.segments[0] | startswith($loc)))' &&
        ctl "cnil3-pe$node" --json headend-v4 list --vrf global |
        jq -e --arg p "$ip/32" 'all(.[]?; .trigger_prefix != $p)'
}

# no_headend_to <node> <ip>: no VRF has an encap entry for ip/32.
no_headend_to() {
    ctl "cnil3-pe$1" --json headend-v4 list --all-vrfs | jq -e --arg p "$2/32" 'all(.[]?; .trigger_prefix != $p)'
}

device_attached() {
    ctl "cnil3-pe$1" --json device list |
        jq -e --arg n "$2" 'any(.devices[]?; .name == $n and .mode == "generic" and (.config | not))'
}

has_ac() {
    ctl "cnil3-pe$1" --json vrf show |
        jq -e --arg n "$2" 'any(.vrfs[]? | select(.name == "tenant-a") | .acs[]?; .interface_name == $n)'
}

static_route() {
    ip -n "cnil3-pe$1" -j route show table 100 "$2/32" proto static | jq -e 'length == 1'
}

cni_add() {
    cni "$1" ADD "$2" > "$work/$2.json"
}

bound_with_rd() {
    ctl "cnil3-pe$1" --json vrf-bgp list |
        jq -e --arg rd "$2" 'any(.[]?; .vrf_name == "tenant-a" and .rd == $rd)'
}

only_config_device() {
    ctl "cnil3-pe$1" --json device list | jq -e '[.devices[]?.name] == ["eth1"]'
}

in_vrf() {
    ip -n "cnil3-pe$1" link show "$2" | grep -q 'master tenant-a'
}

pod_has() {
    ip -n "$1" -4 addr show dev net1 | grep -q "inet $2/32"
}

pod_routes_range() {
    ip -n "$1" route show 10.100.0.0/16 | grep -q 'via 169.254.1.1 dev net1'
}

pod_mtu() {
    ip -n "$1" link show net1 | grep -q "mtu $2"
}

vrf_table() {
    ip -n "cnil3-pe$1" -d link show tenant-a | grep -q "vrf table $2"
}

permanent_neigh() {
    ip -n "cnil3-pe$1" neigh show "$2" dev "$3" | grep -q PERMANENT
}

has_xdp() {
    ip -n "cnil3-pe$1" link show "$2" | grep -q xdp
}

ping_from() {
    ip netns exec "$1" ping -c 2 -W 2 "$2"
}

echo "=========================================="
echo "vinbero CNI plugin, L3 mode"
echo "=========================================="

start_pe 1
start_pe 2

check "ADD pod1 on PE1" cni_add 1 $POD1
check "ADD pod1b on PE1" cni_add 1 $POD1B
check "ADD pod2 on PE2" cni_add 2 $POD2
ip1=$(pod_ip "$POD1")
ip1b=$(pod_ip "$POD1B")
ip2=$(pod_ip "$POD2")
veth1=$(host_veth "$POD1")
veth2=$(host_veth "$POD2")
echo "pod1 $ip1 ($veth1), pod1b $ip1b, pod2 $ip2 ($veth2)"
check "ADD result: /32 via the link-local gateway" \
    jq -e '.ips[0].address | endswith("/32")' "$work/$POD1.json"
check "pod1 has its address on net1" pod_has "$POD1" "$ip1"
check "pod1 routes the cluster range via 169.254.1.1" pod_routes_range "$POD1"
check "pod MTU leaves room for the SRv6 encap" pod_mtu "$POD1" 1436
check "PE1 created the VRF on table 100" vrf_table 1 100
check "PE1 bound the VRF from the network configuration" bound_with_rd 1 65100:1
check "PE2 kept the binding from its config" bound_with_rd 2 65100:2
check "host veth is in the VRF" in_vrf 1 "$veth1"
check "static /32 in the VRF table (PE1)" static_route 1 "$ip1"
check "permanent neighbour for the pod (PE1)" permanent_neigh 1 "$ip1" "$veth1"
check "host veth attached (PE1)" device_attached 1 "$veth1"
check "host veth attached (PE2)" device_attached 2 "$veth2"
check "host veth is an ingress AC of the VRF" has_ac 1 "$veth1"
check "XDP program on the host veth" has_xdp 1 "$veth1"
eventually "PE2 imported pod1's /32 with a PE1 SID" headend_to 2 "$ip1"
eventually "PE2 imported pod1b's /32" headend_to 2 "$ip1b"
eventually "PE1 imported pod2's /32 with a PE2 SID" headend_to 1 "$ip2"

check "pod1 -> pod2 across the PEs" ping_from "$POD1" "$ip2"
check "pod2 -> pod1b across the PEs" ping_from "$POD2" "$ip1b"
check "pod1 -> pod1b on the same PE" ping_from "$POD1" "$ip1b"
check "CHECK pod1" cni 1 CHECK $POD1

# A restart keeps the config binding and re-attaches the veth from the
# state file; the pod route is still in the VRF table and is advertised
# again.
stop_pe 2
start_pe 2
check "host veth re-attached after restart (PE2)" device_attached 2 "$veth2"
eventually "PE1 imported pod2's /32 again after the restart" headend_to 1 "$ip2"
eventually "pod1 -> pod2 after the PE2 restart" ping_from "$POD1" "$ip2"

check "DEL pod1" cni 1 DEL $POD1
eventually "PE2 withdrew pod1's /32" no_headend_to 2 "$ip1"
check_not "host veth detached" device_attached 1 "$veth1"
check_not "AC removed" has_ac 1 "$veth1"
check_not "host veth deleted" ip -n "$PE1" link show "$veth1"
check_not "pod interface deleted" ip -n "$POD1" link show net1
check_not "static route gone" static_route 1 "$ip1"
check "IPAM lease released" test ! -e "$work/ipam-pe1/tenant-a/$ip1"
check "attachment record removed" test ! -e "$work/cni-pe1/${POD1}_net1.json"
check_not "pod2 -> pod1 fails after DEL" ping_from "$POD2" "$ip1"
check "pod2 -> pod1b still works" ping_from "$POD2" "$ip1b"
check "DEL pod1 again succeeds" cni 1 DEL $POD1
check_not "CHECK pod1 after DEL fails" cni 1 CHECK $POD1

# pod1b's veth vanishes before its DEL: its stale AC must not block the other
# pods' AC changes.
ip -n "$PE1" link del "$(host_veth "$POD1B")"
check "ADD with a vanished veth's AC present" cni_add 1 "$POD1"
check "DEL pod1 with a vanished veth's AC present" cni 1 DEL $POD1
check "DEL pod1b after its veth vanished" cni 1 DEL $POD1B
check "DEL pod2" cni 2 DEL $POD2
eventually "PE1 withdrew pod2's /32" no_headend_to 1 "$ip2"
check "only the config device is left (PE1)" only_config_device 1
check "the VRF stays after the last pod" ip -n "$PE1" link show tenant-a

echo "=========================================="
echo "Passed: $PASS  Failed: $FAIL"
echo "=========================================="
((FAIL == 0))
