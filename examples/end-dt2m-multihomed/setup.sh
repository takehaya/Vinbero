#!/bin/bash
# examples/end-dt2m-multihomed/setup.sh
# 5-namespace multi-homed topology for RFC 9252 Split-Horizon + DF election.
#
# host1 dual-homes to PE1 and PE2 via a Linux bridge (shared CE, ES-1).
# Traffic: host1 -> (ES-1) -> PE1/PE2 -> P (End transit) -> PE3 -> host2
#
# All IP is static; VLAN 100 on host legs; MAC Pinning on host1 (02:00:00:00:00:01).

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../common/test_utils.sh"
source "${SCRIPT_DIR}/../common/netns.sh"
source "${SCRIPT_DIR}/../common/veth.sh"

check_root

# ---- namespace + interface naming (veth names ≤15 chars) ----
NS_H1="mh-host1"   NS_H2="mh-host2"
NS_PE1="mh-pe1"    NS_PE2="mh-pe2"    NS_PE3="mh-pe3"   NS_P="mh-p"

V_H1_PE1="mh-h1pe1" V_PE1_H1="mh-pe1h1"
V_H1_PE2="mh-h1pe2" V_PE2_H1="mh-pe2h1"
V_PE1_P="mh-pe1p"   V_P_PE1="mh-ppe1"
V_PE2_P="mh-pe2p"   V_P_PE2="mh-ppe2"
V_P_PE3="mh-ppe3"   V_PE3_P="mh-pe3p"
V_PE3_H2="mh-pe3h2" V_H2_PE3="mh-h2pe3"

BR="mh-h1-br"
VLAN_IF="mh-h1-v100"
HOST1_IP="172.16.100.1/24"
HOST2_IP="172.16.100.2/24"
HOST1_MAC="02:00:00:00:00:01"

print_info "Creating namespaces..."
for ns in "$NS_H1" "$NS_H2" "$NS_PE1" "$NS_PE2" "$NS_PE3" "$NS_P"; do
    create_netns "$ns"
done

# ---- veth pairs ----
print_info "Creating veth pairs..."
create_veth_pair "$V_H1_PE1" "$NS_H1" "$V_PE1_H1" "$NS_PE1"
create_veth_pair "$V_H1_PE2" "$NS_H1" "$V_PE2_H1" "$NS_PE2"
create_veth_pair "$V_PE1_P"  "$NS_PE1" "$V_P_PE1" "$NS_P"
create_veth_pair "$V_PE2_P"  "$NS_PE2" "$V_P_PE2" "$NS_P"
create_veth_pair "$V_P_PE3"  "$NS_P"   "$V_PE3_P" "$NS_PE3"
create_veth_pair "$V_PE3_H2" "$NS_PE3" "$V_H2_PE3" "$NS_H2"

# ---- disable IPv6 on hosts (we only do IPv4 in the overlay) ----
for ns in "$NS_H1" "$NS_H2"; do
    ns_sysctl "$ns" net.ipv6.conf.all.disable_ipv6 1
    ns_sysctl "$ns" net.ipv6.conf.default.disable_ipv6 1
done

# ---- host1: bridge + VLAN 100 + static MAC ----
print_info "Configuring host1 shared-CE bridge..."
run ip netns exec "$NS_H1" ip link add "$BR" type bridge
run ip netns exec "$NS_H1" ip link set "$BR" address "$HOST1_MAC"
run ip netns exec "$NS_H1" ip link set "$BR" up
run ip netns exec "$NS_H1" ip link set "$V_H1_PE1" master "$BR"
run ip netns exec "$NS_H1" ip link set "$V_H1_PE2" master "$BR"

run modprobe 8021q 2>/dev/null || true
run ip netns exec "$NS_H1" ip link add link "$BR" name "$VLAN_IF" type vlan id 100
run ip netns exec "$NS_H1" ip link set "$VLAN_IF" address "$HOST1_MAC"
run ip netns exec "$NS_H1" ip addr add "$HOST1_IP" dev "$VLAN_IF"
run ip netns exec "$NS_H1" ip link set "$VLAN_IF" up

# ---- host2: plain VLAN 100 on veth ----
print_info "Configuring host2..."
run ip netns exec "$NS_H2" ip link add link "$V_H2_PE3" name "${V_H2_PE3}.100" type vlan id 100
run ip netns exec "$NS_H2" ip addr add "$HOST2_IP" dev "${V_H2_PE3}.100"
run ip netns exec "$NS_H2" ip link set "${V_H2_PE3}.100" up

# ---- disable VLAN offload on anything touching VLAN 100 ----
print_info "Disabling VLAN offload..."
for entry in \
    "$NS_H1:$V_H1_PE1" "$NS_H1:$V_H1_PE2" \
    "$NS_PE1:$V_PE1_H1" "$NS_PE2:$V_PE2_H1" \
    "$NS_PE3:$V_PE3_H2" "$NS_H2:$V_H2_PE3"; do
    IFS=: read -r ns iface <<< "$entry"
    run ip netns exec "$ns" ethtool -K "$iface" txvlan off rxvlan off 2>/dev/null || true
done

# ---- PE / P loopbacks ----
run ip netns exec "$NS_PE1" ip -6 addr add fc00:1::1/128 dev lo
run ip netns exec "$NS_PE2" ip -6 addr add fc00:2::2/128 dev lo
run ip netns exec "$NS_PE3" ip -6 addr add fc00:3::3/128 dev lo
run ip netns exec "$NS_P"   ip -6 addr add fc00:99::1/128 dev lo

# ---- router sysctls ----
for ns in "$NS_PE1" "$NS_PE2" "$NS_PE3" "$NS_P"; do
    ns_sysctl "$ns" net.ipv4.conf.all.forwarding 1
    ns_sysctl "$ns" net.ipv6.conf.all.forwarding 1
    ns_sysctl "$ns" net.ipv4.conf.all.rp_filter 0
    ns_enable_srv6 "$ns"
done

# ---- SRv6 uplinks: fc00:1p::/64 PE1-P, fc00:2p::/64 PE2-P, fc00:3p::/64 PE3-P ----
run ip netns exec "$NS_PE1" ip addr add fc00:10::1/64 dev "$V_PE1_P"
run ip netns exec "$NS_P"   ip addr add fc00:10::2/64 dev "$V_P_PE1"
run ip netns exec "$NS_PE2" ip addr add fc00:20::1/64 dev "$V_PE2_P"
run ip netns exec "$NS_P"   ip addr add fc00:20::2/64 dev "$V_P_PE2"
run ip netns exec "$NS_P"   ip addr add fc00:30::2/64 dev "$V_P_PE3"
run ip netns exec "$NS_PE3" ip addr add fc00:30::1/64 dev "$V_PE3_P"

# ---- IPv6 routes via P ----
for prefix in fc00:2 fc00:3 fc00:99; do
    run ip netns exec "$NS_PE1" ip -6 route add "${prefix}::/64" via fc00:10::2
done

run ip netns exec "$NS_PE2" ip -6 route add fc00:1::/64 via fc00:20::2
run ip netns exec "$NS_PE2" ip -6 route add fc00:3::/64 via fc00:20::2
run ip netns exec "$NS_PE2" ip -6 route add fc00:99::/64 via fc00:20::2

run ip netns exec "$NS_PE3" ip -6 route add fc00:1::/64 via fc00:30::2
run ip netns exec "$NS_PE3" ip -6 route add fc00:2::/64 via fc00:30::2
run ip netns exec "$NS_PE3" ip -6 route add fc00:99::/64 via fc00:30::2

run ip netns exec "$NS_P" ip -6 route add fc00:1::/64 via fc00:10::1
run ip netns exec "$NS_P" ip -6 route add fc00:2::/64 via fc00:20::1
run ip netns exec "$NS_P" ip -6 route add fc00:3::/64 via fc00:30::1

# ---- P router: Linux native End transit ----
run ip netns exec "$NS_P" ip -6 route del local fc00:99::1 2>/dev/null || true
run ip netns exec "$NS_P" ip -6 route add local fc00:99::1/128 encap seg6local action End dev lo

# ---- Enable seg6_enabled on carrier ifaces ----
for entry in \
    "$NS_PE1:$V_PE1_P" "$NS_PE2:$V_PE2_P" \
    "$NS_P:$V_P_PE1"  "$NS_P:$V_P_PE2"  "$NS_P:$V_P_PE3" \
    "$NS_PE3:$V_PE3_P"; do
    IFS=: read -r ns iface <<< "$entry"
    ns_sysctl "$ns" "net.ipv6.conf.${iface}.seg6_enabled" 1
done

# PE1 and PE2 need a bridge too so End.DT2M (RX side) can flood BUM to host1.
print_info "Creating bridge br100 on PE1/PE2/PE3..."
for entry in "$NS_PE1:$V_PE1_H1" "$NS_PE2:$V_PE2_H1" "$NS_PE3:$V_PE3_H2"; do
    IFS=: read -r ns iface <<< "$entry"
    run ip netns exec "$ns" ip link add br100 type bridge
    run ip netns exec "$ns" ip link set br100 up
    run ip netns exec "$ns" ip link set "$iface" master br100
done

# ---- Pre-resolve NDP on carrier links ----
print_info "Pre-resolving NDP..."
ip netns exec "$NS_PE1" ping6 -c 1 -W 1 fc00:10::2 > /dev/null 2>&1 || true
ip netns exec "$NS_P"   ping6 -c 1 -W 1 fc00:10::1 > /dev/null 2>&1 || true
ip netns exec "$NS_PE2" ping6 -c 1 -W 1 fc00:20::2 > /dev/null 2>&1 || true
ip netns exec "$NS_P"   ping6 -c 1 -W 1 fc00:20::1 > /dev/null 2>&1 || true
ip netns exec "$NS_PE3" ping6 -c 1 -W 1 fc00:30::2 > /dev/null 2>&1 || true
ip netns exec "$NS_P"   ping6 -c 1 -W 1 fc00:30::1 > /dev/null 2>&1 || true

echo ""
echo "=========================================="
echo "End.DT2M Multi-homed topology ready"
echo "=========================================="
echo "  host1 (VLAN 100, MAC 02:00:00:00:00:01)"
echo "    ├─ shared CE (bridge $BR)"
echo "    ├── PE1 (fc00:1::1)  ─┐"
echo "    └── PE2 (fc00:2::2)  ─┤  both attached to ES-1"
echo "                          └── P (End transit, fc00:99::1)"
echo "                               └── PE3 (fc00:3::3) ── host2"
echo ""
print_success "Now launch PE1/PE2/PE3 vinberod and run test.sh"
