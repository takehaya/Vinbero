#!/bin/bash
# bench/rq1/topo/setup.sh
#
# Topology for the RQ1 convergence measurement.
#
#   src ---- rt (Vinbero headend, XDP) ---- pea  (End.DT4 for fd00:a::100)
#                                     \---- peb  (End.DT4 for fd00:b::100)
#
# The traffic never changes: src sends UDP to 10.0.2.2 throughout. What changes
# is one headend map entry, whose SID selects which PE decapsulates and delivers
# the packet. That single entry is the route whose reflection RQ1 measures, and
# the PE that receives the traffic is how convergence is observed.
#
# Both PEs own 10.0.2.2 in their own namespace, so the destination address is
# identical on either path and the sender needs no knowledge of the change.

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# REPO_ROOT is overridable so this can run from a snapshot of the directory,
# which is how a long measurement avoids reading a file that may be edited.
REPO_ROOT="${REPO_ROOT:-$(cd "${SCRIPT_DIR}/../../.." && pwd)}"
source "${NETNS_HELPER:-${REPO_ROOT}/examples/common/netns.sh}"

export TOPO_NS_PREFIX="${TOPO_NS_PREFIX:-rq1-}"

ns_src="${TOPO_NS_PREFIX}src"
ns_rt="${TOPO_NS_PREFIX}rt"
ns_pea="${TOPO_NS_PREFIX}pea"
ns_peb="${TOPO_NS_PREFIX}peb"

veth_src_rt="${TOPO_NS_PREFIX}srcrt"
veth_rt_src="${TOPO_NS_PREFIX}rtsrc"
veth_rt_pea="${TOPO_NS_PREFIX}rtpea"
veth_pea_rt="${TOPO_NS_PREFIX}pears"
veth_rt_peb="${TOPO_NS_PREFIX}rtpeb"
veth_peb_rt="${TOPO_NS_PREFIX}pebrt"

# This measurement owns fresh namespaces. Refuse collisions rather than using
# the examples' create_netns helper, which deletes an existing namespace.
[[ "$TOPO_NS_PREFIX" =~ ^[a-zA-Z0-9-]{1,9}$ ]] || { echo "invalid namespace prefix" >&2; exit 1; }
namespaces="$(ip netns list)"
for ns in "$ns_src" "$ns_rt" "$ns_pea" "$ns_peb"; do
    if awk '{print $1}' <<< "$namespaces" | grep -Fxq -- "$ns"; then
        echo "namespace already exists: $ns" >&2
        exit 1
    fi
done
created=()
rollback() {
    local status=$?
    for ns in "${created[@]}"; do
        ip netns del "$ns" || echo "rollback could not delete namespace: $ns" >&2
    done
    return "$status"
}
trap rollback EXIT
for ns in "$ns_src" "$ns_rt" "$ns_pea" "$ns_peb"; do
    ip netns add "$ns"
    created+=("$ns")
    ip netns exec "$ns" ip link set lo up
done

link_pair() {
    local a_if="$1" a_ns="$2" b_if="$3" b_ns="$4"
    ip link add "$a_if" type veth peer name "$b_if"
    ip link set "$a_if" netns "$a_ns"
    ip link set "$b_if" netns "$b_ns"
    ip netns exec "$a_ns" ip link set "$a_if" up
    ip netns exec "$b_ns" ip link set "$b_if" up
    # XDP reads packet data, so a VLAN tag parked in skb->vlan_tci would be
    # invisible. Nothing here is tagged, but the offload is disabled anyway so
    # the topology stays honest if tags are added later.
    ip netns exec "$a_ns" ethtool -K "$a_if" txvlan off >/dev/null 2>&1 || true
    ip netns exec "$b_ns" ethtool -K "$b_if" txvlan off >/dev/null 2>&1 || true
}

link_pair "$veth_src_rt" "$ns_src" "$veth_rt_src" "$ns_rt"
link_pair "$veth_rt_pea" "$ns_rt" "$veth_pea_rt" "$ns_pea"
link_pair "$veth_rt_peb" "$ns_rt" "$veth_peb_rt" "$ns_peb"

# Access side: src reaches the tenant prefix through rt.
ip netns exec "$ns_src" ip addr add 10.0.1.2/24 dev "$veth_src_rt"
ip netns exec "$ns_rt" ip addr add 10.0.1.1/24 dev "$veth_rt_src"
ip netns exec "$ns_src" ip route add 10.0.2.0/24 via 10.0.1.1

# Underlay: one IPv6 link to each PE.
ip netns exec "$ns_rt" ip -6 addr add fd00:12::1/64 dev "$veth_rt_pea"
ip netns exec "$ns_pea" ip -6 addr add fd00:12::2/64 dev "$veth_pea_rt"
ip netns exec "$ns_rt" ip -6 addr add fd00:13::1/64 dev "$veth_rt_peb"
ip netns exec "$ns_peb" ip -6 addr add fd00:13::2/64 dev "$veth_peb_rt"

ns_enable_srv6 "$ns_rt"
ns_enable_srv6 "$ns_pea"
ns_enable_srv6 "$ns_peb"

# Reverse path filtering drops the decapsulated packets on the PEs, whose
# source lives behind rt on an interface the PE has no route back through.
for ns in "$ns_pea" "$ns_peb"; do
    ns_sysctl "$ns" net.ipv4.conf.all.rp_filter 0
    ns_sysctl "$ns" net.ipv4.conf.default.rp_filter 0
    # End.DT4 delivers into a VRF, and a socket bound to the wildcard address
    # only sees that traffic once l3mdev accept is on. Without this the packets
    # arrive on the wire and are then dropped before any receiver sees them.
    ns_sysctl "$ns" net.ipv4.udp_l3mdev_accept 1
    ns_sysctl "$ns" net.ipv4.tcp_l3mdev_accept 1
done
ns_sysctl "$ns_rt" net.ipv4.ip_forward 1
ns_sysctl "$ns_rt" net.ipv6.conf.all.forwarding 1

# Locators. Each PE terminates one SID, and rt reaches both.
ip netns exec "$ns_pea" ip -6 addr add fd00:a::1/128 dev lo
ip netns exec "$ns_peb" ip -6 addr add fd00:b::1/128 dev lo
ip netns exec "$ns_rt" ip -6 route add fd00:a::/64 via fd00:12::2 dev "$veth_rt_pea"
ip netns exec "$ns_rt" ip -6 route add fd00:b::/64 via fd00:13::2 dev "$veth_rt_peb"

# Tenant side of each PE. The address is the same on both, so the probe target
# is unchanged by the route move; only which namespace answers changes.
# End.DT4 looks the inner destination up in a VRF table, so the tenant
# interface is enslaved to one and the kernel's strict mode is enabled, which
# it requires before a seg6local route may name a table.
for ns in "$ns_pea" "$ns_peb"; do
    ip netns exec "$ns" ip link add vrf100 type vrf table 100
    ip netns exec "$ns" ip link set vrf100 up
    ip netns exec "$ns" ip rule add l3mdev protocol kernel prio 1000 2>/dev/null || true
    ns_sysctl "$ns" net.vrf.strict_mode 1

    ip netns exec "$ns" ip link add tenant type dummy
    ip netns exec "$ns" ip link set tenant master vrf100
    ip netns exec "$ns" ip link set tenant up
    ip netns exec "$ns" ip addr add 10.0.2.2/32 dev tenant
done

# End.DT4: decapsulate and look the inner IPv4 destination up in the tenant VRF.
ip netns exec "$ns_pea" ip -6 route add local fd00:a::100/128 \
    encap seg6local action End.DT4 vrftable 100 dev lo
ip netns exec "$ns_peb" ip -6 route add local fd00:b::100/128 \
    encap seg6local action End.DT4 vrftable 100 dev lo

# bpf_fib_lookup on the headend needs resolved neighbours, and so does the
# return path; warm both directions before any measurement runs.
warm_neighbor() {
    local ns=$1 address=$2
    # IPv6 duplicate address detection may still be running just after setup.
    for attempt in {1..5}; do
        if ip netns exec "$ns" ping6 -c 1 -W 1 "$address" >/dev/null 2>&1; then return 0; fi
        sleep 1
    done
    echo "neighbor warm-up failed: $ns -> $address" >&2
    return 1
}
warm_neighbor "$ns_rt" fd00:12::2
warm_neighbor "$ns_rt" fd00:13::2
warm_neighbor "$ns_pea" fd00:12::1
warm_neighbor "$ns_peb" fd00:13::1

echo "topology up: $ns_src $ns_rt $ns_pea $ns_peb"
# Publish ownership before releasing rollback. The parent may handle a signal
# as soon as this foreground script exits, before updating its own variables.
if [[ -n "${TOPOLOGY_READY_FILE:-}" ]]; then touch "$TOPOLOGY_READY_FILE"; fi
trap - EXIT
