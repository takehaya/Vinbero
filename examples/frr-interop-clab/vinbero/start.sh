#!/bin/bash
# Bring up the Vinbero PE inside the containerlab node.
#
# Order matters: vinberod must be running before `vbctl locator create`,
# and the locator must exist before BGP routes from FRR settle -- the
# BGP applier needs the source locator registered to turn a received
# VPN route into a headend_v4/v6 map entry.
#
# This node is a *full* SRv6 L3VPN PE: it both H.Encaps plaintext CE
# traffic towards FRR (eth2 XDP) and runs an End.DT4 endpoint that
# decaps the return traffic FRR sends back (eth1 XDP).

# setknob writes a sysctl best-effort: container sysfs may be read-only
# for some keys, which must not abort the script.
setknob() {
    sysctl -w "$1=$2" >/dev/null 2>&1 || true
}

# --- interface addressing --------------------------------------------------
# eth1 faces FRR: the BGP session and the SRv6 underlay both ride it.
ip -6 addr add 2001:db8:ff::2/64 dev eth1 2>/dev/null || true
ip link set eth1 up

# eth2 faces the CE host. The CE sends plaintext IPv4 to this address as
# its default gateway into the L3VPN.
ip addr add 10.0.0.1/24 dev eth2 2>/dev/null || true
ip link set eth2 up

# --- SRv6 dataplane knobs (namespace-scoped, best-effort) ------------------
setknob net.ipv4.ip_forward 1
setknob net.ipv6.conf.all.forwarding 1
setknob net.ipv6.conf.all.seg6_enabled 1
setknob net.ipv6.conf.eth1.seg6_enabled 1
setknob net.ipv6.conf.eth2.seg6_enabled 1
setknob net.ipv4.conf.all.rp_filter 0
setknob net.ipv4.conf.default.rp_filter 0
setknob net.ipv4.conf.eth2.rp_filter 0

# veth + generic XDP: VLAN offload would hide tags from the XDP program.
ethtool -K eth1 txvlan off 2>/dev/null || true
ethtool -K eth1 rxvlan off 2>/dev/null || true
ethtool -K eth2 txvlan off 2>/dev/null || true
ethtool -K eth2 rxvlan off 2>/dev/null || true

# --- return-path VRF for the End.DT4 endpoint ------------------------------
# The End.DT4 endpoint decaps FRR's return traffic and does a FIB lookup
# in a dedicated routing table. eth2 is intentionally NOT enslaved to the
# VRF: the H.Encaps path (CE -> FRR) leaves the encapsulated IPv6 packet
# to the *main* table for the `fd00:200::/64` underlay route, while the
# decap path (FRR -> CE) hands the End.DT4 BPF FIB lookup the VRF device
# so it resolves the customer prefix from table 100 instead.
ip link add vrf-cust type vrf table 100 2>/dev/null || true
ip link set vrf-cust up
ip rule add l3mdev protocol kernel prio 1000 2>/dev/null || true
# The customer subnet reachable out eth2. Placed in table 100 so the
# End.DT4 BPF FIB lookup (keyed by the vrf-cust ifindex) resolves it.
ip route replace 10.0.0.0/24 dev eth2 table 100

# --- underlay route towards FRR's service SID ------------------------------
# After XDP H.Encaps + XDP_PASS, the kernel forwards the SRv6 packet by
# its outer destination (FRR's service SID, inside fd00:200::/64) out
# eth1 to FRR, which decaps it.
ip -6 route replace fd00:200::/64 via 2001:db8:ff::1 dev eth1

# BPF filesystem for pinned maps / XDP links.
mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true

mkdir -p /etc/vinbero
cp /vinbero.yml /etc/vinbero/vinbero.yaml

# Start the daemon with the in-process BGP speaker enabled.
/usr/local/bin/vinberod --bgp-enabled -c /etc/vinbero/vinbero.yaml \
    > /var/log/vinberod.log 2>&1 &
echo $! > /var/run/vinberod.pid

# Wait for the RPC server (localhost:8080) to accept connections.
for i in $(seq 1 30); do
    if /usr/local/bin/vbctl locator list >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

# Register the SRv6 source locator. `source_locator: LOC1` in
# vinbero.yml references this by name; the applier resolves the encap
# source from its prefix. fd00:100::/48 == Vinbero's locator block.
/usr/local/bin/vbctl locator create \
    --name LOC1 \
    --prefix fd00:100::/48 \
    --block-len 32 --node-len 16 --function-len 16 --argument-len 64 \
    --behavior classic || true

# --- return-path End.DT4 endpoint ------------------------------------------
# FRR encaps return traffic towards this SID; Vinbero's XDP decaps it and
# does an IPv4 FIB lookup in vrf-cust (table 100) -> 10.0.0.0/24 -> eth2.
/usr/local/bin/vbctl sid create \
    --trigger-prefix fd00:100:0:1::/128 \
    --action END_DT4 \
    --vrf-name vrf-cust || true

# --- advertise the CE customer subnet into the L3VPN -----------------------
# RT 65000:200 == FRR's vrf-cust import RT, so FRR installs an SRv6
# encap route for 10.0.0.0/24 towards the End.DT4 SID above. This is the
# control-plane half of the FRR -> CE return path.
/usr/local/bin/vbctl bgp advertise-vpn --family vpnv4 \
    --prefix 10.0.0.0/24 --rd 65100:200 --rts 65000:200 \
    --sid fd00:100:0:1:: --next-hop 2001:db8:ff::2 || true

# Pre-resolve neighbours so the XDP BPF FIB lookups never hit
# BPF_FIB_LKUP_RET_NO_NEIGH on the first packet: the underlay NDP entry
# for FRR (H.Encaps egress) and the CE ARP entry in table 100 (End.DT4
# decap egress).
ping6 -c 1 -W 2 2001:db8:ff::1 >/dev/null 2>&1 || true
ping -c 1 -W 2 10.0.0.10 >/dev/null 2>&1 || true

echo "[start.sh] vinbero PE ready"
