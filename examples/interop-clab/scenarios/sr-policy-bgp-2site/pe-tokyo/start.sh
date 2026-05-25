#!/bin/bash
# Bring up the Vinbero PE pe-tokyo for the sr-policy-bgp-2site scenario.
#
# pe-tokyo is a full SRv6 L3VPN PE that also exchanges SR Policies with the
# far PE (pe-osaka). It advertises its own customer subnet as a colored VPN
# route and an SR Policy for reaching itself (transport = the waypoint End
# SID), and it receives pe-osaka's colored route + SR Policy to steer its
# ce-osaka-bound traffic through the waypoint.
#
# Interfaces:
#   eth1  pe-tokyo <-> core      underlay 2001:db8:1::/64  (pe-tokyo = ::1)
#   eth2  pe-tokyo <-> ce-tokyo  customer 10.1.0.0/24      (pe-tokyo = .1)
#   lo    loopback 2001:db8:ff::1  (iBGP peering / SRv6 transport)

setknob() {
    sysctl -w "$1=$2" >/dev/null 2>&1 || true
}

# --- interface addressing --------------------------------------------------
ip -6 addr add 2001:db8:1::1/64 dev eth1 2>/dev/null || true
ip link set eth1 up
ip addr add 10.1.0.1/24 dev eth2 2>/dev/null || true
ip link set eth2 up
ip -6 addr add 2001:db8:ff::1/128 dev lo 2>/dev/null || true
ip link set lo up

# --- SRv6 dataplane knobs --------------------------------------------------
setknob net.ipv4.ip_forward 1
setknob net.ipv6.conf.all.forwarding 1
setknob net.ipv6.conf.all.seg6_enabled 1
setknob net.ipv6.conf.eth1.seg6_enabled 1
setknob net.ipv6.conf.eth2.seg6_enabled 1
setknob net.ipv4.conf.all.rp_filter 0
setknob net.ipv4.conf.default.rp_filter 0
setknob net.ipv4.conf.eth2.rp_filter 0

ethtool -K eth1 txvlan off 2>/dev/null || true
ethtool -K eth1 rxvlan off 2>/dev/null || true
ethtool -K eth2 txvlan off 2>/dev/null || true
ethtool -K eth2 rxvlan off 2>/dev/null || true

# --- return-path VRF for the End.DT4 endpoint ------------------------------
if ! ip link show vrf-cust >/dev/null 2>&1; then
    ip link add vrf-cust type vrf table 100
fi
if ! ip link show vrf-cust >/dev/null 2>&1; then
    echo "ERROR: failed to create VRF vrf-cust -- is the kernel 'vrf' module loaded on the host? (modprobe vrf)" >&2
    exit 1
fi
ip link set vrf-cust up
ip rule add l3mdev protocol kernel prio 1000 2>/dev/null || true
ip route replace 10.1.0.0/24 dev eth2 table 100

# --- static underlay routes ------------------------------------------------
# pe-osaka's loopback (iBGP peer) and locator block (service SID), plus the
# waypoint's End block (first transport hop of the steered path). All reach
# via the core.
ip -6 route replace 2001:db8:ff::2/128 via 2001:db8:1::2 dev eth1 \
    src 2001:db8:ff::1
ip -6 route replace fd00:200::/48 via 2001:db8:1::2 dev eth1
ip -6 route replace fd00:300::/48 via 2001:db8:1::2 dev eth1

mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true

mkdir -p /etc/vinbero
cp /vinbero.yml /etc/vinbero/vinbero.yaml

/usr/local/bin/vinberod --bgp-enabled -c /etc/vinbero/vinbero.yaml \
    > /var/log/vinberod.log 2>&1 &
echo $! > /var/run/vinberod.pid

for i in $(seq 1 30); do
    if /usr/local/bin/vbctl locator list >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

# Source locator: fd00:100::/48 is pe-tokyo's SRv6 block.
/usr/local/bin/vbctl locator create \
    --name LOC1 \
    --prefix fd00:100::/48 \
    --block-len 32 --node-len 16 --function-len 16 --argument-len 64 \
    --behavior classic || true

# End.DT4 service SID: decaps the far PE's traffic into vrf-cust -> ce-tokyo.
/usr/local/bin/vbctl sid create \
    --trigger-prefix fd00:100:0:1::/128 \
    --action END_DT4 \
    --vrf-name vrf-cust || true

# Advertise the local customer subnet as a COLORED VPN route. color 100
# marks it for steering on pe-osaka; the next hop is our loopback, which is
# also the endpoint of the SR Policy we advertise below.
/usr/local/bin/vbctl bgp advertise-vpn --family vpnv4 \
    --prefix 10.1.0.0/24 --rd 65100:100 --rts 65000:100 \
    --sid fd00:100:0:1:: --next-hop 2001:db8:ff::1 --color 100 || true

# Advertise the SR Policy for reaching THIS PE: {color 100, endpoint = our
# loopback, transport = waypoint End SID}. pe-osaka receives it and steers
# its color-100 route to 10.1.0.0/24 (next hop = our loopback) through the
# waypoint.
/usr/local/bin/vbctl bgp advertise-sr-policy \
    --color 100 \
    --endpoint 2001:db8:ff::1 \
    --segments fd00:300:0:ee::1 \
    --distinguisher 1 \
    --next-hop 2001:db8:ff::1 || true

# Pre-resolve the core neighbour and the ce-tokyo ARP entry.
ping6 -c 1 -W 2 2001:db8:1::2 >/dev/null 2>&1 || true
ping -c 1 -W 2 10.1.0.10 >/dev/null 2>&1 || true

echo "[start.sh] pe-tokyo (Vinbero) PE ready"
