#!/bin/bash
# Data-side MUP-PE (MUP Provider Edge), mup-pe, for the mup-2site-multivrf
# scenario.
#
# Hosts one direct segment per VPN: End.DT4 into kernel VRF vrf-a (-> dn-a)
# and into vrf-b (-> dn-b). The two data networks overlap completely
# (both 10.0.0.0/24 with the DN host at .1), so the per-VPN direct SID and
# the kernel VRF are the only things keeping their traffic apart.
#
#   eth1  mup-pe <-> core  SRv6   2001:db8:2::1/64
#   eth2  mup-pe <-> dn-a  N6-A   10.0.0.254/24 (enslaved to vrf-a)
#   eth3  mup-pe <-> dn-b  N6-B   10.0.0.254/24 (enslaved to vrf-b)
#   lo    loopback 2001:db8:ff::d
set -u

ip -6 addr add 2001:db8:2::1/64 dev eth1 2>/dev/null || true
ip link set eth1 up
ip -6 addr add 2001:db8:ff::d/128 dev lo 2>/dev/null || true
# Dedicated v4 loopback used as the DSD originator address (RFC 9433 §3.2:
# Address = originator/PE identifier); both DSDs share it since they have the
# same originator. Kept off the data networks so it cannot be confused with
# an N6 endpoint.
ip addr add 10.255.0.2/32 dev lo 2>/dev/null || true
ip link set lo up

sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.all.seg6_enabled=1 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.eth1.seg6_enabled=1 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.eth2.rp_filter=0 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.eth3.rp_filter=0 >/dev/null 2>&1 || true
for i in eth1 eth2 eth3; do ethtool -K $i txvlan off 2>/dev/null || true; ethtool -K $i rxvlan off 2>/dev/null || true; done

# One kernel VRF per VPN. The N6 interfaces are enslaved so their (identical)
# connected routes land in the per-VRF tables instead of colliding in main.
for v in "vrf-a 100 eth2" "vrf-b 200 eth3"; do
    set -- $v
    name=$1; table=$2; dev=$3
    if ! ip link show "$name" >/dev/null 2>&1; then
        ip link add "$name" type vrf table "$table"
    fi
    ip link set "$name" up
    ip link set "$dev" master "$name"
    ip addr add 10.0.0.254/24 dev "$dev" 2>/dev/null || true
    ip link set "$dev" up
done
ip rule add l3mdev protocol kernel prio 1000 2>/dev/null || true

# Underlay: mup-gw loopback, the controller, and the GW's uplink-source block.
ip -6 route replace 2001:db8:ff::a/128 via 2001:db8:2::2 dev eth1 src 2001:db8:ff::d
ip -6 route replace 2001:db8:ff::c/128 via 2001:db8:2::2 dev eth1 src 2001:db8:ff::d
ip -6 route replace fd00:a::/48 via 2001:db8:2::2 dev eth1

mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
mkdir -p /etc/vinbero; cp /vinbero.yml /etc/vinbero/vinbero.yaml
/usr/local/bin/vinberod --bgp-enabled -c /etc/vinbero/vinbero.yaml > /var/log/vinberod.log 2>&1 &
echo $! > /var/run/vinberod.pid

for _ in $(seq 1 30); do /usr/local/bin/vbctl locator list >/dev/null 2>&1 && break; sleep 1; done

# Source locator = this PE's SRv6 block (also the direct segment block).
/usr/local/bin/vbctl locator create --name LOC1 --prefix fd00:d::/48 \
    --block-len 32 --node-len 16 --function-len 16 --argument-len 64 --behavior classic || true

# One direct segment per VPN: End.DT4 decaps into the VPN's kernel VRF.
/usr/local/bin/vbctl sid create \
    --trigger-prefix fd00:d:0:1::/128 --action END_DT4 --vrf-name vrf-a || true
/usr/local/bin/vbctl sid create \
    --trigger-prefix fd00:d:0:2::/128 --action END_DT4 --vrf-name vrf-b || true

# Originate one DSD per VPN. RDs are per-advertiser (distinct from the
# controller's session RDs); VPN membership is the RT, and the MUP Extended
# Community segment id pairs each DSD with its VPN's T2ST.
sleep 6
/usr/local/bin/vbctl mup create --route-type dsd \
    --rd 65100:21 --address 10.255.0.2 \
    --segment-id2 1 --segment-id4 1 \
    --route-targets 100:6001 --sid fd00:d:0:1:: --next-hop 2001:db8:ff::d || true
/usr/local/bin/vbctl mup create --route-type dsd \
    --rd 65100:22 --address 10.255.0.2 \
    --segment-id2 1 --segment-id4 2 \
    --route-targets 100:6002 --sid fd00:d:0:2:: --next-hop 2001:db8:ff::d || true
echo "[start.sh] mup-pe originated per-VPN DSDs; local MUP table:"
/usr/local/bin/vbctl mup list || true

# Pre-resolve neighbours for the redirect FIB lookups: the core next hop and
# the DN host in EACH VRF (bpf_fib_lookup needs the per-VRF neighbor entry).
ping6 -c 1 -W 2 2001:db8:2::2 >/dev/null 2>&1 || true
ping -I eth2 -c 1 -W 2 10.0.0.1 >/dev/null 2>&1 || true
ping -I eth3 -c 1 -W 2 10.0.0.1 >/dev/null 2>&1 || true

echo "[start.sh] mup-pe (data MUP-PE) ready; advertised DSDs for vrf-a / vrf-b"
