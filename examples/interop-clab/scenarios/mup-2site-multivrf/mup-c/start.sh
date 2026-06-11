#!/bin/bash
# MUP Controller (mup-c) for the mup-2site-multivrf scenario.
#
# Peers iBGP with mup-gw and mup-pe and advertises one (SID-less) T2ST uplink
# session per VPN. The two sessions are deliberately identical on the wire
# where a VPN may overlap — same endpoint, same TEID — and differ only in
# RD (per service instance) and RT (per uplink VPN), which is what lets the
# GW install them under different uplink instances.
#
#   eth1  mup-c <-> core  2001:db8:3::/64  (mup-c = ::1)
#   lo    loopback 2001:db8:ff::c

ip -6 addr add 2001:db8:3::1/64 dev eth1 2>/dev/null || true
ip link set eth1 up
ip -6 addr add 2001:db8:ff::c/128 dev lo 2>/dev/null || true
ip link set lo up
sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true
ethtool -K eth1 txvlan off 2>/dev/null || true; ethtool -K eth1 rxvlan off 2>/dev/null || true

# Reach both edge loopbacks (iBGP peers) across the core.
ip -6 route replace 2001:db8:ff::a/128 via 2001:db8:3::2 dev eth1 src 2001:db8:ff::c
ip -6 route replace 2001:db8:ff::d/128 via 2001:db8:3::2 dev eth1 src 2001:db8:ff::c

mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
mkdir -p /etc/vinbero; cp /vinbero.yml /etc/vinbero/vinbero.yaml
/usr/local/bin/vinberod --bgp-enabled -c /etc/vinbero/vinbero.yaml > /var/log/vinberod.log 2>&1 &
echo $! > /var/run/vinberod.pid

for _ in $(seq 1 30); do /usr/local/bin/vbctl locator list >/dev/null 2>&1 && break; sleep 1; done
/usr/local/bin/vbctl locator create --name LOC1 --prefix fd00:c::/48 \
    --block-len 32 --node-len 16 --function-len 16 --argument-len 64 --behavior classic || true

# Let the two iBGP sessions establish before advertising.
sleep 6

# T2ST for VPN-A: GTP-U to 172.16.0.254 / TEID 256 belongs to uplink VPN-A
# (RT 100:6001); the GW resolves the direct SID from the DSD carrying
# segment id 1:1.
/usr/local/bin/vbctl mup create --route-type t2st \
    --rd 65100:1 --route-targets 100:6001 --endpoint 172.16.0.254 \
    --teid 256 --teid-len 32 \
    --segment-id2 1 --segment-id4 1 \
    --next-hop 2001:db8:ff::d || true

# T2ST for VPN-B: the SAME endpoint and the SAME TEID, distinguished only by
# RD/RT/segment id. Without uplink instances these two sessions would collide
# on the GW's F-TEID key.
/usr/local/bin/vbctl mup create --route-type t2st \
    --rd 65100:2 --route-targets 100:6002 --endpoint 172.16.0.254 \
    --teid 256 --teid-len 32 \
    --segment-id2 1 --segment-id4 2 \
    --next-hop 2001:db8:ff::d || true

echo "[start.sh] mup-c (MUP Controller) originated two overlapping T2STs; local MUP table:"
/usr/local/bin/vbctl mup list || true
