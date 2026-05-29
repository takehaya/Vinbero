#!/bin/bash
# MUP Controller (mup-c) for the mup-2site scenario.
#
# Peers iBGP with mup-gw and mup-pe and advertises the (SID-less) T1ST/T2ST
# session routes that drive their data plane. Forwards no traffic.
#
#   eth1  mup-c <-> core  2001:db8:3::/64  (mup-c = ::1)
#   lo    loopback 2001:db8:ff::c

ip -6 addr add 2001:db8:3::1/64 dev eth1 2>/dev/null || true
ip link set eth1 up
ip -6 addr add 2001:db8:ff::c/128 dev lo 2>/dev/null || true
ip link set lo up
sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true
ethtool -K eth1 txvlan off 2>/dev/null || true; ethtool -K eth1 rxvlan off 2>/dev/null || true

# Reach both gateway loopbacks (iBGP peers) across the core.
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

# The controller advertises ONLY the session-transformed routes (T1ST/T2ST) --
# the per-UE-session state it learns from the mobile control plane -- and carries
# NO SRv6 SID on them. Each edge node resolves the SID from its peer's segment
# discovery route (RFC 9433 §3): the T1ST against mup-gw's ISD by gNB
# endpoint, the T2ST against mup-pe's DSD by the MUP segment id below.

# T1ST (downlink): UE 10.1.0.1, gNB endpoint 172.16.0.1. mup-pe resolves the
# interwork SID from the ISD covering 172.16.0.0/24, composes Args.Mob.Session
# onto it, and installs the H.Encaps; mup-gw's End.M.GTP4.E emits GTP-U.
/usr/local/bin/vbctl bgp advertise-mup --route-type t1st \
    --rd 65100:1 --prefix 10.1.0.1/32 \
    --teid 256 --qfi 9 --endpoint 172.16.0.1 \
    --next-hop 2001:db8:ff::a || true

# T2ST (uplink): gNB GTP-U to the N3 endpoint, segment id 1:2. mup-gw resolves
# the direct SID from the DSD carrying segment id 1:2, installs the F-TEID entry
# + H.M.GTP4.D_TEID gate; mup-pe's End.DT4 delivers to the DN.
/usr/local/bin/vbctl bgp advertise-mup --route-type t2st \
    --rd 65100:1 --endpoint 172.16.0.254 \
    --teid 256 --teid-len 32 \
    --segment-id2 1 --segment-id4 2 \
    --next-hop 2001:db8:ff::d || true

echo "[start.sh] mup-c (MUP Controller) advertised T1ST/T2ST (SID-less; resolved by gateways)"
