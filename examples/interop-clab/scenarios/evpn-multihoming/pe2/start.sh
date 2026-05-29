#!/bin/bash
# Bring up Vinbero PE pe2 for the evpn-multihoming scenario. Mirror of pe1: the
# second PE attaching ES-1. DF election against pe1 (lower encap source wins)
# decides which PE forwards BUM toward the dual-homed ce-mh.
#
#   eth1  pe2 <-> core      underlay 2001:db8:2::/64 (pe2 = ::1)
#   eth2  pe2 <-> ce-mh     ES-1 leg (bd 100)
#   lo    loopback 2001:db8:ff::2
# SRv6: locator fd00:200::/48, End.DT2U fd00:200:0:2::, End.DT2M fd00:200:0:3::,
# encap source fd00:200:: (DF-election identity; higher than pe1's, so pe1 is DF).

setknob() { sysctl -w "$1=$2" >/dev/null 2>&1 || true; }

# ESI type 0 (arbitrary): the leading byte is the ESI type. A leading 01 would
# be parsed as a LACP ESI whose last octet must be 0x00, so gobgp rejects the
# RT4. Type 0 carries no such structural constraint.
ESI=00:00:00:00:00:00:00:00:00:01
ES_IMPORT_RT=00:00:00:00:00:01
LOCAL_PE=fd00:200::

ip -6 addr add 2001:db8:2::1/64 dev eth1 2>/dev/null || true
ip link set eth1 up
ip link set eth2 up
ip -6 addr add 2001:db8:ff::2/128 dev lo 2>/dev/null || true
ip link set lo up

setknob net.ipv6.conf.all.forwarding 1
setknob net.ipv6.conf.all.seg6_enabled 1
setknob net.ipv6.conf.eth1.seg6_enabled 1
setknob net.ipv6.conf.eth2.seg6_enabled 1
ethtool -K eth1 txvlan off 2>/dev/null || true
ethtool -K eth1 rxvlan off 2>/dev/null || true
ethtool -K eth2 txvlan off 2>/dev/null || true
ethtool -K eth2 rxvlan off 2>/dev/null || true

if ! ip link show br100 >/dev/null 2>&1; then
    ip link add br100 type bridge
fi
ip link set br100 up
ip link set eth2 master br100

ip -6 route replace 2001:db8:ff::1/128 via 2001:db8:2::2 dev eth1 src 2001:db8:ff::2
ip -6 route replace 2001:db8:ff::3/128 via 2001:db8:2::2 dev eth1 src 2001:db8:ff::2
ip -6 route replace fd00:100::/48 via 2001:db8:2::2 dev eth1
ip -6 route replace fd00:300::/48 via 2001:db8:2::2 dev eth1

mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
mkdir -p /etc/vinbero
cp /vinbero.yml /etc/vinbero/vinbero.yaml

/usr/local/bin/vinberod --bgp-enabled -c /etc/vinbero/vinbero.yaml \
    > /var/log/vinberod.log 2>&1 &
echo $! > /var/run/vinberod.pid

for i in $(seq 1 30); do
    if /usr/local/bin/vbctl locator list >/dev/null 2>&1; then break; fi
    sleep 1
done

/usr/local/bin/vbctl locator create \
    --name LOC1 --prefix fd00:200::/48 \
    --block-len 32 --node-len 16 --function-len 16 --argument-len 64 \
    --behavior classic || true

/usr/local/bin/vbctl sid create --trigger-prefix fd00:200:0:2::/128 \
    --action END_DT2 --bd-id 100 --bridge-name br100 || true
/usr/local/bin/vbctl sid create --trigger-prefix fd00:200:0:3::/128 \
    --action END_DT2M --bd-id 100 --bridge-name br100 || true

/usr/local/bin/vbctl hl2 create --interface eth2 --vlan-id 0 \
    --src-addr fd00:200:0:2:: --segments fd00:200:0:2:: --bd-id 100 \
    --esi "$ESI" || true

/usr/local/bin/vbctl es create --esi "$ESI" --local-attached \
    --local-pe "$LOCAL_PE" --mode SINGLE_ACTIVE || true

/usr/local/bin/vbctl bgp advertise-evpn-mac --rd 65100:2 \
    --route-targets 65000:100 --mac aa:bb:cc:00:00:10 \
    --sid fd00:200:0:2:: --next-hop 2001:db8:ff::2 --esi "$ESI" || true
/usr/local/bin/vbctl bgp advertise-evpn-imet --rd 65100:2 \
    --route-targets 65000:100 --sid fd00:200:0:3:: --next-hop 2001:db8:ff::2 || true
/usr/local/bin/vbctl bgp advertise-evpn-es --rd 65100:2 --esi "$ESI" \
    --es-import-rt "$ES_IMPORT_RT" --next-hop "$LOCAL_PE" || true

ping6 -c 1 -W 2 2001:db8:2::2 >/dev/null 2>&1 || true
echo "[start.sh] pe2 (Vinbero) EVPN multi-homing PE ready (ES-1 local)"
