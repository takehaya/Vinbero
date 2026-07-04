#!/bin/bash
# Bring up Vinbero PE pe3 for the evpn-multihoming scenario. pe3 is the remote
# single-homed PE: ce-remote attaches to it normally (no Ethernet Segment, no
# RT4). It learns ce-mh via RT2 and floods toward both pe1/pe2 End.DT2M peers;
# DF election + split-horizon on pe1/pe2 ensure ce-mh sees BUM exactly once.
#
#   eth1  pe3 <-> core      underlay 2001:db8:3::/64 (pe3 = ::1)
#   eth2  pe3 <-> ce-remote customer access port (bd 100)
#   lo    loopback 2001:db8:ff::3
# SRv6: locator fd00:300::/48, End.DT2U fd00:300:0:2::, End.DT2M fd00:300:0:3::.

setknob() { sysctl -w "$1=$2" >/dev/null 2>&1 || true; }

ip -6 addr add 2001:db8:3::1/64 dev eth1 2>/dev/null || true
ip link set eth1 up
ip link set eth2 up
ip -6 addr add 2001:db8:ff::3/128 dev lo 2>/dev/null || true
ip link set lo up

setknob net.ipv6.conf.all.forwarding 1
setknob net.ipv6.conf.all.seg6_enabled 1
setknob net.ipv6.conf.eth1.seg6_enabled 1
setknob net.ipv6.conf.eth2.seg6_enabled 1
ethtool -K eth1 txvlan off 2>/dev/null || true
ethtool -K eth1 rxvlan off 2>/dev/null || true
ethtool -K eth2 txvlan off 2>/dev/null || true
ethtool -K eth2 rxvlan off 2>/dev/null || true

ip -6 route replace 2001:db8:ff::1/128 via 2001:db8:3::2 dev eth1 src 2001:db8:ff::3
ip -6 route replace 2001:db8:ff::2/128 via 2001:db8:3::2 dev eth1 src 2001:db8:ff::3
ip -6 route replace fd00:100::/48 via 2001:db8:3::2 dev eth1
ip -6 route replace fd00:200::/48 via 2001:db8:3::2 dev eth1

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

# bd 100 local delivery as evi-100's L2 facet: End.DT2/DT2M decap into br100
# -> the CE on eth2 (enslaved via --members). The facet is the bridge
# domain's single source and must attach BEFORE the vrf-bgp bind below, so
# the moment the binding can match a received RT2/RT3/RT4 its bd is
# resolvable.
/usr/local/bin/vbctl vrf bridge-attach \
    --vrf evi-100 \
    --name br100 \
    --bd-id 100 \
    --members eth2 || true

# Bind evi-100 to the EVPN import RT before the SID/headend setup so an early
# RT2/RT3/RT4 from a peer is never dropped for lack of a binding; the routes
# install into the facet's bd 100.
/usr/local/bin/vbctl vrf-bgp bind \
    --vrf evi-100 \
    --rt evpn:65000:100:import || true

/usr/local/bin/vbctl locator create \
    --name LOC1 --prefix fd00:300::/48 \
    --block-len 32 --node-len 16 --function-len 16 --argument-len 64 \
    --behavior classic || true

/usr/local/bin/vbctl sid create --trigger-prefix fd00:300:0:2::/128 \
    --action END_DT2 --bd-id 100 --bridge-name br100 || true
/usr/local/bin/vbctl sid create --trigger-prefix fd00:300:0:3::/128 \
    --action END_DT2M --bd-id 100 --bridge-name br100 || true

# Single-homed access port: no ESI.
/usr/local/bin/vbctl hl2 create --interface eth2 --vlan-id 0 \
    --src-addr fd00:300:0:2:: --segments fd00:300:0:2:: --bd-id 100 || true

/usr/local/bin/vbctl bgp advertise-evpn-mac --rd 65100:3 \
    --route-targets 65000:100 --mac aa:bb:cc:00:00:30 \
    --sid fd00:300:0:2:: --next-hop 2001:db8:ff::3 || true
/usr/local/bin/vbctl bgp advertise-evpn-imet --rd 65100:3 \
    --route-targets 65000:100 --sid fd00:300:0:3:: --next-hop 2001:db8:ff::3 || true

ping6 -c 1 -W 2 2001:db8:3::2 >/dev/null 2>&1 || true
echo "[start.sh] pe3 (Vinbero) EVPN remote PE ready (single-homed)"
