#!/bin/bash
# Bring up the Vinbero PE pe-osaka for the evpn-2site scenario.
#
# Mirror of pe-tokyo: bridges ce-osaka into bd 100, advertises ce-osaka's MAC
# as an EVPN RT2 with its own End.DT2U SID, and installs pe-tokyo's RT2 to
# H.Encaps.L2 ce-tokyo-bound unicast toward pe-tokyo.
#
# Interfaces:
#   eth1  pe-osaka <-> core      underlay 2001:db8:2::/64  (pe-osaka = ::1)
#   eth2  pe-osaka <-> ce-osaka  customer access port (bd 100, untagged)
#   lo    loopback 2001:db8:ff::2

setknob() { sysctl -w "$1=$2" >/dev/null 2>&1 || true; }

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

ip -6 route replace 2001:db8:ff::1/128 via 2001:db8:2::2 dev eth1 src 2001:db8:ff::2
ip -6 route replace fd00:100::/48 via 2001:db8:2::2 dev eth1

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

# Bind bd 100 to the EVPN import RT before the SID/headend setup so an early
# RT2/RT3 from pe-tokyo is never dropped for lack of a bridge-domain binding.
# Replaces the deleted YAML vrf_bindings entry.
/usr/local/bin/vbctl vrf-bgp bind \
    --vrf evi-100 \
    --bd-id 100 \
    --rt evpn:65000:100:import || true

# The bridge as evi-100's L2 facet (see pe-tokyo/start.sh for the rationale).
/usr/local/bin/vbctl vrf bridge-attach \
    --vrf evi-100 \
    --name br100 \
    --bd-id 100 \
    --members eth2 || true

/usr/local/bin/vbctl locator create \
    --name LOC1 \
    --prefix fd00:200::/48 \
    --block-len 32 --node-len 16 --function-len 16 --argument-len 64 \
    --behavior classic || true

/usr/local/bin/vbctl sid create \
    --trigger-prefix fd00:200:0:2::/128 \
    --action END_DT2 \
    --bd-id 100 \
    --bridge-name br100 || true

# End.DT2M service SID: decaps a core-bound BUM (flood) L2 frame into br100.
/usr/local/bin/vbctl sid create \
    --trigger-prefix fd00:200:0:3::/128 \
    --action END_DT2M \
    --bd-id 100 \
    --bridge-name br100 || true

/usr/local/bin/vbctl hl2 create \
    --interface eth2 \
    --vlan-id 0 \
    --src-addr fd00:200:0:2:: \
    --segments fd00:200:0:2:: \
    --bd-id 100 || true

/usr/local/bin/vbctl bgp advertise-evpn-mac \
    --rd 65100:2 \
    --route-targets 65000:100 \
    --mac aa:bb:cc:00:00:20 \
    --sid fd00:200:0:2:: \
    --next-hop 2001:db8:ff::2 || true

# Advertise the BUM flood endpoint as an EVPN RT3 with our End.DT2M SID.
/usr/local/bin/vbctl bgp advertise-evpn-imet \
    --rd 65100:2 \
    --route-targets 65000:100 \
    --sid fd00:200:0:3:: \
    --next-hop 2001:db8:ff::2 || true

ping6 -c 1 -W 2 2001:db8:2::2 >/dev/null 2>&1 || true

echo "[start.sh] pe-osaka (Vinbero) EVPN PE ready"
