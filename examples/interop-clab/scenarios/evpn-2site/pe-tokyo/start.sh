#!/bin/bash
# Bring up the Vinbero PE pe-tokyo for the evpn-2site scenario.
#
# pe-tokyo is an SRv6 EVPN L2VPN PE. It bridges ce-tokyo into bridge domain
# 100, advertises ce-tokyo's MAC as a BGP EVPN RT2 (with its own End.DT2U
# SID), and installs pe-osaka's RT2 to H.Encaps.L2 ce-osaka-bound unicast
# toward pe-osaka. End.DT2U decaps the reverse direction into br100 -> ce-tokyo.
#
# Interfaces:
#   eth1  pe-tokyo <-> core      underlay 2001:db8:1::/64  (pe-tokyo = ::1)
#   eth2  pe-tokyo <-> ce-tokyo  customer access port (bd 100, untagged)
#   lo    loopback 2001:db8:ff::1  (iBGP peering / SRv6 transport)

setknob() { sysctl -w "$1=$2" >/dev/null 2>&1 || true; }

# --- interface addressing --------------------------------------------------
ip -6 addr add 2001:db8:1::1/64 dev eth1 2>/dev/null || true
ip link set eth1 up
ip link set eth2 up
ip -6 addr add 2001:db8:ff::1/128 dev lo 2>/dev/null || true
ip link set lo up

# --- SRv6 dataplane knobs --------------------------------------------------
setknob net.ipv6.conf.all.forwarding 1
setknob net.ipv6.conf.all.seg6_enabled 1
setknob net.ipv6.conf.eth1.seg6_enabled 1
setknob net.ipv6.conf.eth2.seg6_enabled 1

ethtool -K eth1 txvlan off 2>/dev/null || true
ethtool -K eth1 rxvlan off 2>/dev/null || true
ethtool -K eth2 txvlan off 2>/dev/null || true
ethtool -K eth2 rxvlan off 2>/dev/null || true

# --- bridge for the End.DT2U decap path ------------------------------------
# br100 is bd 100's local delivery point: End.DT2U decaps a core-bound frame
# into br100, which forwards it to ce-tokyo on eth2. The CE port is enslaved
# for that egress direction; XDP still sees CE->core frames first (ingress).
if ! ip link show br100 >/dev/null 2>&1; then
    ip link add br100 type bridge
fi
ip link set br100 up
ip link set eth2 master br100

# --- static underlay routes ------------------------------------------------
# pe-osaka's loopback (iBGP peer) and locator block (its End.DT2U SID), via core.
ip -6 route replace 2001:db8:ff::2/128 via 2001:db8:1::2 dev eth1 src 2001:db8:ff::1
ip -6 route replace fd00:200::/48 via 2001:db8:1::2 dev eth1

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
# RT2/RT3 from pe-osaka is never dropped for lack of a bridge-domain binding.
# Replaces the deleted YAML vrf_bindings entry.
/usr/local/bin/vbctl vrf-bgp bind \
    --vrf evi-100 \
    --bd-id 100 \
    --rt evpn:65000:100:import || true

# Source locator: fd00:100::/48 is pe-tokyo's SRv6 block (encap source).
/usr/local/bin/vbctl locator create \
    --name LOC1 \
    --prefix fd00:100::/48 \
    --block-len 32 --node-len 16 --function-len 16 --argument-len 64 \
    --behavior classic || true

# End.DT2U service SID: decaps a core-bound unicast L2 frame into br100 -> ce-tokyo.
/usr/local/bin/vbctl sid create \
    --trigger-prefix fd00:100:0:2::/128 \
    --action END_DT2 \
    --bd-id 100 \
    --bridge-name br100 || true

# End.DT2M service SID: decaps a core-bound BUM (flood) L2 frame into br100.
# RT3 advertises this SID so the peer floods broadcast / unknown-unicast here.
/usr/local/bin/vbctl sid create \
    --trigger-prefix fd00:100:0:3::/128 \
    --action END_DT2M \
    --bd-id 100 \
    --bridge-name br100 || true

# Headend-L2 ingress on the CE port: classify ce-tokyo's frames into bd 100.
# --segments is required by the API but unused for BGP-learned unicast (the
# bd_peer from the peer's RT2 supplies the real path); set it to our own SID.
/usr/local/bin/vbctl hl2 create \
    --interface eth2 \
    --vlan-id 0 \
    --src-addr fd00:100:0:2:: \
    --segments fd00:100:0:2:: \
    --bd-id 100 || true

# Advertise ce-tokyo's MAC as an EVPN RT2 with our End.DT2U SID. pe-osaka
# receives it and H.Encaps.L2's its ce-tokyo-bound unicast toward this SID.
/usr/local/bin/vbctl bgp advertise-evpn-mac \
    --rd 65100:1 \
    --route-targets 65000:100 \
    --mac aa:bb:cc:00:00:10 \
    --sid fd00:100:0:2:: \
    --next-hop 2001:db8:ff::1 || true

# Advertise the BUM flood endpoint as an EVPN RT3 (Inclusive Multicast) with
# our End.DT2M SID. pe-osaka floods broadcast / unknown-unicast toward this SID,
# so the CEs no longer need static ARP.
/usr/local/bin/vbctl bgp advertise-evpn-imet \
    --rd 65100:1 \
    --route-targets 65000:100 \
    --sid fd00:100:0:3:: \
    --next-hop 2001:db8:ff::1 || true

# Pre-resolve the core neighbour.
ping6 -c 1 -W 2 2001:db8:1::2 >/dev/null 2>&1 || true

echo "[start.sh] pe-tokyo (Vinbero) EVPN PE ready"
