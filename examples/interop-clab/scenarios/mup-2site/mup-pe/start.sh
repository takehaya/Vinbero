#!/bin/bash
# Data-side MUP-PE (MUP Provider Edge), mup-pe, for the mup-2site scenario.
#
# Hosts the direct segment (End.DT4 -> DN VRF, uplink delivery) locally, and
# applies the controller's T1ST as the downlink H.Encaps onto the UE prefix.
#
#   eth1  mup-pe <-> core  SRv6   2001:db8:2::1/64
#   eth2  mup-pe <-> DN    N6     10.0.0.254/24
#   lo    loopback 2001:db8:ff::d
set -u

ip -6 addr add 2001:db8:2::1/64 dev eth1 2>/dev/null || true
ip link set eth1 up
ip addr add 10.0.0.254/24 dev eth2 2>/dev/null || true
ip link set eth2 up
ip -6 addr add 2001:db8:ff::d/128 dev lo 2>/dev/null || true
# Dedicated v4 loopback used as the DSD originator address (RFC 9433 §3.2:
# Address = originator/PE identifier). Kept separate from the N6 interface
# (10.0.0.254/24) and from the DN host (10.0.0.1) so the DSD originator is not
# confused with a data-network endpoint. Not routed across the core; the GW
# resolves the T2ST against the DSD by segment id, not by this address.
ip addr add 10.0.0.2/32 dev lo 2>/dev/null || true
ip link set lo up

sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.all.seg6_enabled=1 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.eth1.seg6_enabled=1 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.eth2.rp_filter=0 >/dev/null 2>&1 || true
for i in eth1 eth2; do ethtool -K $i txvlan off 2>/dev/null || true; ethtool -K $i rxvlan off 2>/dev/null || true; done

# Return-path VRF for End.DT4: the decapped uplink inner packet (UE -> DN) is
# routed via table 100 out eth2 to the data network.
if ! ip link show vrf-cust >/dev/null 2>&1; then
    ip link add vrf-cust type vrf table 100
fi
ip link set vrf-cust up
ip rule add l3mdev protocol kernel prio 1000 2>/dev/null || true
ip route replace 10.0.0.0/24 dev eth2 table 100

# Underlay: mup-gw loopback + its interwork-segment block, and the controller.
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

# Direct segment: End.DT4 decaps uplink SRv6 into vrf-cust -> DN.
/usr/local/bin/vbctl sid create \
    --trigger-prefix fd00:d:0:1::/128 --action END_DT4 --vrf-name vrf-cust || true

# Bind the MUP service instance (the DN VRF that End.DT4 decaps into) at
# runtime via the operator surface. The rd must be the RD the controller
# stamps on the T1ST/T2ST session routes (65100:1 in mup-c/start.sh): a
# received MUP route resolves its binding, and so the source prefix below, by
# RD. Declaring mup_ipv4 import RTs activates the session-route import filter
# (ISD/DSD discovery routes bypass it): 100:2000 imports the downlink VPN
# (T1ST); 100:6000 imports the uplink VPN (T2ST), which this PE needs as the
# RFC 9433 §6.6 UPF anchor even though the uplink gate itself lives on the GW.
# --mup-gtp4-source-prefix embeds that anchor (the same-RD T2ST endpoint,
# 172.16.0.254) into the downlink outer IPv6 source right after the /64
# (v4src position 64), asserted by test.sh as SRC ADDR fd00:d::ac10:fe:0:0.
# Vinbero's own End.M.GTP4.E takes its GTP-U source from the configured
# --gtp-v4-src-addr instead of extracting it from the outer source. Binding
# mutations re-reconcile the RD's installed downlinks, so the order of this
# bind vs. BGP route arrival does not matter.
/usr/local/bin/vbctl vrf-bgp bind --vrf vrf-cust --rd 65100:1 \
    --rt mup_ipv4:100:2000:import --rt mup_ipv4:100:6000:import \
    --mup-gtp4-source-prefix fd00:d::/64 || true

# Originate this PE's Direct Segment Discovery route via MupService (a managed
# local table auto-advertised into SAFI 85): it hosts the End.DT4 direct segment
# (SID fd00:d:0:1::) tagged with a MUP Extended Community segment id, which the
# controller's T2ST resolves against. The address is the dedicated originator
# loopback above, not a data-network endpoint.
# The RD is this PE's own (per-advertiser, RFC 4364 §4.2), distinct from the
# controller's session RD 65100:1; VPN membership is the route target
# (100:6000, the uplink VPN shared with the T2ST), so the GW's resolution
# crosses RDs and is RT-scoped.
sleep 6
/usr/local/bin/vbctl mup create --route-type dsd \
    --rd 65100:12 --address 10.0.0.2 \
    --segment-id2 1 --segment-id4 2 \
    --route-targets 100:6000 --sid fd00:d:0:1:: --next-hop 2001:db8:ff::d || true
echo "[start.sh] mup-pe originated DSD; local MUP table:"
/usr/local/bin/vbctl mup list || true

# Pre-resolve neighbours for the redirect FIB lookups.
ping6 -c 1 -W 2 2001:db8:2::2 >/dev/null 2>&1 || true
ping -c 1 -W 2 10.0.0.1 >/dev/null 2>&1 || true

echo "[start.sh] mup-pe (data MUP-PE) ready; advertised DSD"
